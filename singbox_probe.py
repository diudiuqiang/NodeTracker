# -*- coding: utf-8 -*-
"""
singbox_probe.py — 基于 sing-box 内核的真实延迟探测模块
=====================================================
解决裸 TCP 探测的硬伤：Hysteria2 / TUIC / AnyTLS / VLESS-Reality 等
UDP / 特殊协议用 TCP connect 必然超时，测不准。本模块改用 sing-box 的
Clash API（external_controller）对每个 outbound 做真实 urltest，
能准确测出所有协议节点的真实延迟。

对外暴露：
  - parse_link_to_item(link)       单个分享链接 -> {tag, outbound, link, proto}
  - load_subscription(url/text)    订阅链接/文本 -> [item...]
  - run_probe(items, kernel, ...)  启动内核、逐个测延迟、关闭内核 -> [result...]
  - probe_links(links, kernel,...) 便捷：解析+探测 一步到位

依赖：仅 Python 标准库（subprocess / json / base64 / urllib / tempfile）
"""
import os
import re
import io
import sys
import csv
import json
import base64
import time
import shutil
import socket
import threading
import urllib.parse
import urllib.request
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor

# sing-box 内核默认位置（复用 v2rayN 自带，无需下载）
DEFAULT_KERNEL = r"C:\v2rayN-windows-64\bin\sing_box\sing-box.exe"

# 延迟测试的探测 URL（走代理出口，HK/JP 节点可直连）
DEFAULT_TEST_URL = "https://www.gstatic.com/generate_204"
DEFAULT_TEST_TIMEOUT_MS = 5000

# 常见协议前缀
PROTO_PREFIXES = ("vmess://", "vless://", "trojan://", "ss://", "ssr://",
                 "hysteria2://", "hy2://", "tuic://", "anytls://")


# ============================================================ 工具函数
def _b64decode(s):
    """容错 base64 解码（自动补 pad）"""
    s = s.strip()
    try:
        return base64.b64decode(s + "=" * (-len(s) % 4))
    except Exception:
        return None


def _clean_tag(name, used):
    """生成 sing-box 合法且唯一的 tag"""
    tag = (name or "node").strip()
    # 去掉会干扰 clash api 的字符（保留中文/字母数字/._-）
    tag = re.sub(r"[^\w\u4e00-\u9fff\.\-]", "_", tag)
    if not tag:
        tag = "node"
    base = tag
    i = 1
    while tag in used:
        i += 1
        tag = f"{base}_{i}"
    used.add(tag)
    return tag


# ============================================================ 分享链接解析 -> sing-box outbound
def parse_link_to_item(link):
    """
    解析单条分享链接 -> dict(tag, outbound, link, proto)
    解析失败返回 None
    """
    link = (link or "").strip()
    if not link:
        return None
    proto = None
    for p in PROTO_PREFIXES:
        if link.lower().startswith(p):
            proto, rest = p[:-3], link[len(p):]
            break
    if proto is None:
        return None

    remark = ""
    if "#" in rest:
        rest, frag = rest.split("#", 1)
        remark = urllib.parse.unquote(frag)

    used = set()

    if proto == "vmess":
        return _parse_vmess(rest, remark, used, link)

    # 其余均为 URI 格式：scheme://userinfo@host:port?query
    # 先拆 query
    query = {}
    if "?" in rest:
        rest, q = rest.split("?", 1)
        query = {k: v[0] for k, v in urllib.parse.parse_qs(q).items()}
    # 拆 userinfo@host:port
    if "@" in rest:
        userinfo, hostport = rest.split("@", 1)
    else:
        userinfo, hostport = "", rest
    # 拆 host:port（兼容 IPv6 [::]:port）
    if "]:" in hostport:
        host, port = hostport.rsplit(":", 1)
        host = host.strip("[]")
    elif ":" in hostport:
        host, port = hostport.rsplit(":", 1)
    else:
        return None
    try:
        port = int(port)
    except Exception:
        return None

    if proto == "vless":
        return _parse_vless(userinfo, host, port, query, remark, used, link)
    if proto == "trojan":
        return _parse_trojan(userinfo, host, port, query, remark, used, link)
    if proto in ("hysteria2", "hy2"):
        return _parse_hysteria2(userinfo, host, port, query, remark, used, link)
    if proto == "tuic":
        return _parse_tuic(userinfo, host, port, query, remark, used, link)
    if proto == "anytls":
        return _parse_anytls(userinfo, host, port, query, remark, used, link)
    if proto == "ss":
        return _parse_ss(rest, query, remark, used, link)
    return None


def _tls_block(query, allow_insecure_key="allow_insecure"):
    """根据 query 生成 sing-box tls 块"""
    sni = query.get("sni") or query.get("peer") or query.get("host")
    insecure = (str(query.get(allow_insecure_key, "0")).lower() in ("1", "true", "yes")
                or str(query.get("insecure", "0")).lower() in ("1", "true", "yes"))
    block = {"enabled": True}
    if sni:
        block["server_name"] = sni
    if insecure:
        block["insecure"] = True
    alpn = query.get("alpn")
    if alpn:
        block["alpn"] = [a.strip() for a in alpn.split(",") if a.strip()]
    fp = query.get("fp") or query.get("fingerprint")
    if fp:
        block["utls"] = {"enabled": True, "fingerprint": fp}
    pin = query.get("pinSHA256") or query.get("pin")
    if pin:
        block["certificate_public_key_sha256"] = pin
    return block


def _transport(net, query):
    """根据 net/type + query 生成 sing-box transport 块"""
    net = (net or "tcp").lower()
    if net in ("ws", "websocket"):
        t = {"type": "ws", "path": query.get("path", "/")}
        h = query.get("host") or query.get("Host")
        if h:
            t["headers"] = {"Host": h}
        return t
    if net == "grpc":
        t = {"type": "grpc"}
        if query.get("serviceName") or query.get("path"):
            t["service_name"] = query.get("serviceName") or query.get("path")
        return t
    if net in ("h2", "http"):
        t = {"type": "http", "path": [query.get("path", "/")]}
        h = query.get("host") or query.get("Host")
        if h:
            t["host"] = [h]
        return t
    # tcp / kcp / quic 等：返回 None（默认 tcp 无需 transport）
    return None


def _parse_vmess(b64, remark, used, link):
    raw = _b64decode(b64)
    if not raw:
        return None
    try:
        d = json.loads(raw.decode("utf-8", "replace"))
    except Exception:
        return None
    tag = _clean_tag(remark or d.get("ps", ""), used)
    ob = {
        "type": "vmess",
        "tag": tag,
        "server": d.get("add", ""),
        "server_port": int(d.get("port") or 0),
        "uuid": d.get("id", ""),
        "alter_id": int(d.get("aid", 0)),
        "security": d.get("scy") or "auto",
    }
    net = (d.get("net") or "tcp").lower()
    t = _transport(net, d)
    if t:
        ob["transport"] = t
    if str(d.get("tls", "")).lower() in ("tls", "reality"):
        sni = d.get("sni") or d.get("host")
        ob["tls"] = {"enabled": True}
        if sni:
            ob["tls"]["server_name"] = sni
    if not ob["server"] or not ob["server_port"]:
        return None
    return {"tag": tag, "outbound": ob, "link": link, "proto": "vmess"}


def _parse_vless(userinfo, host, port, query, remark, used, link):
    security = (query.get("security") or "none").lower()
    tag = _clean_tag(remark, used)
    ob = {
        "type": "vless",
        "tag": tag,
        "server": host,
        "server_port": port,
        "uuid": userinfo,
        "packet_encoding": "xudp",
    }
    flow = query.get("flow")
    if flow:
        ob["flow"] = flow
    t = _transport(query.get("type", "tcp"), query)
    if t:
        ob["transport"] = t
    if security in ("tls", "reality"):
        tls = _tls_block(query)
        if security == "reality":
            pbk = query.get("pbk")
            sid = query.get("sid") or ""
            r = {"enabled": True}
            if pbk:
                r["public_key"] = pbk
            if sid:
                r["short_id"] = sid
            tls["reality"] = r
            tls.pop("insecure", None)
        ob["tls"] = tls
    return {"tag": tag, "outbound": ob, "link": link, "proto": "vless"}


def _parse_trojan(userinfo, host, port, query, remark, used, link):
    tag = _clean_tag(remark, used)
    ob = {
        "type": "trojan",
        "tag": tag,
        "server": host,
        "server_port": port,
        "password": userinfo,
        "tls": _tls_block(query),
    }
    t = _transport(query.get("type", "tcp"), query)
    if t:
        ob["transport"] = t
    return {"tag": tag, "outbound": ob, "link": link, "proto": "trojan"}


def _parse_hysteria2(userinfo, host, port, query, remark, used, link):
    tag = _clean_tag(remark, used)
    ob = {
        "type": "hysteria2",
        "tag": tag,
        "server": host,
        "server_port": port,
        "password": userinfo,
        "tls": _tls_block(query),
    }
    obfs = query.get("obfs")
    if obfs:
        ob["obfs"] = {"type": obfs, "password": query.get("obfs-password", "")}
    return {"tag": tag, "outbound": ob, "link": link, "proto": "hysteria2"}


def _parse_tuic(userinfo, host, port, query, remark, used, link):
    # userinfo = uuid:password
    uuid, _, password = userinfo.partition(":")
    tag = _clean_tag(remark, used)
    ob = {
        "type": "tuic",
        "tag": tag,
        "server": host,
        "server_port": port,
        "uuid": uuid,
        "password": password,
        "congestion_control": query.get("congestion_control", "bbr"),
        "tls": _tls_block(query),
    }
    return {"tag": tag, "outbound": ob, "link": link, "proto": "tuic"}


def _parse_anytls(userinfo, host, port, query, remark, used, link):
    tag = _clean_tag(remark, used)
    ob = {
        "type": "anytls",
        "tag": tag,
        "server": host,
        "server_port": port,
        "password": userinfo,
        "tls": _tls_block(query),
    }
    return {"tag": tag, "outbound": ob, "link": link, "proto": "anytls"}


def _parse_ss(rest, query, remark, used, link):
    # 去掉可能存在的 @host:port（已在 rest 中，但 userinfo 形式不同）
    # ss:// 形式：base64(method:password)@host:port 或 method:password@host:port
    # 或 新形式 base64(method:password@host:port)
    body = rest
    host, port = "", 0
    if "@" in body:
        left, right = body.split("@", 1)
        method, password = _ss_creds(left)
        if "]:" in right:
            host, p = right.rsplit(":", 1)
            host = host.strip("[]")
        elif ":" in right:
            host, p = right.rsplit(":", 1)
        else:
            return None
        try:
            port = int(p)
        except Exception:
            return None
    else:
        # 整段是 base64(method:password@host:port)
        raw = _b64decode(body)
        if not raw:
            return None
        txt = raw.decode("utf-8", "replace")
        if "@" not in txt:
            return None
        creds, hp = txt.rsplit("@", 1)
        method, password = _ss_creds(creds)
        if "]:" in hp:
            host, p = hp.rsplit(":", 1)
            host = host.strip("[]")
        else:
            host, p = hp.rsplit(":", 1)
        try:
            port = int(p)
        except Exception:
            return None
    if not host or not port:
        return None
    tag = _clean_tag(remark, used)
    ob = {
        "type": "shadowsocks",
        "tag": tag,
        "server": host,
        "server_port": port,
        "method": method,
        "password": password,
    }
    # 简单 obfs 插件（shadowsocks-plugin，sing-box 支持）
    plugin = query.get("plugin")
    if plugin and plugin.startswith("obfs"):
        opts = query.get("plugin-opts", "")
        obfs_host = "www.bing.com"
        obfs_type = "http"
        for kv in opts.split(";"):
            if "=" in kv:
                k, v = kv.split("=", 1)
                if k.strip() == "obfs-host":
                    obfs_host = v.strip()
                elif k.strip() == "obfs":
                    obfs_type = v.strip()
        ob["plugin"] = "shadowsocks-plugin"
        ob["plugin_opts"] = f"obfs={obfs_type};obfs-host={obfs_host}"
    return {"tag": tag, "outbound": ob, "link": link, "proto": "ss"}


def _ss_creds(left):
    raw = _b64decode(left)
    if raw:
        txt = raw.decode("utf-8", "replace")
    else:
        txt = left
    if ":" in txt:
        m, p = txt.split(":", 1)
        return m.strip(), p.strip()
    return "aes-256-gcm", ""


# ============================================================ 订阅加载
def _decode_subscription_text(text):
    """把订阅文本拆成多条分享链接；支持 base64 / 纯文本 / 混合"""
    text = text.strip()
    if not text:
        return []
    links = []
    # 1) 尝试 base64（整段）
    if not text.startswith(("vmess://", "vless://", "trojan://", "ss://",
                            "hysteria2://", "tuic://", "anytls://", "{", "proxies:")):
        raw = _b64decode(text.replace("\n", "").replace(" ", ""))
        if raw:
            try:
                decoded = raw.decode("utf-8", "replace")
                if "://" in decoded:
                    text = decoded
            except Exception:
                pass
    # 2) 按行拆
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith(PROTO_PREFIXES):
            links.append(line)
        elif line.startswith("{"):
            # 可能是 sing-box json 订阅
            try:
                cfg = json.loads(line)
                links.extend(_sb_json_to_links(cfg))
            except Exception:
                pass
    return links


def _parse_clash_yaml_proxies(text):
    """v1.8：零依赖解析 Clash YAML 的 proxies 段（只取该段列表项）。

    免费订阅源一大半是 Clash YAML（proxies: ...），NodeTracker 原来只认 URI，
    这类源拉到内容也解析出 0 节点。简易解析器只处理 proxies 段规整的
    `- key: value` 行，遇到顶层新键（无缩进）即停止。
    嵌套块（ws-opts/reality-opts 等）用缩进栈拍平为点分键：
    `ws-opts.path` / `ws-opts.headers.Host`。返回 [dict...]。
    """
    lines = text.splitlines()
    # 定位 proxies: 段（允许前有注释/空行）
    start = None
    for i, ln in enumerate(lines):
        if ln.strip() == "proxies:":
            start = i + 1
            break
    if start is None:
        return []
    items, cur, stack = [], None, []   # stack: [(indent, key)] 点分键前缀链
    for ln in lines[start:]:
        if not ln.strip() or ln.strip().startswith("#"):
            continue
        indent = len(ln) - len(ln.lstrip())
        s = ln.strip()
        # 顶层新键才结束 proxies 段；⚠️ 列表项可以与 proxies: 同缩进（列 0），
        # 那也是本段内容不是新键（Q3dlaXpoaQ/V2rayN_Clash_Node_Getter 就是这种）
        if indent == 0 and not s.startswith("- "):
            break
        if s.startswith("- "):
            s = s[2:].strip()
            cur, stack = {}, []
            items.append(cur)
        if cur is None or ":" not in s:
            continue
        while stack and indent <= stack[-1][0]:
            stack.pop()
        k, _, v = s.partition(":")
        k, v = k.strip(), v.strip()
        if v.startswith(("'", '"')) and v.endswith(("'", '"')) and len(v) >= 2:
            v = v[1:-1]
        prefix = "".join(p[1] + "." for p in stack)
        if v:
            cur[prefix + k] = v          # 叶子属性：不入栈（否则会变成下层键前缀）
        else:
            # ⚠️ 入栈存「相对键 k」而非 prefix+k：prefix 由整条栈现场拼出，
            # 存完整键会导致每层重复叠加（ws-opts.ws-opts.headers.Host）
            stack.append((indent, k))
    return [p for p in items if p.get("server") and p.get("port")]


def _truthy(v):
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def _clash_tls(p):
    """clash proxy dict → sing-box tls 块（无 tls 需求返回 None）"""
    tls_on = _truthy(p.get("tls")) or bool(p.get("servername") or p.get("sni")) \
        or "reality-opts" in p or "reality-opts" in str(p.get("reality", ""))
    if not tls_on:
        return None
    sni = p.get("servername") or p.get("sni") or p.get("server_name") or ""
    block = {"enabled": True}
    if sni:
        block["server_name"] = sni
    if _truthy(p.get("skip-cert-verify")) or _truthy(p.get("allowInsecure")):
        block["insecure"] = True
    fp = p.get("client-fingerprint")
    if fp:
        block["utls"] = {"enabled": True, "fingerprint": fp}
    # reality（clash.meta 用 reality-opts 嵌套块；简易解析器已拍平其子键）
    pub = p.get("reality-opts.public-key") or p.get("public-key")
    sid = p.get("reality-opts.short-id") or p.get("short-id")
    if pub:
        block["reality"] = {"enabled": True, "public_key": pub}
        if sid:
            block["reality"]["short_id"] = sid
    alpn = p.get("alpn")
    if alpn:
        block["alpn"] = [a.strip() for a in str(alpn).split(",") if a.strip()]
    return block


def _clash_transport(p):
    """clash proxy dict → sing-box transport 块（tcp 返回 None）"""
    net = (p.get("network") or p.get("type") or "tcp").lower()
    if net == "ws":
        t = {"type": "ws"}
        path = p.get("ws-opts.path") or p.get("path")
        if path:
            t["path"] = path
        host = p.get("ws-opts.headers.Host") or p.get("ws-opts.headers.host") \
            or p.get("host")
        if host:
            t["headers"] = {"Host": host}
        return t
    if net == "grpc":
        t = {"type": "grpc"}
        svc = p.get("grpc-opts.grpc-service-name") or p.get("serviceName")
        if svc:
            t["service_name"] = svc
        return t
    if net in ("h2", "http"):
        t = {"type": "http", "path": [p.get("h2-opts.path") or p.get("path") or "/"]}
        host = p.get("h2-opts.host") or p.get("host")
        if host:
            t["host"] = [str(host)]
        return t
    return None


def _clash_proxy_to_item(p, used):
    """clash proxy dict → parse_link_to_item 同构 item；不支持的类型返回 None"""
    t = (p.get("type") or "").lower()
    tag = _clean_tag(p.get("name") or "", used)
    try:
        port = int(str(p.get("port") or "0"))
    except Exception:
        return None
    server = p.get("server") or ""
    if not server or not port:
        return None
    ob = {"tag": tag, "server": server, "server_port": port}
    if t == "vmess":
        ob.update({
            "type": "vmess",
            "uuid": p.get("uuid") or "",
            "alter_id": int(str(p.get("alterId") or 0) or 0),
            "security": p.get("cipher") or "auto",
        })
    elif t == "vless":
        ob.update({"type": "vless", "uuid": p.get("uuid") or "",
                   "packet_encoding": "xudp"})
        if p.get("flow"):
            ob["flow"] = p.get("flow")
    elif t == "trojan":
        ob.update({"type": "trojan", "password": p.get("password") or ""})
    elif t == "ss":
        ob.update({"type": "shadowsocks",
                   "method": p.get("cipher") or p.get("method") or "",
                   "password": p.get("password") or ""})
    elif t in ("hysteria2", "hy2"):
        ob.update({"type": "hysteria2", "password": p.get("password") or ""})
        if p.get("obfs"):
            ob["obfs"] = {"type": str(p.get("obfs")).lower(),
                          "password": p.get("obfs-password") or ""}
    elif t == "tuic":
        ob.update({"type": "tuic", "uuid": p.get("uuid") or "",
                   "password": p.get("password") or ""})
        if p.get("congestion-controller"):
            ob["congestion_control"] = p.get("congestion-controller")
        if p.get("udp-relay-mode"):
            ob["udp_relay_mode"] = p.get("udp-relay-mode")
    elif t == "anytls":
        ob.update({"type": "anytls", "password": p.get("password") or ""})
    else:
        return None
    tls = _clash_tls(p)
    if tls:
        ob["tls"] = tls
    tr = _clash_transport(p)
    if tr:
        ob["transport"] = tr
    link = ob.get("type", "") + "://" + server
    return {"tag": tag, "outbound": ob, "link": link, "proto": t}


def _sb_json_to_links(cfg):
    """sing-box 配置订阅 -> 还原分享链接（尽力而为，用于输出）"""
    out = []
    for ob in cfg.get("outbounds", []):
        l = outbound_to_link(ob)
        if l:
            out.append(l)
    return out


def _http_get_via_curl(url, proxy="", timeout=30):
    """v1.8：经 curl.exe 子进程拉取（原生支持 socks5h/http 代理）。
    Windows 10 1803+ 自带 C:\\Windows\\System32\\curl.exe。失败返回 None。
    timeout 默认 30s：经代理拉 3MB 大源（SoliSpirit 等）20s 会超时误杀。"""
    exe = os.path.join(os.environ.get("SYSTEMROOT", r"C:\Windows"),
                       "System32", "curl.exe")
    if not os.path.exists(exe):
        return None
    cmd = [exe, "-sL", "--max-time", str(int(timeout)),
           "-A", "Mozilla/5.0", url]
    if proxy:
        cmd[1:1] = ["-x", proxy]
    try:
        # CREATE_NO_WINDOW：GUI 程序起 curl.exe 不弹黑窗（并发 8 × 67 源会弹一屏）
        r = subprocess.run(cmd, capture_output=True, timeout=timeout + 10,
                           creationflags=0x08000000 if os.name == "nt" else 0)
        if r.returncode == 0 and r.stdout:
            return r.stdout.decode("utf-8", "replace")
    except Exception:
        pass
    return None


def load_subscription(url_or_text, proxy=""):
    """加载订阅：http(s) 链接或本地文本，返回 [item...]

    proxy: v1.8 拉源代理，如 `socks5h://127.0.0.1:10809` / `http://127.0.0.1:10809`。
    空 = 直连。配了代理时优先走 curl.exe（SOCKS 必须），curl 不可用再回退
    urllib（仅 HTTP 代理支持，SOCKS 会静默变直连——所以 socks 场景 curl 必需）。
    """
    text = url_or_text.strip()
    if text.lower().startswith(("http://", "https://")):
        if proxy:
            body = _http_get_via_curl(text, proxy)
            if body is not None:
                text = body
            else:
                # curl 不可用：HTTP 代理可用 urllib ProxyHandler；SOCKS 只能直连碰运气
                try:
                    if proxy.lower().startswith(("socks", "socks5")):
                        print(f"[订阅] curl.exe 不可用，SOCKS 代理 {proxy} 无法经 urllib 使用，回退直连")
                    else:
                        opener = urllib.request.build_opener(
                            urllib.request.ProxyHandler(
                                {"http": proxy, "https": proxy}))
                        req = urllib.request.Request(
                            text, headers={"User-Agent": "Mozilla/5.0"})
                        with opener.open(req, timeout=20) as resp:
                            text = resp.read().decode("utf-8", "replace")
                except Exception as e:
                    print(f"[订阅] 拉取失败 {text}: {e}")
                    return []
        else:
            try:
                req = urllib.request.Request(text, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=20) as resp:
                    text = resp.read().decode("utf-8", "replace")
            except Exception as e:
                print(f"[订阅] 拉取失败 {text}: {e}")
                return []
    # v1.8：Clash YAML 订阅（proxies: 段）直接转 items，不经 URI 链路
    if text.lstrip().startswith("proxies:") or "\nproxies:" in text:
        items, used = [], set()
        for p in _parse_clash_yaml_proxies(text):
            it = _clash_proxy_to_item(p, used)
            if it:
                items.append(it)
        return items
    links = _decode_subscription_text(text)
    items = []
    for l in links:
        it = parse_link_to_item(l)
        if it:
            items.append(it)
    return items


# ============================================================ sing-box 配置生成
def build_config(items, api_port=9090, secret="sbprobe", speed_port=None):
    """
    由 items 生成 sing-box 配置 dict
    speed_port 非 None 时额外开启 mixed 入口 + 路由，用于真实下载测速
    """
    outbounds = [{"type": "direct", "tag": "direct"}]
    node_tags = []
    for it in items:
        ob = dict(it["outbound"])
        node_tags.append(ob["tag"])
        outbounds.append(ob)
    # selector 聚合所有节点（clash api 需要可见 + 速度测试时切换用）
    outbounds.append({
        "type": "selector",
        "tag": "PROXY",
        "outbounds": node_tags,
    })
    inbounds = []
    route = {"auto_detect_interface": True}
    if speed_port:
        inbounds.append({
            "type": "mixed", "tag": "speed-in",
            "listen": "127.0.0.1", "listen_port": speed_port,
        })
        route = {"final": "PROXY", "auto_detect_interface": True}
    cfg = {
        "log": {"level": "warn", "timestamp": False},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": route,
        "experimental": {
            "clash_api": {
                "external_controller": f"127.0.0.1:{api_port}",
                "secret": secret,
            }
        },
    }
    return cfg


# ============================================================ 内核运行 + 延迟/速度探测
_NO_PROXY_OPENER = None


def _local_opener():
    """
    访问本机 Clash API 用的 opener —— 强制禁用系统代理。

    ⚠️ 这是「整轮全灭」的头号根因：开着 v2rayN 的系统代理时，urllib 会把
    127.0.0.1:9090 的请求也发给代理，代理连不回本机 → 返回 502 Bad Gateway →
    _wait_api 判定「内核未就绪」→ 一整轮节点全部判失败。
    """
    global _NO_PROXY_OPENER
    if _NO_PROXY_OPENER is None:
        _NO_PROXY_OPENER = urllib.request.build_opener(
            urllib.request.ProxyHandler({}))
    return _NO_PROXY_OPENER


def _api_get(base, secret, path, timeout=8):
    url = base + path
    req = urllib.request.Request(url)
    if secret:
        req.add_header("Authorization", "Bearer " + secret)
    try:
        with _local_opener().open(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except Exception:
        return None


def _api_put(base, secret, path, data, timeout=8):
    req = urllib.request.Request(url=base + path, data=json.dumps(data).encode(),
                                method="PUT")
    req.add_header("Content-Type", "application/json")
    if secret:
        req.add_header("Authorization", "Bearer " + secret)
    try:
        with _local_opener().open(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except Exception:
        return None


def _port_free(port, host="127.0.0.1"):
    """端口是否可用（用于避免多开实例抢同一个 API 端口导致整轮全灭）"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, port))
        return True
    except OSError:
        return False


def _find_free_port(start, tries=200):
    """从 start 起找第一个空闲端口"""
    for p in range(start, start + tries):
        if _port_free(p):
            return p
    return start


_ACTIVE_PIDS = set()      # 本次进程启动过的内核 PID


def _kernel_pid_file():
    try:
        base = (sys._MEIPASS if getattr(sys, "frozen", False)
                else os.path.dirname(os.path.abspath(__file__)))
        return os.path.join(base, ".kernel_pids")
    except Exception:
        return None


def _save_pids():
    p = _kernel_pid_file()
    if not p:
        return
    try:
        with open(p, "w", encoding="utf-8") as f:
            json.dump(sorted(_ACTIVE_PIDS), f)
    except Exception:
        pass


def _kernel_cmdlines():
    """返回 {pid: 命令行}（只列 sing-box.exe）；查不到就返回空 → 安全优先，不做清理"""
    if sys.platform != "win32":
        return {}
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-CimInstance Win32_Process -Filter \"Name='sing-box.exe'\" | "
             "Select-Object ProcessId,CommandLine | ConvertTo-Csv -NoTypeInformation"],
            capture_output=True, text=True, timeout=15,
            creationflags=0x08000000)
        txt = out.stdout or ""
    except Exception:
        return {}
    res = {}
    try:
        for row in csv.reader(io.StringIO(txt)):
            if len(row) >= 2 and row[0].strip().isdigit():
                res[int(row[0].strip())] = row[1]
    except Exception:
        return {}
    return res


def kill_stale_kernels():
    """
    清理上次异常退出（被强杀/崩溃）残留的 sing-box 内核。

    ⚠️ 关键：只杀「命令行含 sbprobe_」的进程 —— 那是我们自己的临时配置目录。
    v2rayN 也在用 sing-box.exe，绝不能按进程名一刀切地杀。
    """
    cmds = _kernel_cmdlines()
    if not cmds:
        return 0
    killed = 0
    for pid, cmd in cmds.items():
        if "sbprobe_" not in (cmd or ""):
            continue                      # 别人的内核，不碰
        try:
            subprocess.run(["taskkill", "/PID", str(pid), "/F"],
                           capture_output=True, timeout=8,
                           creationflags=0x08000000)
            killed += 1
        except Exception:
            pass
    return killed


def _wait_api(base, secret, timeout=12):
    t0 = time.time()
    last = None
    while time.time() - t0 < timeout:
        try:
            req = urllib.request.Request(base + "/version")
            if secret:
                req.add_header("Authorization", "Bearer " + secret)
            with _local_opener().open(req, timeout=3) as r:
                if r.status == 200:
                    return True
                last = f"HTTP {r.status}"
        except urllib.error.HTTPError as e:
            last = f"HTTP {e.code} {e.reason}"   # 502 = 被系统代理劫持
        except Exception as e:
            last = f"{type(e).__name__}: {e}"
        time.sleep(0.4)
    hint = ""
    if last and "502" in str(last):
        hint = ("  ← 502 说明请求被系统代理劫持了（v2rayN 开着系统代理时，"
                "本机 API 请求也会被发出去）")
    print(f"[内核] Clash API 未就绪（{last}）{hint}")
    return False


def _speed_through_proxy(proxy_url, url, bytes_target=3_000_000, timeout=15):
    """通过本地代理下载测速，返回 KB/s（带总时长保险，防慢速节点无限拖延）"""
    try:
        handler = urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
        op = urllib.request.build_opener(handler)
        req = urllib.request.Request(url, headers={"User-Agent": "sbprobe-speed"})
        t0 = time.time()
        deadline = t0 + max(float(timeout) * 3, 30)   # 总时长硬上限
        got = 0
        with op.open(req, timeout=timeout) as resp:
            while got < bytes_target:
                if time.time() > deadline:
                    break
                chunk = resp.read(65536)
                if not chunk:
                    break
                got += len(chunk)
        dt = time.time() - t0
        return (got / 1024.0) / dt if dt > 0 else 0.0
    except Exception:
        return 0.0


def run_probe(items, kernel=DEFAULT_KERNEL, api_port=9090, secret="sbprobe",
              test_url=DEFAULT_TEST_URL, test_timeout_ms=DEFAULT_TEST_TIMEOUT_MS,
              per_node_timeout=8, startup_timeout=15,
              measure_speed=False, speed_port=None, concurrency=20, speed_top_n=20,
              speed_url="https://speed.cloudflare.com/__down?bytes=3000000",
              speed_bytes=3_000_000, speed_timeout=15,
              progress_cb=None, cancel_cb=None, repeat=1):
    """
    启动 sing-box -> 并发测延迟 -> 对延迟最快的 top-N 实测下载速度 -> 关闭内核
    两阶段设计（v1.5）：
      阶段1  延迟测试：Clash API 并发 urltest（concurrency 路），831 节点 ~2 分钟
      阶段2  速度测试：selector 全局唯一无法并发，仅对延迟最快 speed_top_n 个
             节点串行实测下载，避免整体耗时爆炸
    返回: ([{"tag","link","proto","delay_ms":int|None,"speed_kbs":float,"ok":bool}], cancelled)
      progress_cb(done, total, phase): phase="delay"/"speed"，每完成一个节点回调
      cancel_cb(): 返回 True 时中止（取消的节点不出现在结果里，已测的保留）
    """
    if not items:
        return [], False
    if not os.path.exists(kernel):
        print(f"[内核] 未找到 sing-box: {kernel}")
        return ([{"tag": it["tag"], "link": it["link"], "proto": it["proto"],
                 "delay_ms": None, "speed_kbs": 0.0, "ok": False} for it in items], False)

    # ⚠️ 端口必须自适应：同时开两个 exe（或别的程序占了 9090）时，
    # 后启动的内核绑不上端口 → Clash API 起不来 → 整轮节点全部判定失败却没有任何提示
    if not _port_free(api_port):
        api_port = _find_free_port(api_port + 1)
    if measure_speed:
        if not speed_port:
            speed_port = api_port + 1000
        if not _port_free(speed_port):
            speed_port = _find_free_port(speed_port + 1)
    cfg = build_config(items, api_port, secret, speed_port=speed_port if measure_speed else None)
    tmp = tempfile.mkdtemp(prefix="sbprobe_")
    cfg_path = os.path.join(tmp, "config.json")
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)

    base = f"http://127.0.0.1:{api_port}"
    proxy_url = f"http://127.0.0.1:{speed_port}" if measure_speed else None
    proc = None
    try:
        proc = subprocess.Popen(
            [kernel, "run", "-c", cfg_path],
            # ⚠️ 不能用 PIPE：大量失败节点时内核 warning 会塞满 64KB 管道缓冲区，
            # 内核写日志被阻塞 → 整体冻住、所有 API 超时。直接丢弃输出。
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=0x08000000,  # CREATE_NO_WINDOW
        )
        _ACTIVE_PIDS.add(proc.pid)
        _save_pids()
        if not _wait_api(base, secret, startup_timeout):
            print("[内核] Clash API 未就绪（启动超时或配置错误）")
            return [_fail(it) for it in items], False

        proxies = _api_get(base, secret, "/proxies", timeout=8)
        valid = set(proxies.get("proxies", {}).keys()) if proxies else set()

        results = []
        cancelled = False
        total = len(items)
        done_lock = threading.Lock()
        done_count = [0]

        # ---------- 阶段1：并发延迟测试 ----------
        def _test_delay(it):
            # 任务真正开跑前再查一次取消（此时可能还在队列里排队）
            if cancel_cb and cancel_cb():
                return None  # 已取消：该节点不测、不出结果
            tag = it["outbound"]["tag"]
            delays = []
            # repeat>1：同一节点连测多次取中位数，抵消单次抖动的误判（精测模式）
            for _ in range(max(1, int(repeat or 1))):
                if cancel_cb and cancel_cb():
                    break
                if tag in valid:
                    ep = f"/proxies/{urllib.parse.quote(tag, safe='')}/delay" + \
                         f"?url={urllib.parse.quote(test_url, safe='')}&timeout={test_timeout_ms}"
                    d = _api_get(base, secret, ep, timeout=per_node_timeout)
                    if d and isinstance(d, dict):
                        dl = d.get("delay")
                        if isinstance(dl, (int, float)) and dl > 0:
                            delays.append(int(dl))
            if delays:
                delays.sort()
                return it, delays[len(delays) // 2], True     # 中位数
            return it, None, False

        workers = max(1, min(int(concurrency or 1), 64))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(_test_delay, it) for it in items]
            for f in futures:
                try:
                    r = f.result()
                except Exception:
                    continue
                if r is None:   # 被取消跳过的节点
                    cancelled = True
                    continue
                it, delay, ok = r
                results.append({"tag": it["outbound"]["tag"], "link": it["link"],
                                "proto": it["proto"],
                                "host": it["outbound"].get("server", ""),
                                "port": it["outbound"].get("server_port", ""),
                                "delay_ms": delay, "speed_kbs": 0.0, "ok": ok})
                with done_lock:
                    done_count[0] += 1
                    n = done_count[0]
                if progress_cb:
                    try:
                        progress_cb(n, total, "delay")
                    except Exception:
                        pass
        results.sort(key=lambda r: (not r["ok"], r["delay_ms"] if r["delay_ms"] else 10**9))

        # ---------- 阶段2：仅对延迟最快的 top-N 实测下载速度 ----------
        if measure_speed and proxy_url and not cancelled and speed_top_n > 0:
            tops = [r for r in results if r["ok"]][:int(speed_top_n)]
            for i, r in enumerate(tops, 1):
                if cancel_cb and cancel_cb():
                    cancelled = True
                    break
                _api_put(base, secret, "/proxies/PROXY", {"name": r["tag"]}, timeout=5)
                sp = _speed_through_proxy(proxy_url, speed_url,
                                          speed_bytes, speed_timeout)
                r["speed_kbs"] = round(sp, 1)
                if progress_cb:
                    try:
                        progress_cb(i, len(tops), "speed")
                    except Exception:
                        pass
        return results, cancelled
    except Exception as e:
        print(f"[内核] 运行异常: {e}")
        return [_fail(it) for it in items], False
    finally:
        if proc:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                    proc.wait(timeout=3)
                except Exception:
                    pass
            _ACTIVE_PIDS.discard(proc.pid)
            _save_pids()
        try:
            shutil.rmtree(tmp, ignore_errors=True)
        except Exception:
            pass


def _fail(it):
    return {"tag": it["outbound"]["tag"], "link": it["link"],
            "proto": it["proto"], "host": it["outbound"].get("server", ""),
            "port": it["outbound"].get("server_port", ""), "delay_ms": None,
            "speed_kbs": 0.0, "ok": False}


def probe_links(links, kernel=DEFAULT_KERNEL, **kw):
    """便捷入口：分享链接列表 -> 探测结果"""
    items = []
    for l in links:
        it = parse_link_to_item(l)
        if it:
            items.append(it)
    return run_probe(items, kernel=kernel, **kw)


# ============================================================ outbound -> 分享链接（用于输出订阅）
def outbound_to_link(ob):
    """把 sing-box outbound 尽力还原成分享链接（保证输出订阅可用）"""
    t = ob.get("type")
    tag = ob.get("tag", "node")
    host = ob.get("server", "")
    port = ob.get("server_port", 0)
    name = urllib.parse.quote(tag)
    if t == "vmess":
        d = {
            "v": "2", "ps": tag, "add": host, "port": port,
            "id": ob.get("uuid", ""), "aid": ob.get("alter_id", 0),
            "scy": ob.get("security", "auto"), "net": "tcp",
            "type": "none", "host": "", "path": "", "tls": "",
        }
        tr = ob.get("transport")
        if tr:
            nt = tr.get("type")
            if nt == "ws":
                d["net"] = "ws"
                d["path"] = tr.get("path", "/")
                d["host"] = (tr.get("headers") or {}).get("Host", "")
            elif nt == "grpc":
                d["net"] = "grpc"
                d["path"] = tr.get("service_name", "")
            elif nt == "http":
                d["net"] = "h2"
                d["path"] = (tr.get("path") or ["/"])[0]
                d["host"] = (tr.get("host") or [""])[0]
        if ob.get("tls"):
            d["tls"] = "tls"
            d["sni"] = (ob.get("tls") or {}).get("server_name", "")
        b = base64.b64encode(json.dumps(d, ensure_ascii=False).encode()).decode()
        return "vmess://" + b + "#" + name
    if t == "vless":
        tls = ob.get("tls") or {}
        # security 只写一次：reality 优先，否则按是否 tls
        if tls.get("reality", {}).get("enabled"):
            sec = "reality"
        else:
            sec = "tls" if tls else "none"
        q = f"encryption=none&security={sec}"
        if ob.get("flow"):
            q += f"&flow={ob['flow']}"
        tr = ob.get("transport")
        if tr:
            nt = tr.get("type")
            if nt == "ws":
                q += f"&type=ws&path={tr.get('path','/')}"
                if (tr.get("headers") or {}).get("Host"):
                    q += f"&host={tr['headers']['Host']}"
            elif nt == "grpc":
                q += f"&type=grpc&serviceName={tr.get('service_name','')}"
            elif nt == "http":
                q += f"&type=h2&path={(tr.get('path') or ['/'])[0]}"
                if (tr.get("host") or [""])[0]:
                    q += f"&host={tr['host'][0]}"
        if tls.get("server_name"):
            q += f"&sni={tls['server_name']}"
        if tls.get("utls", {}).get("fingerprint"):
            q += f"&fp={tls['utls']['fingerprint']}"
        if tls.get("reality", {}).get("enabled"):
            if tls["reality"].get("public_key"):
                q += f"&pbk={tls['reality']['public_key']}"
            if tls["reality"].get("short_id"):
                q += f"&sid={tls['reality']['short_id']}"
        if tls.get("insecure"):
            q += "&allow_insecure=1"
        if tls.get("alpn"):
            q += f"&alpn={','.join(tls['alpn'])}"
        return f"vless://{ob.get('uuid','')}@{host}:{port}?{q}#{name}"
    if t == "trojan":
        tls = ob.get("tls") or {}
        q = ""
        if tls.get("server_name"):
            q += f"sni={tls['server_name']}"
        if tls.get("insecure"):
            q += "&allow_insecure=1"
        if tls.get("alpn"):
            q += f"&alpn={','.join(tls['alpn'])}"
        tr = ob.get("transport")
        if tr and tr.get("type") == "ws":
            q += f"&type=ws&path={tr.get('path','/')}"
            if (tr.get("headers") or {}).get("Host"):
                q += f"&host={tr['headers']['Host']}"
        q = q.strip("&")
        return f"trojan://{ob.get('password','')}@{host}:{port}?{q}#{name}"
    if t == "hysteria2":
        tls = ob.get("tls") or {}
        q = ""
        if tls.get("server_name"):
            q += f"sni={tls['server_name']}"
        if tls.get("insecure"):
            q += "&insecure=1"
        if tls.get("alpn"):
            q += f"&alpn={','.join(tls['alpn'])}"
        obfs = ob.get("obfs")
        if obfs:
            q += f"&obfs={obfs.get('type','')}&obfs-password={obfs.get('password','')}"
        q = q.strip("&")
        return f"hysteria2://{ob.get('password','')}@{host}:{port}?{q}#{name}"
    if t == "tuic":
        tls = ob.get("tls") or {}
        q = f"congestion_control={ob.get('congestion_control','bbr')}"
        if tls.get("server_name"):
            q += f"&sni={tls['server_name']}"
        if tls.get("insecure"):
            q += "&allow_insecure=1"
        if tls.get("alpn"):
            q += f"&alpn={','.join(tls['alpn'])}"
        return f"tuic://{ob.get('uuid','')}:{ob.get('password','')}@{host}:{port}?{q}#{name}"
    if t == "anytls":
        tls = ob.get("tls") or {}
        q = ""
        if tls.get("server_name"):
            q += f"sni={tls['server_name']}"
        if tls.get("insecure"):
            q += "&insecure=1"
        q = q.strip("&")
        return f"anytls://{ob.get('password','')}@{host}:{port}?{q}#{name}"
    if t == "shadowsocks":
        cred = base64.b64encode(f"{ob.get('method','aes-256-gcm')}:{ob.get('password','')}".encode()).decode()
        return f"ss://{cred}@{host}:{port}#{name}"
    return None


if __name__ == "__main__":
    # 自测：解析样例链接
    sample = ("vless://00000000-0000-0000-0000-000000000000@example.com:41241"
              "?encryption=none&flow=xtls-rprx-vision&security=reality&sni=example.com"
              "&fp=chrome&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
              "&sid=00000000&type=tcp#Demo-Reality")
    it = parse_link_to_item(sample)
    print(json.dumps(it["outbound"], ensure_ascii=False, indent=2))
    # 还原链接
    print("还原:", outbound_to_link(it["outbound"]))
