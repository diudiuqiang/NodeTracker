# -*- coding: utf-8 -*-
"""
节点稳定性追踪器 v1.3
=====================

核心思路（主人的设计）:
  · 每隔 N 小时（默认 3 小时）自动跑一轮测速
  · 每轮结果全部落盘累积成历史
  · 统计时取「多轮结果的交集」→ 那是长期稳定、能长久用的节点
  · 同时给「动态的优秀节点」留入口 → 不漏掉新冒出来的好节点
  · 最终订阅 = 核心组(交集) ∪ 新秀组(动态)

v1.3 新增（借鉴 SubsCheck-Win-GUI）:
  · 🆓 一键填充 GitHub 免费节点源（68 个聚合订阅）
  · Github 加速前缀（raw.githubusercontent 直连不通时用）
  · ④ 订阅服务：本地 HTTP 常驻订阅 + 局域网 IP 选择 + 一键复制订阅 URL
  · 订阅保留节点数 / 测速下限过滤
  · 启动时自动开始测速 / 自动开启订阅服务（常驻模式）

用法: python node_stability_tracker.py
依赖: 仅 Python 标准库
"""

import sys
import re
import socket
import ssl
import time
import csv
import os
import json
import base64
import threading
import datetime
import traceback
import urllib.parse
import urllib.request
import statistics
import random
import http.server
import subprocess
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from concurrent.futures import ThreadPoolExecutor

# 系统托盘用（Windows）；非 Windows 环境下 import 失败会自动降级为「直接退出」
try:
    import ctypes
    from ctypes import wintypes
except Exception:
    ctypes = None
    wintypes = None

# 内核探测模块（sing-box Clash API，准确测所有协议延迟+真实下载速度）
import singbox_probe as sb

__version__ = "1.9.3"

# v1.9 修复（2026-10-24，「GUI 显示 10 个但 v2rayN 只进 5 个」）：
#  P0-4 vmess 节点被 v2rayN 全量丢弃（根因读 v2rayN 源码实锤）：
#       v2rayN 的 ServiceLib/Handler/Fmt/VmessFmt.cs → ResolveVmess() 把 "vmess://"
#       之后的**整串（含 "#备注"）**直接丢给 Utils.Base64Decode()，而后者
#       （ServiceLib/Common/Utils.cs）只做 Replace('_','/') / Replace('-','+') /
#       去空格 / 补 padding，**完全不 split '#'**。我们给节点备注做过
#       urllib.parse.quote → 备注里的空格、"["、中文变成 %20 / %5B / %E4%BC%98，
#       '#' 与 '%' 都是非法 base64 字符 → 抛 Format_BadBase64Char → 返回空串 →
#       JSON 反序列化失败 → 节点丢弃。
#       实测：订阅 10 个节点，v2rayN 日志报 5 次 Format_BadBase64Char，SQLite 里
#       只入库 5 条（全是 vless），5 条 vmess 一条不剩。
#       linkmap 里 4,933 条 vmess **全部是旧式 base64 格式**（0 条新式）→ 只要
#       vmess 进订阅就必丢。
#       修复：输出前把旧式 `vmess://<base64 JSON>` 转成新式明文 URI
#       `vmess://uuid@host:port?type=ws&security=tls&host=..&path=..#备注`。
#       新式 URI 里 "#" 是标准 fragment → v2rayN 走 ResolveStdVmess 的 Uri 解析
#       （Utils.TryUri + Fragment），备注正确保留、节点正常入库。

# v1.7 修复清单（2026-10-24，根因均用真实数据实锤）：
#  P0-1 订阅凑不满 top_n：旧版先 final[:top] 截断再解析链接，前 top 名里没链接的
#       节点被静默丢弃且无回填（实测 10 个丢 3 个只剩 7）→ 改为按序解析、收满即止
#  P0-2 免费节点链接丢失：无名节点（ps="node"）旧版存成 node@host:port 键，与
#       analyze 规范化后的 host:port@host:port 查找键对不上 → 查找兼容旧键 +
#       migrate_linkmap.py 给 tracker_links.json 补键（16,318 → 17,252 键）
#  P1-1 陈年样本霸榜：老样本（源早死）avail%=100% 永居前排 → analyze 加 14 天时间窗
#  P1-2 全灭轮静默剔除：用户以为订阅正常更新实则数据冻结 → 低成功率轮弹窗告警
#  P2  gh_proxy 失效无感知：代理死了全部源静默失败 → 开轮前探活 + PROXY_BACKUPS 切换

# v1.8 修复（2026-10-24，「本轮全灭」弹窗触发后定位）：
#  P0-3 订阅源直连必被墙：67 个源 65 个是 raw.githubusercontent.com，urllib 直连
#       全 000（GFW IP 封锁+SNI 阻断），gh 镜像前缀直连同样被墙 → 全部源静默失败，
#       测速只能吃 826 个手动缓存节点（5 小时前导出，免费节点已死 97.8%）→ 全灭轮。
#       修复：新增「拉源代理」配置（本机 sing-box/v2rayN 的 SOCKS5/HTTP 代理），
#       _worker 拉源经代理走；实测经 socks5h://127.0.0.1:10809 拉通 SoliSpirit
#       源 10,647 节点、go4sharing 15 节点。代理不可用时自动回退 gh_proxy 镜像链。
#  P1-3 Clash YAML 订阅源解析 0 节点：67 个源里一大半是 Clash YAML（proxies: 段），
#       NodeTracker 只认 URI 格式 → 拉到内容也解析不出节点。修复：singbox_probe
#       新增零依赖 Clash 解析器（点分键拍平 ws-opts/reality-opts 嵌套）+ proxy→
#       sing-box outbound 映射（vmess/vless/trojan/ss/hysteria2/tuic/anytls）。

# 订阅兜底最少节点数：稳定组（核心∪新秀）不足时，用实测可用的高分节点补齐，
# 避免订阅变成空的导致客户端更新订阅报错
MIN_FALLBACK = 10
# 自建节点精测次数（同一节点连测 N 次取中位数，抵消单次抖动）
OWN_REPEAT = 3
# 精选输出：订阅默认只给综合最优的前 N 个（用户真正会用的就那么几个）
DEFAULT_PICK_N = 5
# v1.7 历史时间窗：只统计最近 N 天的样本。
# 不设窗口时，陈年样本（源早就死了但历史里还有 2 次成功）avail% 永远是 100%，
# 会一直霸榜把新节点压死 → 订阅看起来"永远不变"。
HISTORY_WINDOW_DAYS = 14
# v1.7 gh 代理备份链：主代理探活失败时按顺序自动切换
PROXY_BACKUPS = ["https://gh-proxy.com/", "https://ghfast.top/", "https://ghproxy.net/"]
# v1.8 本机拉源代理候选（sing-box 客户端 10809=SOCKS5；v2rayN 常见 10808=SOCKS/10809=HTTP）
SRC_PROXY_CANDIDATES = ["socks5h://127.0.0.1:10809", "socks5h://127.0.0.1:10808",
                        "http://127.0.0.1:10809", "http://127.0.0.1:10808",
                        "socks5h://192.168.31.254:7890", "http://192.168.31.254:7890"]


def _proxy_alive(prefix, timeout=6, via="", as_prefix=True):
    """v1.7 探活 gh 代理：经代理拉一个已知存在的小文件（HEAD 失败退化 GET）
    v1.8 via：拉源代理（socks5h://... 走 curl.exe；http:// 走 urllib ProxyHandler）
    v1.8 as_prefix=False：prefix 是代理地址本身（src_proxy 探活），URL 不加前缀"""
    if not prefix:
        return False
    if as_prefix:
        test = prefix + "https://raw.githubusercontent.com/bestruirui/BestSub/v2/README.md"
    else:
        test = "https://raw.githubusercontent.com/bestruirui/BestSub/v2/README.md"
    if via:
        body = sb._http_get_via_curl(test, via, timeout=timeout)
        return body is not None
    try:
        try:
            req = urllib.request.Request(test, method="HEAD")
        except Exception:
            req = urllib.request.Request(test)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status == 200
    except Exception:
        pass
    try:
        with urllib.request.urlopen(test, timeout=timeout) as r:
            return r.status == 200
    except Exception:
        return False

# ⚠️ 数据文件必须落在 exe/脚本自身所在目录，不能依赖 CWD
# （否则从其它目录启动、或 CWD 不可写时，历史与配置会静默写失败）
BASE_DIR = (os.path.dirname(sys.executable) if getattr(sys, "frozen", False)
            else os.path.dirname(os.path.abspath(__file__)))
HISTORY_FILE = os.path.join(BASE_DIR, "node_history.csv")
CONFIG_FILE = os.path.join(BASE_DIR, "tracker_config.json")

# 内置免费节点源（借鉴 SubsCheck「一键获取 GitHub 免费节点」）
FREE_SOURCES = [
    "https://raw.githubusercontent.com/snakem982/proxypool/main/source/clash-meta.yaml",
    "https://raw.githubusercontent.com/snakem982/proxypool/main/source/clash-meta-2.yaml",
    "https://raw.githubusercontent.com/go4sharing/sub/main/sub.yaml",
    "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/all_configs.txt",
    "https://raw.githubusercontent.com/firefoxmmx2/v2rayshare_subcription/main/subscription/clash_sub.yaml",
    "https://raw.githubusercontent.com/Roywaller/clash_subscription/main/clash_subscription.txt",
    "https://raw.githubusercontent.com/Q3dlaXpoaQ/V2rayN_Clash_Node_Getter/main/APIs/sc0.yaml",
    "https://raw.githubusercontent.com/Q3dlaXpoaQ/V2rayN_Clash_Node_Getter/main/APIs/sc1.yaml",
    "https://raw.githubusercontent.com/Q3dlaXpoaQ/V2rayN_Clash_Node_Getter/main/APIs/sc2.yaml",
    "https://raw.githubusercontent.com/Q3dlaXpoaQ/V2rayN_Clash_Node_Getter/main/APIs/sc3.yaml",
    "https://raw.githubusercontent.com/Q3dlaXpoaQ/V2rayN_Clash_Node_Getter/main/APIs/sc4.yaml",
    "https://raw.githubusercontent.com/xiaoji235/airport-free/main/clash/naidounode.txt",
    "https://raw.githubusercontent.com/mahdibland/SSAggregator/master/sub/sub_merge_yaml.yml",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity.yml",
    "https://raw.githubusercontent.com/vxiaov/free_proxies/main/clash/clash.provider.yaml",
    "https://raw.githubusercontent.com/leetomlee123/freenode/main/README.md",
    "https://raw.githubusercontent.com/chengaopan/AutoMergePublicNodes/master/list.yml",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/clash.yml",
    "https://raw.githubusercontent.com/zhangkaiitugithub/passcro/main/speednodes.yaml",
    "https://raw.githubusercontent.com/mgit0001/test_clash/main/heima.txt",
    "https://raw.githubusercontent.com/mai19950/clashgithub_com/main/site",
    "https://raw.githubusercontent.com/mai19950/sites/main/sub/v2ray/base64",
    "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/shahidbhutta/Clash/main/Router",
    "https://raw.githubusercontent.com/anaer/Sub/main/clash.yaml",
    "https://raw.githubusercontent.com/free18/v2ray/main/c.yaml",
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.yml",
    "https://raw.githubusercontent.com/mfbpn/tg_mfbpn_sub/main/trial.yaml",
    "https://raw.githubusercontent.com/Ruk1ng001/freeSub/main/clash.yaml",
    "https://raw.githubusercontent.com/ripaojiedian/freenode/main/clash",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/clash.yaml",
    "https://raw.githubusercontent.com/xiaoji235/airport-free/main/v2ray.txt",
    "https://raw.githubusercontent.com/vxiaov/free_proxies/main/links.txt",
    "https://raw.githubusercontent.com/xiaoji235/airport-free/main/v2ray/v2rayshare.txt",
    "https://raw.githubusercontent.com/MrMohebi/xray-proxy-grabber-telegram/master/collected-proxies/clash-meta/all.yaml",
    "https://raw.githubusercontent.com/ts-sf/fly/main/clash",
    "https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/yudou66.txt",
    "https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/clashmeta.txt",
    "https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/ndnode.txt",
    "https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/nodev2ray.txt",
    "https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/nodefree.txt",
    "https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/v2rayshare.txt",
    "https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/wenode.txt",
    "https://raw.githubusercontent.com/ggborr/FREEE-VPN/main/4V2ray",
    "https://raw.githubusercontent.com/SamanGho/v2ray_collector/main/v2tel_links1.txt",
    "https://raw.githubusercontent.com/SamanGho/v2ray_collector/main/v2tel_links2.txt",
    "https://raw.githubusercontent.com/acymz/AutoVPN/main/data/V2.txt",
    "https://raw.githubusercontent.com/peacefish/nodefree/main/sub/proxy_cf.yaml",
    "https://raw.githubusercontent.com/darknessm427/IranConfigCollector/main/V2.txt",
    "https://raw.githubusercontent.com/NiceVPN123/NiceVPN/main/utils/pool/output.yaml",
    "https://raw.githubusercontent.com/yorkLiu/FreeV2RayNode/main/v2ray.txt",
    "https://raw.githubusercontent.com/gfpcom/free-proxy-list/main/list/ss.txt",
    "https://raw.githubusercontent.com/gfpcom/free-proxy-list/main/list/ssr.txt",
    "https://raw.githubusercontent.com/gfpcom/free-proxy-list/main/list/trojan.txt",
    "https://raw.githubusercontent.com/gfpcom/free-proxy-list/main/list/vless.txt",
    "https://raw.githubusercontent.com/gfpcom/free-proxy-list/main/list/vmess.txt",
    "https://raw.githubusercontent.com/NiceVPN123/NiceVPN/main/Clash.yaml",
    "https://raw.githubusercontent.com/lagzian/SS-Collector/main/SS/trinity_clash.yaml",
    "https://raw.githubusercontent.com/lagzian/SS-Collector/main/SS/VM_TrinityBase",
    "https://raw.githubusercontent.com/lagzian/SS-Collector/main/SS/TrinityBase",
    "https://raw.githubusercontent.com/darknessm427/IranConfigCollector/main/bulk/ss_iran.txt",
    "https://raw.githubusercontent.com/darknessm427/IranConfigCollector/main/bulk/trojan_iran.txt",
    "https://raw.githubusercontent.com/darknessm427/IranConfigCollector/main/bulk/vless_iran.txt",
    "https://raw.githubusercontent.com/darknessm427/IranConfigCollector/main/bulk/vmess_iran.txt",
]

# 常见 GitHub 加速前缀（可手填其它）
GH_PROXIES = ["", "https://gh-proxy.com/", "https://ghfast.top/", "https://gh-proxy.net/"]

# sing-box 内核路径（复用 v2rayN 自带，无需下载）
# v1.9.2：v2rayN 安装路径会变（v2rayN-With-Core → v2rayN-windows-64），
# 内核路径不再写死一处，改为多候选搜索。
SINGBOX_KERNEL_CANDIDATES = [
    r"C:\v2rayN-windows-64\bin\sing_box\sing-box.exe",
    r"C:\v2rayN-With-Core\bin\sing_box\sing-box.exe",
    r"D:\v2rayN-windows-64\bin\sing_box\sing-box.exe",
    r"C:\v2rayN\bin\sing_box\sing-box.exe",
]

# v1.9.3：内核获取策略（开源友好，无需预装 v2rayN 也能跑）
#   · 一键导入 v2rayN 时自动定位其自带内核
#   · 本机没装 v2rayN → 「📦 一键下载内核」按钮从 GitHub 拉取 sing-box（经加速镜像）
#   · 也可「📂 指定内核」手动选择 sing-box.exe
SINGBOX_DOWNLOAD_VERSION = "1.11.12"   # 默认拉取版本（稳定线，兼容本工具生成的配置）
DOWNLOAD_MIRRORS = [                   # GitHub 加速镜像（国内可直连；按顺序尝试）
    "https://ghfast.top",
    "https://gh-proxy.com",
    "https://gh-proxy.net",
    "https://mirror.ghproxy.com",
]


def get_kernel():
    """解析 sing-box 内核路径：
    持久化路径(导入v2rayN/一键下载/手动指定) > 打包内 > exe同目录 >
    各 v2rayN 候选路径 > PATH > 默认候选(报错时给明确提示)

    v1.9.2 起不再只认一个写死路径；v1.9.3 起优先用已配置/已下载的内核。"""
    import sys, shutil
    # 0) 持久化的内核路径优先（v1.9.3：导入 v2rayN / 一键下载 / 手动指定都会写这里）
    try:
        if os.path.exists(CONFIG_FILE):
            _k = json.load(open(CONFIG_FILE, encoding="utf-8")).get("singbox_kernel") or ""
            if _k and os.path.exists(_k):
                return _k
    except Exception:
        pass
    if getattr(sys, "frozen", False):
        # PyInstaller onefile：内核已打进 _MEIPASS
        p = os.path.join(sys._MEIPASS, "sing-box.exe")
        if os.path.exists(p):
            return p
        q = os.path.join(os.path.dirname(sys.executable), "sing-box.exe")
        if os.path.exists(q):
            return q
    for cand in SINGBOX_KERNEL_CANDIDATES:
        if os.path.exists(cand):
            return cand
    on_path = shutil.which("sing-box.exe")
    if on_path:
        return on_path
    # 全找不到：返回新默认路径，让上层报错时给出明确提示（而非神秘失败）
    return SINGBOX_KERNEL_CANDIDATES[0]


TIME_SLOTS = {"上午": (9, 12), "中午": (12, 14), "晚上": (19, 23)}


def _remark_of(link):
    """从分享链接提取备注名（# 之后部分）"""
    link = (link or "").strip()
    if "#" in link:
        try:
            return urllib.parse.unquote(link.split("#", 1)[1])
        except Exception:
            return link.split("#", 1)[1]
    return link.split("://", 1)[-1][:40]


def current_slot():
    h = datetime.datetime.now().hour
    for name, (a, b) in TIME_SLOTS.items():
        if a <= h < b:
            return name
    return "上午" if h < 9 else "晚上"


def _lan_ips():
    """枚举本机局域网 IP（借鉴 SubsCheck 的局域网 IP 选择）"""
    ips = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.append(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    try:
        ips += socket.gethostbyname_ex(socket.gethostname())[2]
    except Exception:
        pass
    uniq = []
    for i in ips:
        if i and not i.startswith("127.") and i not in uniq:
            uniq.append(i)
    return uniq


# ============================================================ v2rayN 一键导入
def _find_v2rayn_db():
    """探测本机 v2rayN 的节点数据库 guiNDB.db（多版本/多安装位置/多盘符兼容）
    顺序：上次手动指定的路径（记住，跨机器换路径无痛）→ 环境变量常见位置 →
    全盘符扫描（含一级/二级子目录里的 v2rayN* 目录）"""
    import string
    # 0) 上次手动指定的路径优先
    try:
        if os.path.exists(CONFIG_FILE):
            p = (json.load(open(CONFIG_FILE, encoding="utf-8"))
                 .get("v2rayn_db") or "").strip()
            if p and os.path.exists(p):
                return p
    except Exception:
        pass

    candidates = []
    # 1) 环境变量常见位置
    for env in ("APPDATA", "LOCALAPPDATA", "ProgramFiles", "ProgramFiles(x86)"):
        base = os.environ.get(env)
        if base:
            candidates += [
                os.path.join(base, "v2rayN", "guiNDB.db"),
                os.path.join(base, "v2rayN", "guiConfigs", "guiNDB.db"),
            ]
    # 2) 所有存在的盘符：根目录 + 一级/二级子目录中的 v2rayN*
    drives = [f"{d}:\\" for d in string.ascii_uppercase if os.path.exists(f"{d}:\\")]
    known_names = ("v2rayN", "v2rayN-With-Core", "v2rayN-Core",
                   "v2rayN-windows-64", "v2rayn")
    for drv in drives:
        for name in known_names:
            candidates += [
                os.path.join(drv, name, "guiConfigs", "guiNDB.db"),
                os.path.join(drv, name, "guiNDB.db"),
            ]
        try:
            for entry in os.scandir(drv):
                if not (entry.is_dir() and "v2rayn" in entry.name.lower()):
                    continue
                candidates.append(os.path.join(entry.path, "guiConfigs", "guiNDB.db"))
                candidates.append(os.path.join(entry.path, "guiNDB.db"))
                try:  # 二级子目录（如 X:\Soft\v2rayN-With-Core）
                    for e2 in os.scandir(entry.path):
                        if e2.is_dir() and "v2rayn" in e2.name.lower():
                            candidates.append(
                                os.path.join(e2.path, "guiConfigs", "guiNDB.db"))
                            candidates.append(os.path.join(e2.path, "guiNDB.db"))
                except Exception:
                    pass
        except Exception:
            pass
    for c in candidates:
        if c and os.path.exists(c):
            return c
    return None


# ============================================================ v1.9.3 内核获取辅助
def _v2rayn_root_from_db(db_path):
    """由 guiNDB.db 路径反推 v2rayN 安装根目录
    db 多在 <root>/guiConfigs/guiNDB.db 或 <root>/guiNDB.db"""
    d = os.path.dirname(db_path)
    if os.path.basename(d).lower() == "guiconfigs":
        d = os.path.dirname(d)
    return d


def _find_singbox_in_v2rayn(root):
    """在 v2rayN 安装目录里找自带 sing-box 内核（兼容经典 / 新版目录布局）"""
    cands = [
        os.path.join(root, "bin", "sing_box", "sing-box.exe"),
        os.path.join(root, "sing-box.exe"),
        os.path.join(root, "bin", "sing-box.exe"),
    ]
    for c in cands:
        if os.path.exists(c):
            return c
    return None


def _persist_singbox_kernel(path):
    """把内核路径写入配置（导入 v2rayN / 一键下载 / 手动指定都会调用）"""
    try:
        cfg = {}
        if os.path.exists(CONFIG_FILE):
            cfg = json.load(open(CONFIG_FILE, encoding="utf-8"))
        cfg["singbox_kernel"] = path or ""
        json.dump(cfg, open(CONFIG_FILE, "w", encoding="utf-8"),
                  ensure_ascii=False, indent=1)
    except Exception:
        pass


def _v2n_safe_json(s):
    try:
        return json.loads(s) if s else {}
    except Exception:
        return {}


def v2rayn_profile_to_outbound(d):
    """v2rayN ProfileItem 行(dict) -> sing-box outbound dict；不支持返回 None。
    注意：本机 v2rayN 的 uuid 存放在 Password 列（id 列为空），故优先取 Password。"""
    ct = str(d.get("configType", ""))
    host = (d.get("address") or "").strip()
    try:
        port = int(d.get("port") or 0)
    except Exception:
        port = 0
    if not host or not port:
        return None
    pe = _v2n_safe_json(d.get("ProtoExtra"))
    te = _v2n_safe_json(d.get("TransportExtra"))
    tls_field = (d.get("streamSecurity") or "").strip().lower()
    sni = (d.get("sni") or "").strip()
    ai = str(d.get("allowInsecure") or "").strip().lower() == "true"
    alpn = (d.get("alpn") or "").strip()
    fp = (d.get("fingerprint") or "").strip()
    pbk = (d.get("publicKey") or "").strip()
    sid = (d.get("shortId") or "").strip()
    net = (d.get("network") or "tcp").strip().lower()
    if net in ("raw", "", "none"):
        net = "tcp"
    host_header = (d.get("requestHost") or te.get("Host") or "").strip()
    ws_path = (d.get("path") or te.get("Path") or "").strip()
    uuid = (d.get("id") or d.get("Password") or "").strip()
    pw = (d.get("Password") or "").strip()

    def make_tls():
        t = {"enabled": True}
        if sni:
            t["server_name"] = sni
        if ai:
            t["insecure"] = True
        if alpn:
            t["alpn"] = [a.strip() for a in alpn.split(",") if a.strip()]
        if fp:
            t["utls"] = {"enabled": True, "fingerprint": fp}
        return t

    def make_tr():
        if net == "ws":
            tr = {"type": "ws", "path": ws_path or "/"}
            if host_header:
                tr["headers"] = {"Host": host_header}
            return tr
        if net == "grpc":
            tr = {"type": "grpc"}
            if ws_path:
                tr["service_name"] = ws_path
            return tr
        if net == "http":
            tr = {"type": "http", "path": [ws_path or "/"]}
            if host_header:
                tr["host"] = [host_header]
            return tr
        return None

    if ct == "1":  # VMess
        ob = {"type": "vmess", "server": host, "server_port": port, "uuid": uuid,
              "alter_id": int(pe.get("AlterId", 0) or 0),
              "security": pe.get("VmessSecurity") or "auto"}
        tr = make_tr()
        if tr:
            ob["transport"] = tr
        if tls_field in ("tls", "reality"):
            ob["tls"] = make_tls()
        return ob
    if ct == "5":  # VLESS
        ob = {"type": "vless", "server": host, "server_port": port,
              "uuid": uuid, "packet_encoding": "xudp"}
        flow = pe.get("Flow") or ""
        if flow:
            ob["flow"] = flow
        tr = make_tr()
        if tr:
            ob["transport"] = tr
        if tls_field in ("tls", "reality"):
            t = make_tls()
            if tls_field == "reality":
                r = {"enabled": True}
                if pbk:
                    r["public_key"] = pbk
                if sid:
                    r["short_id"] = sid
                t["reality"] = r
                t.pop("insecure", None)
            ob["tls"] = t
        return ob
    if ct == "7":  # Hysteria2
        ob = {"type": "hysteria2", "server": host, "server_port": port,
              "password": pw, "tls": make_tls()}
        sal = pe.get("SalamanderPass") or ""
        if sal:
            ob["obfs"] = {"type": "salamander", "password": sal}
        return ob
    if ct == "8":  # TUIC
        ob = {"type": "tuic", "server": host, "server_port": port,
              "uuid": (d.get("Username") or "").strip(), "password": pw,
              "congestion_control": (d.get("headerType") or te.get("RawHeaderType") or "bbr").strip() or "bbr",
              "tls": make_tls()}
        return ob
    if ct == "11":  # AnyTLS
        ob = {"type": "anytls", "server": host, "server_port": port,
              "password": pw, "tls": make_tls()}
        return ob
    if ct == "3":  # Trojan（防御性支持）
        ob = {"type": "trojan", "server": host, "server_port": port,
              "password": pw, "tls": make_tls()}
        tr = make_tr()
        if tr:
            ob["transport"] = tr
        return ob
    return None


def v2rayn_profile_to_link(d):
    ob = v2rayn_profile_to_outbound(d)
    if not ob:
        return None
    return sb.outbound_to_link(ob)


# ============================================================ 节点解析
def parse_node_link(link):
    """返回 (地址, 端口, 备注)；无法解析返回 None"""
    link = (link or "").strip()
    if not link:
        return None
    proto = None
    for p in ("vmess://", "vless://", "trojan://", "ss://", "ssr://",
              "hysteria2://", "hy2://", "tuic://", "anytls://"):
        if link.startswith(p):
            proto, rest = p[:-3], link[len(p):]
            break
    if proto is None:
        return None

    remark = ""
    if "#" in rest:
        rest, remark = rest.split("#", 1)
        try:
            remark = urllib.parse.unquote(remark)
        except Exception:
            pass

    if proto == "vmess":
        try:
            raw = base64.b64decode(rest + "=" * (-len(rest) % 4)).decode("utf-8", "replace")
            d = json.loads(raw)
            return (d.get("add", ""), int(d.get("port") or 0), remark or d.get("ps", ""))
        except Exception:
            return None

    rest = rest.split("?", 1)[0]
    if "@" in rest:
        rest = rest.split("@", 1)[1]
    if "]:" in rest:
        host, port = rest.rsplit(":", 1)
        host = host.strip("[]")
    elif ":" in rest:
        host, port = rest.rsplit(":", 1)
    else:
        return None
    try:
        return (host, int(port), remark)
    except Exception:
        return None


def tcp_ping(host, port, timeout=3.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    t0 = time.time()
    try:
        s.connect((host, port))
        return (time.time() - t0) * 1000
    except Exception:
        return None
    finally:
        s.close()


def speed_test(sample_bytes=262144, timeout=8.0):
    """从 CF 取一段数据测下行速度，返回 KB/s；失败返回 None"""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection(("speed.cloudflare.com", 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname="speed.cloudflare.com") as ss:
                req = (f"GET /__down?bytes={sample_bytes} HTTP/1.1\r\n"
                       f"Host: speed.cloudflare.com\r\n"
                       f"User-Agent: node-tracker/{__version__}\r\n"
                       f"Connection: close\r\n\r\n").encode()
                ss.sendall(req)
                got, t0 = 0, time.time()
                while got < sample_bytes and (time.time() - t0) < timeout:
                    b = ss.recv(65536)
                    if not b:
                        break
                    got += len(b)
                dt = time.time() - t0
                return (got / 1024.0) / dt if dt > 0 else None
    except Exception:
        return None


# ============================================================ 历史存取
def load_history():
    if not os.path.exists(HISTORY_FILE):
        return []
    with open(HISTORY_FILE, "r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def append_history(records):
    new = not os.path.exists(HISTORY_FILE)
    with open(HISTORY_FILE, "a", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["ts", "round", "slot", "node",
                                          "proto", "host", "port",
                                  "delay_ms", "speed_kbs", "ok"])
        if new:
            w.writeheader()
        for r in records:
            w.writerow(r)


# 故障轮判定：整轮成功率低于该比例 → 认定是「内核没起来/端口冲突」，数据全部作废
BAD_ROUND_RATE = 0.05
# 故障轮判定所需的最小样本（小样本不做判定，避免误伤）
BAD_ROUND_MIN_N = 10
# 可用率只统计最近 N 次（老数据不代表现在的状态）
RECENT_N = 8


def drop_bad_rounds(rows, own_keys=None):
    """
    剔除「全灭轮」：整轮成功率极低说明测量本身挂了（内核起不来 / 端口冲突），
    不是节点不行。这类脏数据会把好节点的可用率从 100% 稀释到 40%，
    稳定性评估必须先把它清掉。

    v1.8 own_keys：判定探针优先用同轮自有节点。免费订阅源正常存活率就只有
    2~3%（实测 314 抽 7），用总量 5% 线会把正常轮当故障轮剔光 → 数据冻结。
    自有节点是可控的，它们不通用意昧着内核/代理真出问题。
    """
    by_ts = {}
    for r in rows:
        by_ts.setdefault(r.get("ts", ""), []).append(r)
    good, dropped = set(), []
    for ts, g in by_ts.items():
        if len(g) < BAD_ROUND_MIN_N:
            good.add(ts)
            continue
        probe = [r for r in g if own_keys
                 and any(k in str(r.get("host", "")) for k in own_keys)]
        pool = probe if probe else g
        ok = sum(1 for r in pool
                 if str(r.get("ok", "")).strip() in ("1", "true", "yes", "是"))
        threshold = 0.5 if probe else BAD_ROUND_RATE
        if ok / len(pool) < threshold:
            dropped.append((ts, len(g), ok))
        else:
            good.add(ts)
    kept = [r for r in rows if r.get("ts", "") in good]
    return kept, dropped


# ============================================================ 稳定性统计
_LAST_DROPPED = []      # 最近一次 analyze 剔除掉的故障轮（供 UI 提示）


def analyze(rows, delay_cap=2000.0, own_keys=None):
    """
    按节点聚合历史 → 指标 + 评分 + 分组

    评分口径（要「最快 + 最稳」，所以延迟与抖动占比高于速度）：
      可用率 35% + 中位数延迟 30% + 抖动 15% + 最差延迟 10% + 覆盖率 5% + 速度 5%
    · 延迟用**中位数**而非平均值：单次偶发抖动不会把好节点拖下水
    · 可用率只算**最近 RECENT_N 次**：老掉的数据不代表现在
    · 最差延迟惩罚：偶尔抽风的节点要扣分
    """
    global _LAST_DROPPED
    rows, _dropped = drop_bad_rounds(rows, own_keys=own_keys)
    _LAST_DROPPED = _dropped

    # v1.7 时间窗：剔除窗口外的陈年样本，防止"源已死但老样本 avail=100% 霸榜"
    _cutoff = datetime.datetime.now() - datetime.timedelta(days=HISTORY_WINDOW_DAYS)

    def _in_window(r):
        try:
            t = datetime.datetime.strptime(str(r.get("ts") or ""), "%Y-%m-%d %H:%M:%S")
        except Exception:
            return True   # 时间戳解析失败的保守保留，不当脏数据删
        return t >= _cutoff

    rows = [r for r in rows if _in_window(r)]

    g = {}
    for r in rows:
        # ⚠️ 聚合键必须带 host:port：公共订阅里大量「同名不同服务器」的节点，
        # 只按节点名聚合会把不同服务器的数据混成一条（延迟被平均、可用性失真、
        # 导出订阅时还会拿错链接）。显示名仍用节点备注。
        name = r.get("node") or f"{r.get('host')}:{r.get('port')}"
        # 名字是解析兜底出来的 "node"（很多免费源 ps 就叫这个）→ 用 host:port，可分辨
        if str(name).strip().lower() == "node":
            name = f"{r.get('host')}:{r.get('port')}"
        key = f"{name}@{r.get('host')}:{r.get('port')}"
        d = g.setdefault(key, {"node": name, "proto": r.get("proto", ""),
                               "host": r.get("host", ""), "port": r.get("port", ""),
                               "rounds": set(), "delays": [], "speeds": [],
                               "recent": [],        # 最近 N 次的成败（可用率按这个算）
                               "ok": 0, "n": 0, "slots": set()})
        d["n"] += 1
        if r.get("round"):
            d["rounds"].add(r["round"])
        if r.get("slot"):
            d["slots"].add(r["slot"])
        good = str(r.get("ok", "")).strip() in ("1", "true", "yes", "是")
        if good:
            d["ok"] += 1
        d["recent"].append(1 if good else 0)
        try:
            dl = float(r.get("delay_ms") or 0)
            if dl > 0:
                d["delays"].append(min(dl, delay_cap))
        except Exception:
            pass
        try:
            sp = float(r.get("speed_kbs") or 0)
            if sp > 0:
                d["speeds"].append(sp)
        except Exception:
            pass

    total_rounds = len({r.get("round") for r in rows if r.get("round")}) or 1
    out = []
    for key, d in g.items():
        n = d["n"] or 1
        # 可用率只看最近 RECENT_N 次：老掉的数据不代表现在的状态
        recent = d["recent"][-RECENT_N:]
        avail = sum(recent) / len(recent) * 100.0
        dl = d["delays"]
        med_d = statistics.median(dl) if dl else 0.0          # 中位数，抗单次异常
        worst_d = max(dl) if dl else 0.0                       # 最差延迟，抽风要扣分
        jit = statistics.pstdev(dl) if len(dl) > 1 else 0.0
        sp = d["speeds"]
        avg_s = sum(sp) / len(sp) if sp else 0.0
        appear = len(d["rounds"]) or 1
        coverage = appear / total_rounds * 100.0

        # 分组：核心组 = 覆盖率高 + 可用率高 + 抖动小
        if coverage >= 60.0 and avail >= 80.0 and jit < 50.0:
            group = "核心(稳)"
        # 门槛 800ms：免费/自建节点实测普遍 300~1800ms，原来 300ms 的门槛一个都进不来
        elif appear <= 2 and d["ok"] >= 2 and (med_d == 0 or med_d < 800):
            group = "新秀(动态)"
        elif d["n"] - d["ok"] >= 3:
            group = "淘汰"
        else:
            group = "观察"

        # ---- 综合评分：可用率35 + 中位延迟30 + 抖动15 + 最差延迟10 + 覆盖率5 + 速度5 ----
        s_avail = avail * 0.35
        if med_d > 0:
            s_delay = max(0.0, 100.0 - min(med_d, 1000.0) / 10.0) * 0.30
            s_worst = max(0.0, 100.0 - min(worst_d, 2000.0) / 20.0) * 0.10
        else:
            # ⚠️ 没测出延迟（失败节点）不能按 0ms 算成满分，否则「全失败」的节点
            #    反而白拿 40 分延迟分，排名压过真正能用的好节点
            s_delay = s_worst = 0.0
        s_jit = max(0.0, 100.0 - min(jit, 200.0) / 2.0) * 0.15
        s_cov = coverage * 0.05
        base = s_avail + s_delay + s_jit + s_worst + s_cov     # 满分 95
        if sp:
            s_speed = min(avg_s / 1024.0, 100.0) * 0.05
            score = min(100.0, base / 0.95 + s_speed)
        else:
            score = min(100.0, base / 0.95)                    # 未实测速度：归一化，不奖不罚
        score = round(score, 1)

        out.append({"key": key, "node": d["node"], "proto": d["proto"], "host": d["host"],
                    "port": d["port"], "samples": n, "rounds": appear,
                    "avail%": round(avail, 1),
                    "avg_delay_ms": round(med_d, 1),      # 展示的是中位数延迟
                    "worst_delay_ms": round(worst_d, 1),
                    "jitter_ms": round(jit, 1),
                    "avg_speed_kbs": round(avg_s, 1),
                    "slots": ",".join(sorted(d["slots"])) or "-",
                    "group": group, "score": score})
    out.sort(key=lambda x: -x["score"])
    return out


def summarize(agg):
    """分组统计"""
    s = {}
    for r in agg:
        s[r["group"]] = s.get(r["group"], 0) + 1
    return s


# ============================================================ 本地订阅 HTTP 服务
class SubHTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class SubHandler(http.server.BaseHTTPRequestHandler):
    """/sub = base64 订阅 · /links = 明文链接"""

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        app = getattr(self.server, "app", None)
        if app is None:
            self.send_error(503)
            return
        if path in ("/", "/sub", "/sub/", "/sub.txt", "/index.txt"):
            if app._served_links:
                body = app._served_b64.encode("utf-8")
            else:
                # 空组也要给合法 base64，客户端解码才不会报错
                body = base64.b64encode("# no nodes yet\n".encode()).decode().encode()
            ctype = "text/plain; charset=utf-8"
        elif path in ("/links", "/links.txt"):
            body = ("\n".join(app._served_links)).encode("utf-8")
            ctype = "text/plain; charset=utf-8"
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        # profile-update-interval: 单位秒，提示客户端 3 小时后自动更新
        self.send_header("profile-update-interval", "3")
        # 空值可能让部分客户端解析失败，给一个合法占位
        self.send_header("subscription-userinfo",
                         "upload=0; download=0; total=0; expire=0")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass  # 静默日志


# ============================================================ 图标路径
def _icon_path():
    """app_icon.ico 的实际位置（打包后从 _MEIPASS 取）"""
    try:
        base = (sys._MEIPASS if getattr(sys, "frozen", False)
                else os.path.dirname(os.path.abspath(__file__)))
        p = os.path.join(base, "app_icon.ico")
        return p if os.path.exists(p) else None
    except Exception:
        return None


# ============================================================ Windows 系统托盘
class TrayIcon:
    """
    最小化到 Windows 右下角托盘（纯 ctypes 调 Win32 API，不引入第三方依赖）。
    非 Windows 或创建失败时所有方法安全空转，调用方据此回退为「直接退出」。
    """
    NIM_ADD, NIM_MODIFY, NIM_DELETE = 0, 1, 2
    NIF_MESSAGE, NIF_ICON, NIF_TIP, NIF_INFO = 0x1, 0x2, 0x4, 0x10
    WM_USER = 0x0400
    WM_TRAY = WM_USER + 1
    WM_LBUTTONDBLCLK, WM_RBUTTONUP = 0x0203, 0x0205
    WM_COMMAND, WM_DESTROY = 0x0111, 0x0002
    ID_OPEN, ID_EXIT = 1001, 1002

    def __init__(self, app, icon_path=None, tip="节点稳定性追踪器"):
        self.app = app
        self.tip = tip
        self._visible = False
        self._hwnd = None
        self._nid = None
        self._wndproc_ref = None      # 必须长期持有，否则回调被 GC 后直接崩溃
        self._thread = None
        self._stop = False
        self.queue = __import__("queue").Queue()   # 托盘线程 -> UI：事件队列
        self._user32 = self._shell32 = None
        if ctypes is None or sys.platform != "win32":
            return
        try:
            self._init_win(icon_path)
        except Exception:
            self._hwnd = None

    # -------------------------------------------------- Win32 初始化
    def _init_win(self, icon_path):
        u32 = ctypes.windll.user32
        k32 = ctypes.windll.kernel32
        shell32 = ctypes.windll.shell32
        self._user32, self._shell32 = u32, shell32
        shell32.Shell_NotifyIconW.argtypes = [wintypes.DWORD, wintypes.LPVOID]
        shell32.Shell_NotifyIconW.restype = wintypes.BOOL

        u32.LoadImageW.restype = wintypes.HANDLE
        u32.CreateWindowExW.restype = wintypes.HWND
        u32.CreateWindowExW.argtypes = [wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR,
                                        wintypes.DWORD, ctypes.c_int, ctypes.c_int,
                                        ctypes.c_int, ctypes.c_int, wintypes.HWND,
                                        wintypes.HMENU, wintypes.HINSTANCE, wintypes.LPVOID]
        u32.RegisterClassExW.restype = wintypes.ATOM
        # ⚠️ 必须显式声明 64 位参数：否则 lParam 会被当成 32 位 int，
        # 溢出后抛 ArgumentError（回调异常会被静默吞掉，消息处理直接断掉）
        u32.DefWindowProcW.restype = ctypes.c_ssize_t
        u32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT,
                                       wintypes.WPARAM, wintypes.LPARAM]
        # 句柄类返回值在 64 位下必须声明 restype，否则被截断成 32 位 int
        u32.CreatePopupMenu.restype = wintypes.HMENU
        u32.SetForegroundWindow.argtypes = [wintypes.HWND]
        u32.SetForegroundWindow.restype = wintypes.BOOL
        u32.TrackPopupMenu.argtypes = [wintypes.HMENU, wintypes.UINT, ctypes.c_int,
                                       ctypes.c_int, ctypes.c_int, wintypes.HWND,
                                       ctypes.POINTER(wintypes.RECT)]
        u32.GetCursorPos.argtypes = [ctypes.POINTER(wintypes.POINT)]
        u32.DestroyMenu.argtypes = [wintypes.HMENU]
        u32.DestroyWindow.argtypes = [wintypes.HWND]
        u32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT,
                                     wintypes.WPARAM, wintypes.LPARAM]
        u32.AppendMenuW.argtypes = [wintypes.HMENU, wintypes.UINT,
                                    ctypes.c_ulonglong, wintypes.LPCWSTR]
        u32.GetMessageW.argtypes = [ctypes.POINTER(wintypes.MSG), wintypes.HWND,
                                    wintypes.UINT, wintypes.UINT]
        u32.TranslateMessage.argtypes = [ctypes.POINTER(wintypes.MSG)]
        u32.DispatchMessageW.argtypes = [ctypes.POINTER(wintypes.MSG)]

        WNDPROC = ctypes.WINFUNCTYPE(ctypes.c_ssize_t, wintypes.HWND, wintypes.UINT,
                                     wintypes.WPARAM, wintypes.LPARAM)

        class WNDCLASSEXW(ctypes.Structure):
            _fields_ = [("cbSize", wintypes.UINT), ("style", wintypes.UINT),
                        ("lpfnWndProc", WNDPROC), ("cbClsExtra", ctypes.c_int),
                        ("cbWndExtra", ctypes.c_int), ("hInstance", wintypes.HINSTANCE),
                        ("hIcon", wintypes.HICON), ("hCursor", wintypes.HANDLE),
                        ("hbrBackground", wintypes.HANDLE),
                        ("lpszMenuName", wintypes.LPCWSTR),
                        ("lpszClassName", wintypes.LPCWSTR), ("hIconSm", wintypes.HICON)]

        class NOTIFYICONDATAW(ctypes.Structure):
            _fields_ = [("cbSize", wintypes.DWORD), ("hWnd", wintypes.HWND),
                        ("uID", wintypes.UINT), ("uFlags", wintypes.UINT),
                        ("uCallbackMessage", wintypes.UINT), ("hIcon", wintypes.HICON),
                        ("szTip", wintypes.WCHAR * 128), ("dwState", wintypes.DWORD),
                        ("dwStateMask", wintypes.DWORD), ("szInfo", wintypes.WCHAR * 256),
                        ("uVersion", wintypes.UINT), ("szInfoTitle", wintypes.WCHAR * 64),
                        ("dwInfoFlags", wintypes.DWORD),
                        ("guidItem", ctypes.c_ubyte * 16), ("hBalloonIcon", wintypes.HICON)]

        self._NOTIFYICONDATAW = NOTIFYICONDATAW

        def wndproc(hwnd, msg, wparam, lparam):
            # ⚠️ 运行在托盘线程：绝不能碰 tkinter（非线程安全，跨线程调用会崩），
            #    只往队列里放事件，由 Tk 主线程轮询消费
            try:
                if msg == self.WM_TRAY:
                    if lparam == self.WM_LBUTTONDBLCLK:
                        self.queue.put("open")
                    elif lparam == self.WM_RBUTTONUP:
                        self._popup_menu(hwnd)
                elif msg == self.WM_COMMAND:
                    cmd = wparam & 0xFFFF
                    if cmd == self.ID_OPEN:
                        self.queue.put("open")
                    elif cmd == self.ID_EXIT:
                        self.queue.put("exit")
                elif msg == self.WM_DESTROY:
                    u32.PostQuitMessage(0)
                    return 0
            except Exception:
                pass
            return u32.DefWindowProcW(hwnd, msg, wparam, lparam)

        self._wndproc_ref = WNDPROC(wndproc)

        hinstance = k32.GetModuleHandleW(None)
        wc = WNDCLASSEXW()
        wc.cbSize = ctypes.sizeof(WNDCLASSEXW)
        wc.lpfnWndProc = self._wndproc_ref
        wc.hInstance = hinstance
        wc.lpszClassName = "NodeTrackerTrayCls"
        u32.RegisterClassExW(ctypes.byref(wc))     # 已注册时会失败，忽略

        hwnd = u32.CreateWindowExW(0, "NodeTrackerTrayCls", "NodeTrackerTray",
                                   0, 0, 0, 0, 0, None, None, hinstance, None)
        if not hwnd:
            return
        self._hwnd = hwnd

        hicon = None
        if icon_path and os.path.exists(icon_path):
            # IMAGE_ICON=1, LR_LOADFROMFILE=0x10, LR_DEFAULTSIZE=0x40
            hicon = u32.LoadImageW(None, icon_path, 1, 0, 0, 0x10 | 0x40)
        if not hicon:
            hicon = u32.LoadIconW(None, wintypes.LPCWSTR(32512))   # IDI_APPLICATION

        nid = NOTIFYICONDATAW()
        nid.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
        nid.hWnd = hwnd
        nid.uID = 1
        nid.uFlags = self.NIF_MESSAGE | self.NIF_ICON | self.NIF_TIP
        nid.uCallbackMessage = self.WM_TRAY
        nid.hIcon = hicon
        nid.szTip = self.tip[:127]
        self._nid = nid

        self._thread = threading.Thread(target=self._msg_loop, daemon=True)
        self._thread.start()

    # -------------------------------------------------- 消息循环
    def _msg_loop(self):
        """
        消息循环：刻意用 PeekMessage + 短睡，而不是长期阻塞的 GetMessage。
        这样 stop() 一置标志，线程 50ms 内就能退出并被 join 住 ——
        否则进程退出时它还堵在系统调用里，解释器销毁后才苏醒 → Fatal error 崩溃。
        """
        u = self._user32
        msg = wintypes.MSG()
        while not self._stop:
            try:
                if u.PeekMessageW(ctypes.byref(msg), None, 0, 0, 0x0001):  # PM_REMOVE
                    if msg.message == 0x0012:      # WM_QUIT
                        break
                    u.TranslateMessage(ctypes.byref(msg))
                    u.DispatchMessageW(ctypes.byref(msg))
                else:
                    time.sleep(0.05)
            except Exception:
                break

    # -------------------------------------------------- 右键菜单
    def _popup_menu(self, hwnd):
        u = self._user32
        h = u.CreatePopupMenu()
        u.AppendMenuW(h, 0, self.ID_OPEN, "打开主界面")
        u.AppendMenuW(h, 0, self.ID_EXIT, "退出程序")
        pt = wintypes.POINT()
        u.GetCursorPos(ctypes.byref(pt))
        u.SetForegroundWindow(hwnd)
        u.TrackPopupMenu(h, 0x0000 | 0x0002, pt.x, pt.y, 0, hwnd, None)
        u.PostMessageW(hwnd, 0, 0, 0)
        u.DestroyMenu(h)

    # -------------------------------------------------- 对外接口
    @property
    def available(self):
        return bool(self._hwnd and self._nid)

    def show(self, balloon=None):
        """显示托盘图标；balloon 为气泡提示文本"""
        if not self.available:
            return False
        try:
            nid = self._nid
            nid.uFlags = self.NIF_MESSAGE | self.NIF_ICON | self.NIF_TIP
            if balloon:
                nid.uFlags |= self.NIF_INFO
                nid.szInfo = balloon[:255]
                nid.szInfoTitle = self.tip[:63]
                nid.dwInfoFlags = 0x00000001          # NIIF_INFO
            if not self._visible:
                self._visible = bool(
                    self._shell32.Shell_NotifyIconW(self.NIM_ADD, ctypes.byref(nid)))
            else:
                self._shell32.Shell_NotifyIconW(self.NIM_MODIFY, ctypes.byref(nid))
        except Exception:
            self._visible = False
        return self._visible

    def hide(self):
        if self._visible and self._nid:
            try:
                self._shell32.Shell_NotifyIconW(self.NIM_DELETE, ctypes.byref(self._nid))
            except Exception:
                pass
            self._visible = False

    def stop(self):
        """
        彻底收摊：移除图标 + 销毁隐藏窗口 + 等消息线程退出。
        ⚠️ 必须等线程结束：否则进程退出时该线程还在 GetMessageW 里阻塞，
        解释器销毁后它才苏醒 → Fatal Python error: PyEval_RestoreThread（直接崩）。
        """
        self.hide()
        self._stop = True
        if self._hwnd and self._user32:
            try:
                self._user32.DestroyWindow(self._hwnd)   # → WM_DESTROY → PostQuitMessage
            except Exception:
                pass
            self._hwnd = None
        th = self._thread
        if th is not None and th.is_alive():
            try:
                th.join(timeout=3)
            except Exception:
                pass


# ============================================================ GUI
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"节点稳定性追踪器  v{__version__}")
        # 窗口/任务栏专属图标（打包时 ico 打进 _MEIPASS）
        try:
            _ico = _icon_path()
            if _ico:
                self.iconbitmap(_ico)
        except Exception:
            pass
        self.geometry("1200x820")
        self.minsize(1080, 720)
        self._running = False
        self._busy = False          # 本轮测速进行中（防重入）
        self._sort_desc = {}        # 各列排序方向
        self._timer = None
        self._round = 0
        self._fallback_n = 0        # 本轮订阅里兜底补进来的节点数
        # 轮次从历史续接：否则每次重启软件 round 都归 1，
        # 多轮数据被算成「同一轮」，覆盖率/可用率统计会失真
        try:
            self._round = max((int(r.get("round") or 0) for r in load_history()),
                              default=0)
        except Exception:
            pass
        # 测速取消事件（测速进行中点「取消本轮」置位）
        self._cancel_event = threading.Event()
        # 订阅服务状态
        self._server = None          # ThreadingHTTPServer 实例
        self._server_thread = None
        self._served_b64 = ""        # 订阅服务当前提供的内容
        self._served_links = []
        # 测速参数（控件在 ② 号页，变量先建好避免跨页引用出错）
        self.conc = tk.StringVar(value="20")
        self.timeout = tk.StringVar(value="5")
        self._style()
        self._ui()
        self._load_config()
        self._update_served()
        # 常驻模式：自动开订阅服务 / 自动开始定时测速
        if getattr(self, "auto_sub", None) and self.auto_sub.get():
            self.after(500, lambda: self._start_server(silent=True))
        if getattr(self, "auto_timer", None) and self.auto_timer.get():
            # 醒目说明"为什么一打开就在测速"，免得用户以为点错了
            self.status.set("⏱ 常驻模式：启动时自动开始定时测速"
                            "（不想要的话，在②号页取消勾选即可）")
            self.after(1500, self._toggle_timer)
        # 系统托盘（点 X 最小化到右下角，不退出）
        self._tray = None
        self._tray_tipped = False
        self._tray_polling = False
        # 关窗（X）→ 最小化到托盘；真正退出走托盘菜单「退出程序」
        self.protocol("WM_DELETE_WINDOW", self._minimize_to_tray)

    # ------------------------------------------------------ 托盘 / 退出
    def _get_tray(self):
        if self._tray is None:
            self._tray = TrayIcon(self, _icon_path(), f"节点稳定性追踪器 v{__version__}")
        return self._tray

    def _minimize_to_tray(self):
        """点右上角 X：最小化到系统托盘（托盘不可用时退回直接退出）"""
        self._save_config()
        tray = self._get_tray()
        if not tray.available:
            self._on_close()
            return
        tip = None if self._tray_tipped else "已最小化到右下角托盘，双击图标可重新打开"
        if tray.show(tip):
            self._tray_tipped = True
            if not self._tray_polling:     # 避免反复最小化叠加出多条轮询链
                self._tray_polling = True
                self._poll_tray()          # Tk 主线程消费托盘事件（绝不在托盘线程里碰 tkinter）
            self.withdraw()
        else:
            self._on_close()

    def _poll_tray(self):
        """主线程每 200ms 消费一次托盘事件队列"""
        try:
            tray = self._tray
            if tray is not None:
                while True:
                    try:
                        ev = tray.queue.get_nowait()
                    except Exception:
                        break
                    if ev == "open":
                        self._restore_from_tray()
                    elif ev == "exit":
                        self._quit_from_tray()
                        return
        except Exception:
            pass
        if getattr(self, "_tray_polling", False):
            self.after(200, self._poll_tray)

    def _restore_from_tray(self):
        """双击托盘图标 / 菜单「打开主界面」"""
        self._tray_polling = False     # 回到前台就停止轮询
        try:
            self.deiconify()
            self.lift()
            self.focus_force()
        except Exception:
            pass
        if self._tray:
            self._tray.hide()

    def _quit_from_tray(self):
        """托盘菜单「退出程序」→ 真正退出"""
        self._on_close()

    def _on_close(self):
        self._save_config()
        if self._running:
            self._running = False
        if self._timer:
            try:
                self.after_cancel(self._timer)
            except Exception:
                pass
        self._stop_server()
        if self._tray:
            self._tray.stop()
        self.destroy()

    # ------------------------------------------------------ 样式
    def _style(self):
        st = ttk.Style()
        try:
            st.theme_use("clam")
        except Exception:
            pass
        st.configure("Big.TNotebook.Tab", font=("Microsoft YaHei", 12, "bold"),
                     padding=[18, 8])
        st.configure("Big.Treeview.Heading", font=("Microsoft YaHei", 11, "bold"),
                     background="#4a7ab8", foreground="white")
        st.configure("Big.Treeview", font=("Microsoft YaHei", 10), rowheight=26)
        st.configure("Big.TButton", font=("Microsoft YaHei", 10), padding=[14, 6])
        st.configure("Big.TLabel", font=("Microsoft YaHei", 10))
        st.configure("Big.TCheckbutton", font=("Microsoft YaHei", 10))
        self.option_add("*Font", ("Microsoft YaHei", 10))

    # ------------------------------------------------------ 界面
    def _ui(self):
        nb = ttk.Notebook(self, style="Big.TNotebook")
        nb.pack(fill="both", expand=True, padx=10, pady=8)

        f1 = ttk.Frame(nb, padding=12); nb.add(f1, text="① 节点来源")
        self._src_tab(f1)

        f2 = ttk.Frame(nb, padding=12); nb.add(f2, text="② 定时测速")
        self._timer_tab(f2)

        f3 = ttk.Frame(nb, padding=12); nb.add(f3, text="③ 历史数据")
        self._hist_tab(f3)

        f4 = ttk.Frame(nb, padding=12); nb.add(f4, text="④ 订阅服务")
        self._sub_tab(f4)

    # ------------------------------------------------------ ① 来源
    def _src_tab(self, f):
        # v1.8 拉源代理：本机 sing-box/v2rayN 的 SOCKS5/HTTP 代理。
        # GitHub raw 直连必被 GFW 阻断（000），gh 镜像前缀直连同样被墙 →
        # 只有经本机代理拉源才通。留空=直连（会全灭）。
        bar0 = ttk.Frame(f)
        bar0.pack(fill="x", pady=(0, 6))
        ttk.Label(bar0, text="拉源代理:", style="Big.TLabel").pack(side="left")
        self.src_proxy = ttk.Combobox(bar0, values=SRC_PROXY_CANDIDATES, width=26)
        self.src_proxy.set("socks5h://127.0.0.1:10809")
        self.src_proxy.pack(side="left", padx=6)
        ttk.Label(bar0, text="(订阅源经此代理拉取；v2rayN/sing-box 本地端口，留空=直连)",
                  style="Big.TLabel", foreground="#666666").pack(side="left")

        # Github 加速前缀（借鉴 SubsCheck 的 Github Proxy）
        bar = ttk.Frame(f)
        bar.pack(fill="x", pady=(0, 6))
        ttk.Label(bar, text="GitHub 加速前缀:", style="Big.TLabel").pack(side="left")
        self.gh_proxy = ttk.Combobox(bar, values=GH_PROXIES, width=26)
        self.gh_proxy.set("")
        self.gh_proxy.pack(side="left", padx=6)
        ttk.Label(bar, text="(raw.githubusercontent 直连超时时选一个；留空=直连)",
                  style="Big.TLabel", foreground="#666666").pack(side="left")

        ttk.Button(bar, text="🆓 一键填充免费节点源",
                   style="Big.TButton",
                   command=self._fill_free_sources).pack(side="right", padx=4)

        ttk.Button(bar, text="📥 一键导入 v2rayN",
                   style="Big.TButton",
                   command=self._import_v2rayn).pack(side="right", padx=4)
        ttk.Button(bar, text="📂 指定内核",
                   style="Big.TButton",
                   command=self._pick_kernel).pack(side="right", padx=4)
        ttk.Button(bar, text="📦 一键下载内核",
                   style="Big.TButton",
                   command=self._download_kernel).pack(side="right", padx=4)

        # v1.9.3：内核状态指示（导入/下载/指定后实时更新）
        self.lbl_kernel = ttk.Label(f, text="内核: 检测中…",
                                    style="Big.TLabel")
        self.lbl_kernel.pack(fill="x", pady=(0, 6))

        # 订阅框标题行（右侧带一键清空）
        hdr1 = ttk.Frame(f)
        hdr1.pack(fill="x")
        ttk.Label(hdr1, text="订阅链接（每行一个，可留空）：",
                  style="Big.TLabel").pack(side="left")
        ttk.Button(hdr1, text="🗑 清空订阅", style="Big.TButton",
                   command=self._clear_subs).pack(side="right")

        self.txt_subs = scrolledtext.ScrolledText(f, height=5,
                                                   font=("Consolas", 10))
        self.txt_subs.pack(fill="x", pady=(2, 10))
        self.txt_subs.insert("1.0", "# 每行一条订阅 URL，例如:\n"
                                     "# https://example.com/sub?token=xxx\n")

        # 手动节点框标题行（右侧带一键清空）
        hdr2 = ttk.Frame(f)
        hdr2.pack(fill="x")
        ttk.Label(hdr2, text="手动节点（每行一个 vmess:// / vless:// / trojan:// / ss:// 链接）：",
                  style="Big.TLabel").pack(side="left")
        ttk.Button(hdr2, text="🗑 清空节点", style="Big.TButton",
                   command=self._clear_nodes).pack(side="right")

        self.txt_nodes = scrolledtext.ScrolledText(f, height=10,
                                                    font=("Consolas", 10))
        self.txt_nodes.pack(fill="both", expand=True, pady=(2, 6))
        self.txt_nodes.insert("1.0", "# 在这里粘贴你的散装节点，每行一个，例如:\n"
                                      "# vmess://eyJ2IjoiMiIsInBzIjoi...\n"
                                      "# trojan://password@host:443#备注\n")

        ttk.Label(f, text="💡 以 # 开头的行会被忽略。订阅链接与手动节点会合并进同一个测速池。",
                  style="Big.TLabel", foreground="#666666").pack(anchor="w")

        # v1.9.3：构建完界面后刷新内核状态（此时 config 已加载）
        self._refresh_kernel_status()

    # ------------------------------------------------------ 一键清空
    @staticmethod
    def _count_real(text):
        """统计文本里真正的条目数（忽略 # 注释与空行）"""
        return len([l for l in (text or "").splitlines()
                    if l.strip() and not l.strip().startswith("#")])

    def _clear_subs(self):
        n = self._count_real(self.txt_subs.get("1.0", "end"))
        if not n:
            self.status_msg("订阅框已经是空的。")
            return
        if not messagebox.askyesno("清空订阅",
                                   f"将清空订阅框里的 {n} 条订阅链接（手动节点不受影响）。\n\n继续？"):
            return
        self.txt_subs.delete("1.0", "end")
        self._save_config()
        self.status_msg(f"已清空 {n} 条订阅链接。")

    def _clear_nodes(self):
        n = self._count_real(self.txt_nodes.get("1.0", "end"))
        if not n:
            self.status_msg("手动节点框已经是空的。")
            return
        if not messagebox.askyesno("清空节点",
                                   f"将清空手动节点框里的 {n} 个节点（订阅链接不受影响）。\n\n继续？"):
            return
        self.txt_nodes.delete("1.0", "end")
        self._save_config()
        self.status_msg(f"已清空 {n} 个手动节点。")

    def _fill_free_sources(self):
        """一键填充内置免费节点源（借鉴 SubsCheck）"""
        if not messagebox.askyesno(
                "一键填充",
                f"将把 {len(FREE_SOURCES)} 条 GitHub 免费节点源填入订阅框（覆盖现有内容）。\n\n"
                "这些源会聚合出上千个公共节点，配合定时测速+交集统计，\n"
                "自动筛出真正可用的少数好节点。\n\n继续？"):
            return
        self.txt_subs.delete("1.0", "end")
        self.txt_subs.insert("1.0", "\n".join(FREE_SOURCES) + "\n")
        self.status_msg(f"已填充 {len(FREE_SOURCES)} 条免费节点源。"
                        "建议先测一轮看通量，节点太多时可删减部分源。")

    # ------------------------------------------------------ v1.9.3 内核获取
    def _refresh_kernel_status(self):
        """在来源页显示 sing-box 内核是否就绪"""
        try:
            k = get_kernel()
            if k and os.path.exists(k):
                self.lbl_kernel.config(
                    text=f"内核: ✅ 就绪  →  {k}", foreground="#1a7f37")
            else:
                self.lbl_kernel.config(
                    text="内核: ⚠️ 未找到 — 点「📥 一键导入 v2rayN」或「📦 一键下载内核」",
                    foreground="#b35900")
        except Exception:
            self.lbl_kernel.config(text="内核: 状态未知", foreground="#666666")

    def _pick_kernel(self):
        """手动指定 sing-box 内核文件（用户已有 v2rayN 但目录布局特殊时）"""
        picked = filedialog.askopenfilename(
            title="选择 sing-box 可执行文件",
            filetypes=[("sing-box", "sing-box.exe"), ("所有文件", "*.*")])
        if not picked:
            return
        if not os.path.basename(picked).lower().startswith("sing-box"):
            messagebox.showwarning("文件不对",
                "请选择 sing-box 的可执行文件（sing-box.exe）。")
            return
        _persist_singbox_kernel(picked)
        self._refresh_kernel_status()
        messagebox.showinfo("内核已指定", f"已锁定内核路径：\n{picked}")

    def _download_kernel(self):
        """一键下载 sing-box 内核（本机未装 v2rayN 时的兜底；经 GitHub 加速镜像）"""
        import zipfile, urllib.request, threading
        gp = (getattr(self, "gh_proxy", None)
              and self.gh_proxy.get() or "").strip().rstrip("/")
        mirrors = ([gp] if gp else []) + list(DOWNLOAD_MIRRORS)
        versions = [SINGBOX_DOWNLOAD_VERSION,
                    "1.11.12", "1.11.11", "1.11.10", "1.11.9", "1.11.8",
                    "1.11.7", "1.11.6", "1.11.5", "1.11.4", "1.11.3",
                    "1.11.2", "1.11.1", "1.11.0", "1.10.0", "1.9.3"]

        def _work():
            dest = os.path.join(BASE_DIR, "kernel")
            os.makedirs(dest, exist_ok=True)
            last_err = ""
            for ver in versions:
                asset = f"sing-box-{ver}-windows-amd64.zip"
                base = (f"https://github.com/SagerNet/sing-box/releases/"
                        f"download/v{ver}/{asset}")
                for m in mirrors:
                    url = (m + "/" + base) if m else base
                    zp = os.path.join(dest, asset)
                    try:
                        self.after(
                            0, lambda t=f"正在下载内核 {ver} …":
                            self.lbl_kernel.config(text=t, foreground="#1a7f37"))
                        req = urllib.request.Request(
                            url, headers={"User-Agent": "NodeTracker"})
                        with urllib.request.urlopen(req, timeout=20) as r, \
                                open(zp, "wb") as fo:
                            fo.write(r.read())
                        if os.path.getsize(zp) <= 100000:
                            continue
                        # 解压并定位 sing-box.exe
                        with zipfile.ZipFile(zp) as z:
                            z.extractall(dest)
                        exe = None
                        for _rt, _, _fs in os.walk(dest):
                            if "sing-box.exe" in _fs:
                                exe = os.path.join(_rt, "sing-box.exe")
                                break
                        if not exe:
                            continue
                        _persist_singbox_kernel(exe)
                        self.after(0, self._refresh_kernel_status)
                        self.after(0, lambda e=exe: messagebox.showinfo(
                            "内核就绪",
                            f"sing-box 内核已下载并配置：\n{e}\n\n"
                            "现在可以点「立即测一轮」了。"))
                        return
                    except Exception as e:
                        last_err = str(e)
            self.after(0, lambda: messagebox.showerror(
                "下载失败",
                f"无法下载 sing-box 内核（已尝试多个版本与镜像）。\n最后错误：{last_err}\n\n"
                "可手动从 https://github.com/SagerNet/sing-box/releases 下载 "
                "windows-amd64 版，解压后点「📂 指定内核」选择 sing-box.exe。"))

        self._dl_cancelled = False
        threading.Thread(target=_work, daemon=True).start()

    # ------------------------------------------------------ v2rayN 一键导入
    def _import_v2rayn(self):
        """一键导入本机 v2rayN：有订阅链接的组→订阅栏；无链接组的散装节点→散装栏"""
        db = _find_v2rayn_db()
        if not db:
            # 找不到 → 让用户手动选 guiNDB.db（选一次就记住，跨机器/怪路径都覆盖）
            messagebox.showinfo("未自动找到 v2rayN",
                "自动扫描（全盘符 + 常见目录）未发现 v2rayN 节点数据库 guiNDB.db。\n\n"
                "接下来会弹出文件选择框，请到你的 v2rayN 安装目录选中 guiNDB.db\n"
                "（通常在 v2rayN 目录下的 guiConfigs 文件夹里）。\n\n"
                "选中一次后会记住路径，以后一键导入不再询问。\n\n"
                "若本机确实未安装 v2rayN，可取消此处，改点「📦 一键下载内核」自动获取 sing-box。")
            picked = filedialog.askopenfilename(
                title="选择 v2rayN 的 guiNDB.db",
                filetypes=[("v2rayN 数据库", "guiNDB.db"), ("所有文件", "*.*")])
            if not picked:
                self.status_msg("已取消 v2rayN 导入。")
                return
            db = picked
            # 记住手动路径
            try:
                cfg = {}
                if os.path.exists(CONFIG_FILE):
                    cfg = json.load(open(CONFIG_FILE, encoding="utf-8"))
                cfg["v2rayn_db"] = db
                json.dump(cfg, open(CONFIG_FILE, "w", encoding="utf-8"),
                          ensure_ascii=False, indent=1)
            except Exception:
                pass
        try:
            # v1.9.3：导入 v2rayN 时顺带定位其自带 sing-box 内核（免去单独配置）
            _v2n_root = _v2rayn_root_from_db(db)
            _k = _find_singbox_in_v2rayn(_v2n_root)
            if _k:
                _persist_singbox_kernel(_k)
                _kernel_note = (f"\n\n✅ 已自动定位 v2rayN 自带的 sing-box 内核：\n{_k}")
            else:
                _kernel_note = ("\n\n⚠️ 未在 v2rayN 目录找到 sing-box 内核，"
                               "可点「📦 一键下载内核」自动获取。")
            import sqlite3
            con = sqlite3.connect(db)
            con.row_factory = sqlite3.Row
            cur = con.cursor()
            cur.execute("SELECT id, remarks, url, enabled FROM SubItem")
            subs = cur.fetchall()
            cur.execute("SELECT * FROM ProfileItem WHERE configType<>'2' "
                        "AND address NOT LIKE '%configMultipleLoad%'")
            profiles = cur.fetchall()
            con.close()
        except Exception as e:
            messagebox.showerror("读取失败", f"读取 v2rayN 数据库出错:\n{e}")
            return

        # 1) 有订阅链接的组 → 订阅栏
        sub_urls = [(s["url"] or "").strip() for s in subs]
        sub_urls = [u for u in sub_urls if u]

        # 2) 无链接组的 subid 集合
        nolink_subids = {str(s["id"]) for s in subs if not (s["url"] or "").strip()}

        # 3) 散装节点 = 属于「无链接组」的节点 + 未分组(空 subid)的节点
        loose_links = []
        skipped = 0
        for p in profiles:
            subid = str(p["subid"] or "")
            is_loose = (subid in nolink_subids) or (subid == "")
            if not is_loose:
                continue
            link = v2rayn_profile_to_link(dict(p))
            if link:
                loose_links.append(link)
            else:
                skipped += 1
        # 同一节点可能出现在多个空链接组里，批内先去重一次
        _seen = set()
        dedup_loose = []
        for l in loose_links:
            if l in _seen:
                continue
            _seen.add(l)
            dedup_loose.append(l)
        loose_links = dedup_loose

        # 合并去重（不覆盖已有内容）
        existing_subs = {l.strip() for l in self.txt_subs.get("1.0", "end").splitlines()
                         if l.strip() and not l.strip().startswith("#")}
        existing_nodes = {l.strip() for l in self.txt_nodes.get("1.0", "end").splitlines()
                          if l.strip() and not l.strip().startswith("#")}

        new_subs = [u for u in sub_urls if u not in existing_subs]
        new_nodes, seen = [], set()
        for l in loose_links:
            if l in existing_nodes or l in seen:
                continue
            seen.add(l)
            new_nodes.append(l)

        if new_subs:
            cur_s = self.txt_subs.get("1.0", "end").strip()
            self.txt_subs.insert("end", ("\n" if cur_s else "")
                                 + "\n".join(new_subs) + "\n")
        if new_nodes:
            cur_n = self.txt_nodes.get("1.0", "end").strip()
            self.txt_nodes.insert("end", ("\n" if cur_n else "")
                                 + "\n".join(new_nodes) + "\n")

        self._save_config()
        msg = (f"已从本机 v2rayN 导入：\n\n"
               f"· 订阅链接（有链接的订阅组）：新增 {len(new_subs)} 条（检测到 {len(sub_urls)} 条）\n"
               f"· 散装节点（无链接组的节点 + 未分组节点）：新增 {len(new_nodes)} 个"
               + (f"（跳过 {skipped} 个无法识别的节点）" if skipped else "")
               + f"\n\n订阅栏现有 {len(existing_subs) + len(new_subs)} 条，"
                 f"散装栏现有 {len(existing_nodes) + len(new_nodes)} 个。\n\n"
               f"点「立即测一轮」即可把这些节点一起测速（已含你的 HK/JP 自建节点）。")
        messagebox.showinfo("导入完成", msg + _kernel_note)
        self.status_msg(f"v2rayN 导入完成：订阅 +{len(new_subs)}，散装节点 +{len(new_nodes)}")

    # ------------------------------------------------------ ② 定时测速
    def _timer_tab(self, f):
        bar = ttk.Frame(f)
        bar.pack(fill="x", pady=(0, 10))

        ttk.Label(bar, text="自动测速间隔（小时）：", style="Big.TLabel").pack(side="left")
        self.interval = tk.StringVar(value="3")
        ttk.Spinbox(bar, from_=1, to=24, width=5,
            textvariable=self.interval).pack(side="left", padx=6)

        ttk.Label(bar, text="并发数:", style="Big.TLabel").pack(side="left", padx=(16, 2))
        # 上限 64：与内核模块 min(concurrency, 64) 对齐，避免界面能选 200 实际被截断的误导
        ttk.Spinbox(bar, from_=1, to=64, width=5,
                    textvariable=self.conc).pack(side="left")

        ttk.Label(bar, text="超时(秒):", style="Big.TLabel").pack(side="left", padx=(16, 2))
        ttk.Spinbox(bar, from_=1, to=30, width=5,
                    textvariable=self.timeout).pack(side="left")

        self.btn_toggle = ttk.Button(bar, text="▶ 启动定时测速",
                                 style="Big.TButton",
                                 command=self._toggle_timer)
        self.btn_toggle.pack(side="left", padx=10)

        self.btn_once = ttk.Button(bar, text="▶ 立即测一轮",
                                   style="Big.TButton",
                                   command=lambda: self._run_round(manual=True))
        self.btn_once.pack(side="left", padx=4)

        self.btn_cancel = ttk.Button(bar, text="⏹ 取消本轮",
                                     style="Big.TButton",
                                     command=self._cancel_round,
                                     state="disabled")
        self.btn_cancel.pack(side="left", padx=4)

        ttk.Button(bar, text="💾 导出最终订阅",
                   style="Big.TButton",
                   command=self._export_sub).pack(side="left", padx=4)

        # 常驻选项（借鉴 SubsCheck 开机自启思路）
        bar2 = ttk.Frame(f)
        bar2.pack(fill="x", pady=(0, 8))
        self.auto_timer = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar2, text="启动时自动开始定时测速（常驻模式）",
                        variable=self.auto_timer,
                        style="Big.TCheckbutton").pack(side="left")

        # ---- 分池策略：自建节点精测 + 免费节点抽样（1 万节点会把内核拖死）----
        bar3 = ttk.Frame(f)
        bar3.pack(fill="x", pady=(0, 8))
        ttk.Label(bar3, text="自建节点关键词(逗号分隔，命中者每轮精测3次):",
                  style="Big.TLabel").pack(side="left")
        self.own_keys = ttk.Entry(bar3, width=42, font=("Consolas", 10))
        self.own_keys.pack(side="left", padx=6)

        ttk.Label(bar3, text="免费节点每轮抽样:", style="Big.TLabel").pack(side="left",
                                                                padx=(14, 2))
        self.sample_n = tk.StringVar(value="300")
        ttk.Spinbox(bar3, from_=0, to=5000, width=6,
                    textvariable=self.sample_n).pack(side="left")
        ttk.Label(bar3, text="(0=全测。上万节点建议抽样，否则内核起不来→整轮失败)",
                  style="Big.TLabel", foreground="#666666").pack(side="left")

        self.status = tk.StringVar(value="就绪。填入节点后点「立即测一轮」或「启动定时测速」。")
        ttk.Label(f, textvariable=self.status, style="Big.TLabel",
                 foreground="#1c5fb0").pack(anchor="w", pady=(0, 8))

        # 测速进度条 + 进度详情（新增：状态显示）
        self.pb = ttk.Progressbar(f, mode="determinate", maximum=100, value=0)
        self.pb.pack(fill="x", pady=(0, 2))
        self.lbl_progress = tk.StringVar(value="")
        ttk.Label(f, textvariable=self.lbl_progress, style="Big.TLabel",
                  foreground="#666666").pack(anchor="w", pady=(0, 6))

        # ---- 复制选中节点链接（粘贴到 v2rayN 单独测试）----
        bar_copy = ttk.Frame(f)
        bar_copy.pack(fill="x", pady=(0, 4))
        ttk.Button(bar_copy, text="📋 复制选中节点链接", style="Big.TButton",
                   command=self._copy_node_link).pack(side="left", padx=4)
        ttk.Label(bar_copy, text="选中一行后点此 / 右键菜单 / Ctrl+C，链接可直接粘贴到 v2rayN 单独测试",
                  style="Big.TLabel", foreground="#666666").pack(side="left", padx=6)

        cols = ("node", "proto", "host", "port", "delay_ms", "speed_kbs", "ok", "slots", "group", "score")
        heads = {"node": "节点", "proto": "协议", "host": "地址", "port": "端口",
                 "delay_ms": "延迟ms", "speed_kbs": "速度KB/s", "ok": "可用",
                 "slots": "覆盖时段", "group": "分组", "score": "评分"}
        tf = ttk.Frame(f)
        tf.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(tf, columns=cols, show="headings",
                                 style="Big.Treeview")
        vsb = ttk.Scrollbar(tf, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        for c in cols:
            self.tree.heading(c, text=heads[c],
                              command=lambda _c=c: self._sort_tree(_c))
            self.tree.column(c, width=118, anchor="center")
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        # 右键菜单 + Ctrl+C 复制节点链接
        self.tree_menu = tk.Menu(self.tree, tearoff=0)
        self.tree_menu.add_command(label="📋 复制节点链接", command=self._copy_node_link)
        self.tree.bind("<Button-3>", self._popup_tree_menu)
        self.tree.bind("<Control-c>", lambda e: (self._copy_node_link(), "break"))

        ttk.Label(f, text="点列标题排序 · 核心组=多轮都在且表现好 · 新秀组=新出现但连续优秀",
                  style="Big.TLabel", foreground="#666666").pack(anchor="w", pady=6)

        # 节点来源统计
        self.lbl_stats = tk.StringVar(value="")
        ttk.Label(f, textvariable=self.lbl_stats, style="Big.TLabel").pack(anchor="w")

    # ------------------------------------------------------ ③ 历史
    def _hist_tab(self, f):
        bar = ttk.Frame(f)
        bar.pack(fill="x", pady=(0, 8))
        ttk.Button(bar, text="刷新", style="Big.TButton",
                 command=self._refresh_hist).pack(side="left", padx=4)
        ttk.Button(bar, text="清空历史", style="Big.TButton",
                 command=self._clear_hist).pack(side="left", padx=4)
        self.lbl_hist = tk.StringVar(value="")
        ttk.Label(bar, textvariable=self.lbl_hist, style="Big.TLabel").pack(side="left", padx=12)

        cols = ("ts", "slot", "node", "delay_ms", "speed_kbs", "ok")
        heads = {"ts": "测速时间", "slot": "时段",
                 "node": "节点(地址:端口)", "delay_ms": "延迟(ms)",
                 "speed_kbs": "速度(KB/s)", "ok": "可用"}
        widths = {"ts": 158, "slot": 64, "node": 240, "delay_ms": 96,
                  "speed_kbs": 110, "ok": 70}
        tf = ttk.Frame(f)
        tf.pack(fill="both", expand=True)
        self.tree_h = ttk.Treeview(tf, columns=cols, show="headings",
                                   style="Big.Treeview")
        vsb = ttk.Scrollbar(tf, orient="vertical", command=self.tree_h.yview)
        self.tree_h.configure(yscrollcommand=vsb.set)
        for c in cols:
            self.tree_h.heading(c, text=heads[c])
            self.tree_h.column(c, width=widths[c], anchor="center")
        self.tree_h.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        self._refresh_hist()

    def _refresh_hist(self):
        for i in self.tree_h.get_children():
            self.tree_h.delete(i)
        rows = load_history()
        for r in rows[-500:]:
            ok_raw = str(r.get("ok", "")).strip()
            ok_disp = "是" if ok_raw in ("1", "true", "yes", "是") else "否"
            self.tree_h.insert("", "end", values=(
                r.get("ts", ""), r.get("slot", ""), r.get("node", ""),
                r.get("delay_ms", ""), r.get("speed_kbs", ""),
                ok_disp))
        self.lbl_hist.set(f"共 {len(rows)} 条历史记录（显示最近 500 条；可用列=是/否）")

    def _clear_hist(self):
        if not messagebox.askyesno("确认", "确定清空所有历史测速记录？"):
            return
        if os.path.exists(HISTORY_FILE):
            os.remove(HISTORY_FILE)
        self._refresh_hist()

    # ------------------------------------------------------ ④ 订阅服务
    def _sub_tab(self, f):
        ttk.Label(f, text="把最终订阅（核心 ∪ 新秀）作为本地 HTTP 服务常驻提供。\n"
                          "v2rayN / Clash / 手机 App 直接订阅这个 URL，每轮测速后节点自动更新，"
                          "无需反复导入文件。",
                  style="Big.TLabel").pack(anchor="w", pady=(0, 10))

        bar1 = ttk.Frame(f)
        bar1.pack(fill="x", pady=(0, 8))
        ttk.Label(bar1, text="服务端口:", style="Big.TLabel").pack(side="left")
        self.sub_port = tk.StringVar(value="18099")
        ttk.Spinbox(bar1, from_=1024, to=65535, width=7,
                    textvariable=self.sub_port).pack(side="left", padx=6)

        self.btn_srv = ttk.Button(bar1, text="▶ 开启订阅服务",
                                  style="Big.TButton",
                                  command=self._toggle_server)
        self.btn_srv.pack(side="left", padx=10)

        ttk.Button(bar1, text="📋 复制订阅链接",
                   style="Big.TButton",
                   command=self._copy_sub_url).pack(side="left", padx=4)

        bar2 = ttk.Frame(f)
        bar2.pack(fill="x", pady=(0, 8))
        ttk.Label(bar2, text="订阅精选节点数:", style="Big.TLabel").pack(side="left")
        self.top_n = tk.StringVar(value=str(DEFAULT_PICK_N))
        ttk.Spinbox(bar2, from_=0, to=999, width=6,
                    textvariable=self.top_n).pack(side="left", padx=(4, 12))
        ttk.Label(bar2, text="(0=不限，按综合评分取最前的 N 个；默认 5 = 只给你最优的几个)",
                  style="Big.TLabel",
                  foreground="#666666").pack(side="left")

        ttk.Label(bar2, text="测速下限 KB/s:", style="Big.TLabel").pack(side="left", padx=(12, 0))
        self.min_speed = tk.StringVar(value="0")
        ttk.Spinbox(bar2, from_=0, to=10000, width=6,
                    textvariable=self.min_speed).pack(side="left", padx=(4, 12))
        ttk.Label(bar2, text="(0=不过滤，低于此速度的节点不进订阅)", style="Big.TLabel",
                  foreground="#666666").pack(side="left")

        bar3 = ttk.Frame(f)
        bar3.pack(fill="x", pady=(0, 8))
        self.auto_sub = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar3, text="启动时自动开启订阅服务（常驻模式）",
                        variable=self.auto_sub,
                        style="Big.TCheckbutton").pack(side="left")
        self.exclude_vmess = tk.BooleanVar(value=True)
        ttk.Checkbutton(bar3, text="订阅排除 vmess（GFW 易识别）",
                        variable=self.exclude_vmess,
                        style="Big.TCheckbutton").pack(side="left", padx=(16, 0))

        self.lbl_srv = tk.StringVar(value="订阅服务未开启。")
        ttk.Label(f, textvariable=self.lbl_srv, style="Big.TLabel",
                  foreground="#1c5fb0").pack(anchor="w", pady=(4, 12))

        ttk.Label(f, text="订阅端点:\n"
                          "  /sub     base64 订阅（v2rayN / Clash Verge / sing-box 通用）\n"
                          "  /links   明文节点链接（每行一条）",
                  style="Big.TLabel", foreground="#666666").pack(anchor="w")
        ttk.Label(f, text="提示: 复制订阅时可选局域网 IP，手机等其它设备在同一 WiFi 下也能订阅。"
                          "服务绑定 0.0.0.0，选哪个 IP 只影响复制出来的 URL。",
                  style="Big.TLabel", foreground="#666666").pack(anchor="w")

    # ---------------------------------------------- 最终组构建（导出+订阅服务共用）
    def _build_final_links(self):
        """
        最终组（核心∪新秀）→ 过滤 → 原始链接列表；无数据返回空列表

        ⚠️ 兜底机制：只跑了一两轮、或节点普遍不稳时，「核心/新秀」可能一个都没有，
        订阅就会变成空的 → 客户端（v2rayN）更新订阅直接报错。
        所以稳定组不足时，用「实测成功过、按评分排序」的节点补齐到 MIN_FALLBACK 个，
        保证订阅永远有内容可用。
        """
        self._fallback_n = 0
        rows = load_history()
        if not rows:
            return []
        # v1.8 own_keys 透传给 drop_bad_rounds：自有节点才是故障轮探针
        _own = [k.strip() for k in (getattr(self, "own_keys", None)
                                    and self.own_keys.get() or "").split(",")
                if k.strip()]
        agg = analyze(rows, own_keys=_own)
        final = [r for r in agg
                 if r["group"].startswith("核心") or r["group"].startswith("新秀")]
        # ---- 兜底补齐 ----
        if len(final) < MIN_FALLBACK:
            have = {r.get("key") for r in final}
            cand = [r for r in agg
                    if r.get("key") not in have
                    and r["avail%"] > 0          # 至少成功过一次
                    and r["avg_delay_ms"] > 0]   # 有真实延迟数据
            cand.sort(key=lambda r: (-r["score"], r["avg_delay_ms"]))
            need = MIN_FALLBACK - len(final)
            final += cand[:need]
            self._fallback_n = len(cand[:need])
        try:
            min_sp = float(self.min_speed.get() or 0)
        except Exception:
            min_sp = 0.0
        if min_sp > 0:
            final = [r for r in final if r["avg_speed_kbs"] >= min_sp]
        try:
            top = int(self.top_n.get() or 0)
        except Exception:
            top = 0
        linkmap = self._load_linkmap()
        # v1.7：先按评分顺序解析链接、收满 top 为止（丢一补一）。
        # ⚠️ 旧版先 final[:top] 截断、再解析链接：前 top 名里没链接的节点被静默
        # 丢弃、后面候选又不回填 → 订阅经常凑不满 top_n（实测 10 个丢 3 个只剩 7）。
        out = []
        _excl_vmess = bool(getattr(self, "exclude_vmess", None)
                           and self.exclude_vmess.get())
        for r in final:
            link = self._resolve_link(linkmap, r)
            if not link:
                continue
            # v1.9.2：GFW 可 DPI 指纹识别 vmess（尤其无 TLS 的 ws），
            # 默认从订阅排除；用户可在②号页关闭开关恢复。
            if _excl_vmess and link.lower().startswith("vmess://"):
                continue
            out.append(self._tag_speed(link, r))
            if top > 0 and len(out) >= top:
                break
        return out

    @staticmethod
    def _resolve_link(linkmap, r):
        """v1.7 按优先级从 linkmap 解析节点原始链接（兼容旧版键名）

        查找顺序：
          1. `name@host:port`  规范键（累积侧现行写法）
          2. `node@host:port`  ⚠️ 旧版遗留键：无名节点（ps="node"）当时没做名字
             规范化、直接按 "node" 存键；而 analyze 聚合时已把 "node" 规范成
             host:port → 两边键名对不上 → 链接解析不出被丢弃。
             （migrate_linkmap.py 负责把旧键补写成新键，这里是运行期兼容）
          3. 纯节点名 / host:port 兜底
        """
        host, port = str(r.get("host") or ""), str(r.get("port") or "")
        for cand in (r.get("key"), f"node@{host}:{port}",
                     r.get("node"), f"{host}:{port}"):
            if cand:
                link = linkmap.get(cand)
                if link:
                    return link
        return None

    @staticmethod
    def _vmess_to_std_uri(link):
        """
        v1.9：旧式 `vmess://<base64 JSON>` → 新式 `vmess://uuid@host:port?...`

        详见文件头 v1.9 P0-4：v2rayN 对旧式 vmess 会把 "#备注" 一起送去 base64 解码，
        备注一旦存在（且被百分号编码）就必然 Format_BadBase64Char → 节点丢弃。
        新式 URI 的 "#" 是标准 fragment，v2rayN 走 ResolveStdVmess 的 Uri 解析正常入库。

        转换失败（不是旧式 / 解不开 / 关键字段缺失）时原样返回，保证不比现状更差。
        """
        if not link.lower().startswith("vmess://"):
            return link
        core = link[8:].split("#", 1)[0].split("?", 1)[0]
        if not core or "@" in core:
            return link                       # 已是新式明文 → 不动
        raw = sb._b64decode(core)
        if not raw:
            return link
        try:
            j = json.loads(raw.decode("utf-8", "replace"))
        except Exception:
            return link
        host = str(j.get("add") or "").strip()
        port = str(j.get("port") or "").strip()
        uid = str(j.get("id") or "").strip()
        if not (host and port and uid):
            return link
        q = []
        net = (str(j.get("net") or "").strip().lower() or "tcp")
        if net in ("none", ""):
            net = "tcp"
        q.append(("type", net))
        tls = str(j.get("tls") or "").strip().lower()
        if tls and tls not in ("none", "false"):
            q.append(("security", tls))       # tls / reality 等；空值=明文，不传
        scy = str(j.get("scy") or "").strip()
        if scy and scy.lower() not in ("auto", ""):
            q.append(("encryption", scy))
        for key, src in (("host", "host"), ("path", "path"), ("sni", "sni"),
                         ("alpn", "alpn"), ("fp", "fp")):
            v = str(j.get(src) or "").strip()
            if v:
                q.append((key, v))
        try:
            aid = int(j.get("aid") or 0)
        except Exception:
            aid = 0
        if aid > 0:
            q.append(("aid", str(aid)))
        qs = "&".join(f"{k}={urllib.parse.quote(v, safe='')}" for k, v in q)
        return f"vmess://{uid}@{host}:{port}?{qs}"

    @staticmethod
    def _tag_speed(link, r):
        """
        给链接备注追加实测性能标识：[延迟·速度]
        例:  香港01 [337ms·1.2MB/s]   —— 在 v2rayN 里一眼挑最快的节点
        没实测过下载的节点只标延迟；两者都没有则保持原名。
        """
        try:
            sp = float(r.get("avg_speed_kbs") or 0)
            dl = float(r.get("avg_delay_ms") or 0)
        except Exception:
            sp = dl = 0.0
        if sp >= 1024:
            spd = f"{sp / 1024:.1f}MB/s"
        elif sp > 0:
            spd = f"{sp:.0f}KB/s"
        else:
            spd = ""
        parts = []
        if dl > 0:
            parts.append(f"{dl:.0f}ms")
        if spd:
            parts.append(spd)
        if not parts:
            return link
        tag = "[" + "·".join(parts) + "]"
        if "#" in link:
            base, frag = link.split("#", 1)
            name = urllib.parse.unquote(frag)
        else:
            # 链接本身没有备注 → 依次尝试: vmess base64 里的 ps 字段 → 统计里的节点名
            base, name = link, ""
            if link.lower().startswith("vmess://"):
                raw = sb._b64decode(link[8:].split("#", 1)[0].split("?", 1)[0])
                if raw:
                    try:
                        name = (json.loads(raw.decode("utf-8", "replace"))
                                .get("ps") or "").strip()
                    except Exception:
                        name = ""
            if not name:
                name = (r.get("node") or "").strip()
        # "node" 是解析兜底的默认名（很多免费源 ps 就叫 node），毫无区分度 → 用 host:port
        if name.lower() in ("", "node"):
            host, port = str(r.get("host") or ""), str(r.get("port") or "")
            name = f"{host}:{port}" if host else ""
        # 已有旧标识先去掉，避免测速多轮后叠罗汉
        name = re.sub(r"\s*\[[^\]]*\]\s*$", "", name).strip()
        new_name = (name + " " + tag).strip()
        # v1.9：旧式 vmess 必须先转新式明文 URI，否则带备注进 v2rayN 必被丢弃
        base = App._vmess_to_std_uri(base)
        return base + "#" + urllib.parse.quote(new_name, safe="")

    def _update_served(self):
        """刷新订阅服务当前提供的内容（每轮测速后/启动时调用）"""
        links = self._build_final_links()
        self._served_links = links
        self._served_b64 = base64.b64encode(
            ("\n".join(links)).encode("utf-8")).decode("utf-8")
        self._refresh_srv_label()

    def _refresh_srv_label(self):
        if self._server:
            port = self.sub_port.get()
            n = len(self._served_links)
            fb = getattr(self, "_fallback_n", 0)
            extra = f"（含 {fb} 个兜底节点）" if fb else ""
            self.lbl_srv.set(f"● 订阅服务运行中  http://<本机IP>:{port}/sub"
                             f"   （当前最终组 {n} 个节点{extra}，测速后自动更新）")
        else:
            self.lbl_srv.set("订阅服务未开启。")

    def _toggle_server(self):
        if self._server:
            self._stop_server()
        else:
            self._start_server()

    def _start_server(self, silent=False):
        if self._server:
            return
        try:
            port = int(self.sub_port.get() or 18099)
        except Exception:
            port = 18099
        try:
            srv = SubHTTPServer(("0.0.0.0", port), SubHandler)
        except Exception as e:
            if not silent:
                messagebox.showerror("端口占用", f"无法监听 {port} 端口:\n{e}")
            return
        srv.app = self
        self._server = srv
        self._server_thread = threading.Thread(target=srv.serve_forever, daemon=True)
        self._server_thread.start()
        self.btn_srv.config(text="⏹ 停止订阅服务")
        self._update_served()
        self._save_config()
        if not silent:
            self.status_msg(f"订阅服务已开启: http://<本机IP>:{port}/sub")

    def _stop_server(self):
        if not self._server:
            return
        srv = self._server
        self._server = None
        try:
            srv.shutdown()
        except Exception:
            pass
        try:
            # ⚠️ 必须关闭监听 socket：只 shutdown() 不放端口，
            # 下次再开启会撞上残留 socket（Windows 下还可能静默绑到同一个端口导致请求落空）
            srv.server_close()
        except Exception:
            pass
        self._server_thread = None
        self.btn_srv.config(text="▶ 开启订阅服务")
        self._refresh_srv_label()
        self._save_config()

    def _copy_sub_url(self):
        """复制订阅 URL（带局域网 IP 选择，借鉴 SubsCheck）"""
        if not self._server:
            messagebox.showinfo("先开启服务", "订阅服务未开启，正在为你自动开启…")
            self._start_server()
            if not self._server:
                return
        self._update_served()   # 复制前按最新过滤条件刷新内容
        ips = _lan_ips()
        ip = self._pick_lan_ip(ips)
        if ip is None:
            return
        url = f"http://{ip}:{self.sub_port.get()}/sub"
        self.clipboard_clear()
        self.clipboard_append(url)
        messagebox.showinfo("已复制", f"订阅 URL 已复制到剪贴板:\n\n{url}\n\n"
                             "粘贴到 v2rayN「订阅分组」→ 添加订阅即可。\n"
                             "每轮测速后节点自动更新，无需重新导入。")

    def _pick_lan_ip(self, ips):
        """局域网 IP 选择对话框（返回选中的 IP；取消返回 127.0.0.1；关闭返回 None）"""
        if not ips:
            return "127.0.0.1"
        dlg = tk.Toplevel(self)
        dlg.title("选择局域网 IP 地址")
        dlg.geometry("380x330")
        dlg.transient(self)
        dlg.grab_set()
        ttk.Label(dlg, text="发现多个局域网 IP 地址：", style="Big.TLabel").pack(anchor="w", padx=12, pady=(12, 4))
        ttk.Label(dlg, text="· 仅在本机访问：直接点【确定】，将使用 127.0.0.1\n"
                            "· 局域网内其它设备访问（如手机）：请在列表中选择",
                  style="Big.TLabel", foreground="#666666",
                  wraplength=340, justify="left").pack(anchor="w", padx=12)
        lb = tk.Listbox(dlg, font=("Consolas", 11), height=6)
        for i in ips:
            lb.insert("end", i)
        lb.pack(fill="both", expand=True, padx=12, pady=8)
        # 默认预选：优先非 .1 结尾（借鉴 SubsCheck 的推荐逻辑）
        prefer = next((k for k, i in enumerate(ips) if not i.endswith(".1")), 0)
        lb.selection_set(prefer)
        result = {"ip": None}
        btns = ttk.Frame(dlg)
        btns.pack(pady=(0, 12))
        ttk.Label(dlg, text="注意: 选择错误的 IP 会导致其它设备无法访问。\n"
                            "推荐可以先尝试使用非「.1」结尾的 IP！",
                  foreground="#c02626", style="Big.TLabel",
                  wraplength=340, justify="left").pack(anchor="w", padx=12)

        def ok(local=False):
            if local:
                result["ip"] = "127.0.0.1"
            else:
                sel = lb.curselection()
                result["ip"] = ips[sel[0]] if sel else "127.0.0.1"
            dlg.destroy()

        ttk.Button(btns, text="确定", style="Big.TButton",
                   command=lambda: ok(False)).pack(side="left", padx=6)
        ttk.Button(btns, text="仅本机(127.0.0.1)", style="Big.TButton",
                   command=lambda: ok(True)).pack(side="left", padx=6)
        ttk.Button(btns, text="取消", style="Big.TButton",
                   command=dlg.destroy).pack(side="left", padx=6)
        dlg.wait_window()
        return result["ip"]

    def status_msg(self, text):
        if hasattr(self, "status"):
            self.status.set(text)

    # ------------------------------------------------------ 配置持久化
    def _load_config(self):
        """启动时恢复上次的节点与间隔设置"""
        try:
            if os.path.exists(CONFIG_FILE):
                d = json.load(open(CONFIG_FILE, encoding="utf-8"))
                self.txt_nodes.delete("1.0", "end")
                self.txt_nodes.insert("1.0", d.get("nodes", ""))
                self.txt_subs.delete("1.0", "end")
                self.txt_subs.insert("1.0", d.get("subs", ""))
                self.interval.set(d.get("interval", "3"))
                self.gh_proxy.set(d.get("gh_proxy", ""))
                if hasattr(self, "src_proxy"):
                    self.src_proxy.set(d.get("src_proxy", "socks5h://127.0.0.1:10809"))
                self.sub_port.set(d.get("sub_port", "18099"))
                self.top_n.set(d.get("top_n", "0"))
                self.min_speed.set(d.get("min_speed", "0"))
                self.auto_sub.set(bool(d.get("auto_sub", False)))
                self.auto_timer.set(bool(d.get("auto_timer", False)))
                if hasattr(self, "exclude_vmess"):
                    self.exclude_vmess.set(bool(d.get("exclude_vmess", True)))
                self.own_keys.delete(0, "end")
                self.own_keys.insert(0, d.get("own_keys", ""))
                self.sample_n.set(str(d.get("sample_n", 300)))
                self.top_n.set(str(d.get("top_n", DEFAULT_PICK_N)))
        except Exception:
            pass

    def _save_config(self):
        """保存当前节点与间隔设置"""
        try:
            # 保留手动指定的 v2rayN db 路径与内核路径（一键导入/下载/指定时写入）
            v2db, _sbk = "", ""
            try:
                if os.path.exists(CONFIG_FILE):
                    _c = json.load(open(CONFIG_FILE, encoding="utf-8"))
                    v2db = _c.get("v2rayn_db", "")
                    _sbk = _c.get("singbox_kernel", "")
            except Exception:
                pass
            json.dump({
                "nodes": self.txt_nodes.get("1.0", "end"),
                "subs": self.txt_subs.get("1.0", "end"),
                "interval": self.interval.get(),
                "gh_proxy": self.gh_proxy.get(),
                "src_proxy": (self.src_proxy.get()
                              if hasattr(self, "src_proxy") else ""),
                "sub_port": self.sub_port.get(),
                "top_n": self.top_n.get(),
                "min_speed": self.min_speed.get(),
                "auto_sub": bool(self.auto_sub.get()),
                "auto_timer": bool(self.auto_timer.get()),
                "exclude_vmess": bool(getattr(self, "exclude_vmess", None)
                                      and self.exclude_vmess.get()),
                "v2rayn_db": v2db,
                "singbox_kernel": _sbk,
                "own_keys": self.own_keys.get(),
                "sample_n": self.sample_n.get(),
            }, open(CONFIG_FILE, "w", encoding="utf-8"),
                 ensure_ascii=False, indent=1)
        except Exception:
            pass

    # ------------------------------------------------------ 节点链接映射（用于导出订阅）
    LINKMAP_FILE = os.path.join(BASE_DIR, "tracker_links.json")

    def _load_linkmap(self):
        try:
            if os.path.exists(self.LINKMAP_FILE):
                return json.load(open(self.LINKMAP_FILE, encoding="utf-8"))
        except Exception:
            pass
        return {}

    def _save_linkmap(self, linkmap):
        try:
            json.dump(linkmap, open(self.LINKMAP_FILE, "w", encoding="utf-8"),
                      ensure_ascii=False, indent=1)
        except Exception:
            pass

    def _export_sub(self):
        """把最终组（核心∪新秀）打包成 base64 订阅并保存"""
        links = self._build_final_links()
        if not links:
            rows = load_history()
            if not rows:
                messagebox.showwarning("无数据", "还没有测速历史，先跑几轮再导出。")
            else:
                messagebox.showinfo("提示", "目前还没节点进入最终组（核心∪新秀），或被过滤条件筛掉。\n"
                                    "多跑几轮（尤其跨上午/中午/晚上）后，稳定节点会自动进组。")
            return
        b64 = base64.b64encode(("\n".join(links)).encode("utf-8")).decode("utf-8")
        out = filedialog.asksaveasfilename(
            title="保存最终订阅",
            defaultextension=".txt",
            filetypes=[("订阅文件", "*.txt"), ("All", "*.*")],
            initialfile="final_subscription.txt")
        if not out:
            return
        try:
            with open(out, "w", encoding="utf-8") as f:
                f.write(b64)
            # 同时存一份带时间戳的副本到工作目录
            stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M")
            dup = os.path.join(os.path.dirname(os.path.abspath(out)),
                               f"final_subscription_{stamp}.txt")
            with open(dup, "w", encoding="utf-8") as f:
                f.write(b64)
            messagebox.showinfo("导出成功",
                                f"已导出 {len(links)} 个节点到:\n{out}\n\n"
                                f"内容为标准 base64 订阅，可直接粘贴到 v2rayN / "
                                f"Clash / sing-box 的订阅框使用。\n"
                                f"另存副本: {dup}")
        except Exception as e:
            messagebox.showerror("导出失败", str(e))

    # ------------------------------------------------------ 测速一轮
    def _run_round(self, manual=False):
        # ⚠️ 重入保护：上一轮未结束时再点会起第二个 sing-box 抢同一个 API 端口（9090），
        # 两个工作线程互相干扰，结果串台且内核启动必然失败
        if getattr(self, "_busy", False):
            messagebox.showinfo("正在测速",
                                "上一轮测速还在进行中。\n请等待完成，或点「⏹ 取消本轮」中止后再开始。")
            return
        if self._timer:
            self.after_cancel(self._timer)
            self._timer = None

        raw_nodes = self.txt_nodes.get("1.0", "end")
        raw_subs = self.txt_subs.get("1.0", "end")

        manual_links = []
        for ln in raw_nodes.splitlines():
            s = (ln or "").strip()
            if not s or s.startswith("#"):
                continue
            manual_links.append(s)

        sub_urls = [l.strip() for l in raw_subs.splitlines()
                    if l.strip() and not l.strip().startswith("#")]

        if not manual_links and not sub_urls:
            messagebox.showwarning("无输入", "请至少填入一个手动节点或订阅链接。")
            return

        self._busy = True
        self.btn_toggle.config(state="disabled")
        self.btn_once.config(state="disabled")
        self._cancel_event.clear()
        self.btn_cancel.config(state="normal")
        self.pb.config(mode="indeterminate")
        self.pb.start(25)
        self.lbl_progress.set("正在启动 sing-box 内核…（点「取消本轮」可中止）")
        self._round += 1
        self.status.set(f"第 {self._round} 轮测速中…（手动 {len(manual_links)} / 订阅 {len(sub_urls)}）")
        threading.Thread(target=self._worker,
                        args=(manual_links, sub_urls, self._round),
                        daemon=True).start()

    def _worker(self, manual_links, sub_urls, rnd):
        timeout = float(self.timeout.get() or 5)
        slot = current_slot()
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # 1) 收集所有节点 -> sing-box item（去重避免重复测速）
        items = []
        meta = {}            # tag -> 原始备注名
        seen = set()        # (server, port) 去重
        for l in manual_links:
            it = sb.parse_link_to_item(l)
            if not it:
                continue
            key = (it["outbound"].get("server"), it["outbound"].get("server_port"))
            if key in seen:
                continue
            seen.add(key)
            items.append(it)
            meta[it["outbound"]["tag"]] = _remark_of(l)
        # 订阅并发拉取：68 个源串行最多要 68×20s≈22 分钟且期间界面毫无反馈
        fetch_ok, fetch_fail = 0, 0
        if sub_urls:
            # v1.8 拉源策略（优先级从高到低，逐级探活）：
            #   1. src_proxy（本机 sing-box/v2rayN 代理）——直连 GitHub 必被墙，
            #      只有经代理拉才通；实测 socks5h://127.0.0.1:10809 可拉通 65 个源
            #   2. gh_proxy 镜像前缀（经 src_proxy 探活；src_proxy 为空则直连探活）
            #   3. 直连（基本必死，兜底）
            src_proxy = (getattr(self, "src_proxy", None)
                         and self.src_proxy.get() or "").strip()
            prefix = (self.gh_proxy.get() or "").strip()
            if src_proxy:
                # as_prefix=False：src_proxy 是代理地址，不是 URL 前缀
                if not _proxy_alive(src_proxy, timeout=8, via=src_proxy,
                                    as_prefix=False):
                    self.after(0, self.status_msg,
                               f"⚠️ 拉源代理({src_proxy}) 探活失败，本轮订阅拉取可能大面积失败")
                    src_proxy = ""
            # v1.7 gh_proxy 探活 + 故障自动切换：
            # 旧版代理死了全部 GitHub 源静默失败 → 池子只剩老节点 → 扫描全灭 → 订阅冻结
            if prefix and any(u.startswith("https://raw.githubusercontent.com")
                              for u in sub_urls):
                if not _proxy_alive(prefix, via=src_proxy):
                    switched = next((b for b in PROXY_BACKUPS
                                     if _proxy_alive(b, via=src_proxy)), "")
                    if switched:
                        self.after(0, self.status_msg,
                                   f"⚠️ gh_proxy({prefix}) 失效，已自动切换为 {switched}")
                        prefix = switched
                    else:
                        self.after(0, self.status_msg,
                                   "⚠️ 所有 gh 代理探活失败，本轮订阅拉取可能大面积失败")

            def _fetch_one(url):
                fetch = url
                if prefix and url.startswith("https://raw.githubusercontent.com"):
                    fetch = prefix + url
                try:
                    return url, sb.load_subscription(fetch, proxy=src_proxy), None
                except Exception as e:
                    return url, [], str(e)

            done_n = 0
            # ⚠️ 并发 8 而非 16：实测 16 并发经 SOCKS5 代理拉大源（3MB）会拥挤
            # 超时误杀（sc1/sc2 单跑 6s/14s 成功，16 并发里全 0）
            with ThreadPoolExecutor(max_workers=min(8, len(sub_urls))) as pool:
                for url, got, err in pool.map(_fetch_one, sub_urls):
                    done_n += 1
                    if err:
                        fetch_fail += 1
                    else:
                        fetch_ok += 1
                    self.after(0, self.lbl_progress.set,
                               f"正在拉取订阅 {done_n}/{len(sub_urls)} …")
                    for it in (got or []):
                        key = (it["outbound"].get("server"),
                               it["outbound"].get("server_port"))
                        if key in seen:
                            continue
                        seen.add(key)
                        items.append(it)
                        meta[it["outbound"]["tag"]] = _remark_of(it["link"])
            # 拉取结果反馈（原来失败完全静默，用户以为卡住）
            tip = f"订阅拉取: 成功 {fetch_ok} / 失败 {fetch_fail}"
            self.after(0, self.lbl_progress.set, tip)

        if not items:
            self.after(0, lambda: messagebox.showwarning(
                "无有效节点", "没有解析出任何有效节点，请检查输入格式/网络。"))
            self.after(0, self._end_round_ui)
            return

        # ⚠️ tag 必须全局唯一：公共订阅里同名节点极多，
        # 同名 tag 会让 sing-box 配置出现 duplicate outbound tag（内核起不来/节点互相覆盖）
        uniq = []
        for idx, it in enumerate(items, 1):
            old = it["outbound"].get("tag")
            name = meta.get(old) or old or "node"
            new_tag = f"n{idx}"
            it["outbound"]["tag"] = new_tag
            meta[new_tag] = name
            uniq.append(it)
        items = uniq

        # 2b) 分池：自建节点精测(多次取中位数) + 免费节点抽样(避免上万节点把内核拖死)
        own_keys = [k.strip() for k in (getattr(self, "own_keys", None)
                                        and self.own_keys.get() or "").split(",")
                    if k.strip()]

        def is_own(it):
            host = str(it["outbound"].get("server", ""))
            return any(k in host for k in own_keys)

        if own_keys:
            own_items = [it for it in items if is_own(it)]
            free_items = [it for it in items if not is_own(it)]
        else:
            own_items, free_items = [], items

        try:
            sample_n = int(self.sample_n.get() or 0)
        except Exception:
            sample_n = 0
        if sample_n > 0 and len(free_items) > sample_n:
            random.shuffle(free_items)
            free_items = free_items[:sample_n]

        # 批次：自建每批 200 且每个节点测 3 次；免费每批 300 测 1 次
        batches = []
        for i in range(0, len(own_items), 200):
            batches.append((own_items[i:i + 200], OWN_REPEAT))
        for i in range(0, len(free_items), 300):
            batches.append((free_items[i:i + 300], 1))
        if not batches:
            batches = [(items, 1)]
        total_items = len(own_items) + len(free_items)

        # 2) 阶段A：分批测延迟（单批太大会让内核起不来 → 整轮全灭）
        self.after(0, self._pb_to_determinate, total_items)
        res = []
        cancelled = False
        done_base = 0
        try:
            for batch, rep in batches:
                if self._cancel_event.is_set():
                    cancelled = True
                    break
                offset = done_base

                def _cb(done, total, phase="", _off=offset):
                    self.after(0, self._pb_tick, _off + done, total_items, phase)

                part, cancelled = sb.run_probe(
                    batch, kernel=get_kernel(),
                    test_timeout_ms=int(timeout * 1000),
                    per_node_timeout=int(timeout) + 5,
                    startup_timeout=60,          # 大配置文件加载慢，20s 不够
                    measure_speed=False,         # 延迟阶段不测速，最后统一精测
                    concurrency=int(self.conc.get() or 20),
                    repeat=rep,                  # 自建节点精测多次取中位数
                    progress_cb=_cb,
                    cancel_cb=lambda: self._cancel_event.is_set(),
                )
                res.extend(part)
                done_base += len(batch)
                if cancelled:
                    break

            # 阶段B：只对「全局延迟最快」的 20 个单独实测下载速度
            # （每批都测会退化成 34批×20个×15s，太慢）
            if res and not cancelled:
                tops = sorted([r for r in res if r["ok"]],
                              key=lambda r: r["delay_ms"] or 10 ** 9)[:20]
                tag2item = {it["outbound"]["tag"]: it for it in items}
                top_items = [tag2item[r["tag"]] for r in tops
                             if r["tag"] in tag2item]
                if top_items:
                    self.after(0, self.lbl_progress.set,
                               f"正在对最快的 {len(top_items)} 个节点实测下载速度 …")
                    part2, _c2 = sb.run_probe(
                        top_items, kernel=get_kernel(),
                        test_timeout_ms=int(timeout * 1000),
                        per_node_timeout=int(timeout) + 5,
                        startup_timeout=60,
                        measure_speed=True,
                        speed_bytes=2_000_000,
                        speed_timeout=int(timeout) + 10,
                        concurrency=min(10, int(self.conc.get() or 20)),
                        speed_top_n=len(top_items),
                        progress_cb=lambda d, t, ph="": self.after(
                            0, self._pb_tick, d, len(top_items), "speed"),
                        cancel_cb=lambda: self._cancel_event.is_set(),
                    )
                    spd = {r["tag"]: r["speed_kbs"] for r in part2}
                    for r in res:
                        if r["tag"] in spd:
                            r["speed_kbs"] = spd[r["tag"]]
        except Exception as e:
            self.after(0, lambda: messagebox.showerror("内核错误", f"sing-box 运行异常:\n{e}"))
            self.after(0, self._end_round_ui)
            return

        # 3) 落盘 + 统计 + 刷新 UI（整段兜底：工作线程绝不能静默死亡把 UI 卡死）
        try:
            # v1.7 全灭轮告警：整轮成功率低于剔除线时必须让用户知道。
            # 旧版只静默剔除 → 用户以为订阅在正常更新，其实数据已冻结（订阅永远同一批节点）
            # v1.8 判定改用「自有节点探针」：免费订阅源正常存活率就只有 2~3%
            # （实测 30 抽 1、314 抽 7），与「内核挂了」的 5% 线根本没法区分 →
            # 旧逻辑把正常轮当故障轮剔除，数据永远冻结。自有节点（own_keys）是
            # 可控的，它们不通用意昧着内核/代理真出问题，才是可靠的故障探针。
            _bad_round = False
            _bad_desc = ""
            if own_items:
                _own_res = [r for r in res
                            if r["tag"] in {it["outbound"]["tag"]
                                            for it in own_items}]
                if _own_res:
                    _ok_n = sum(1 for r in _own_res if r.get("ok"))
                    _rate = _ok_n / len(_own_res)
                    if _rate < 0.5:
                        _bad_round = True
                        _bad_desc = (f"自有节点 {len(_own_res)} 个仅 {_ok_n} 个测通"
                                     f"（{_rate*100:.0f}%），内核/代理可能异常")
            elif res and len(res) >= 100:
                # 无自有节点时回退总量判定（门槛提高到 100 样本，防免费源小样本误判）
                _ok_n = sum(1 for r in res if r.get("ok"))
                _rate = _ok_n / len(res)
                if _rate < BAD_ROUND_RATE:
                    _bad_round = True
                    _bad_desc = (f"本轮 {len(res)} 个节点仅 {_ok_n} 个测通"
                                 f"（{_rate*100:.1f}%），低于 {BAD_ROUND_RATE*100:.0f}% 剔除线")
            if _bad_round:
                self.after(0, lambda: messagebox.showwarning(
                    "⚠️ 本轮全灭（历史数据已冻结）",
                    f"{_bad_desc}，本轮已按故障轮剔除、不进统计。\n\n"
                    "可能原因：\n"
                    "· sing-box 内核异常 / 端口冲突\n"
                    "· 拉源代理失效（①号页 socks5h://127.0.0.1:10809）\n"
                    "· gh_proxy 失效（已内置自动切换，全挂会另出提示）\n\n"
                    "免费节点存活率低是常态，不算故障；连续全灭时订阅会停更。"))
            records = []
            for r in res:
                records.append({
                    "ts": ts, "round": str(rnd), "slot": slot,
                    "node": meta.get(r["tag"], r["tag"]),
                    "proto": r["proto"], "host": r["host"], "port": r["port"],
                    "delay_ms": r["delay_ms"] if r["delay_ms"] else 0,
                    "speed_kbs": r["speed_kbs"],
                    "ok": "是" if r["ok"] else "否",
                })
            # 累积 节点 -> 原始链接 映射（导出订阅用，键与 analyze 的 key 保持一致）
            linkmap = self._load_linkmap()
            for r in res:
                if not r.get("link"):
                    continue
                # ⚠️ 名字必须与 analyze() 保持一致：未命名节点（链接没写 #备注名）兜底成
                # host:port，否则 analyze 的 key = host:port@host:port，而这里写成
                # node@host:port → 两边对不上 → 链接解析不出被丢弃（只影响手动无名节点）。
                # 兜底条件与 analyze 对齐：空名 / "node" 都算 host:port。
                name = meta.get(r["tag"], r["tag"])
                if (not name) or str(name).strip().lower() == "node":
                    name = f"{r['host']}:{r['port']}"
                linkmap[f"{name}@{r['host']}:{r['port']}"] = r["link"]
                linkmap.setdefault(name, r["link"])   # 兼容旧版按名字查 + host:port 兜底
            self._save_linkmap(linkmap)

            append_history(records)
            agg = analyze(load_history())
            self.after(0, self._fill, agg, rnd, cancelled)
            # 订阅服务内容随测速结果自动更新
            self.after(0, self._update_served)
        except Exception:
            err = traceback.format_exc()
            self.after(0, lambda: messagebox.showerror(
                "测速结果处理失败", "结果已测出，但落盘/统计环节出错：\n\n" + err[-1500:]))
            self.after(0, self._end_round_ui)

    # ------------------------------------------------------ 本轮收尾（解锁 UI）
    def _end_round_ui(self):
        """无论正常/异常/取消，都要把按钮和进度恢复，绝不能把 UI 卡死"""
        self._busy = False
        for btn in ("btn_toggle", "btn_once"):
            try:
                getattr(self, btn).config(state="normal")
            except Exception:
                pass
        try:
            self.btn_cancel.config(state="disabled")
        except Exception:
            pass
        self._pb_stop()

    # ------------------------------------------------------ 结果表排序
    def _sort_tree(self, col):
        """点列标题排序（数值列按数值，否则按字符串；再点一次反向）"""
        try:
            self._sort_desc[col] = not self._sort_desc.get(col, True)
            desc = self._sort_desc[col]

            def num_of(v):
                try:
                    return float(str(v).rstrip("%").strip())
                except Exception:
                    return None

            rows = []
            for k in self.tree.get_children(""):
                v = self.tree.set(k, col)
                rows.append((num_of(v), str(v), k))
            if all(r[0] is not None for r in rows):
                rows.sort(key=lambda x: x[0], reverse=desc)
            else:
                rows.sort(key=lambda x: x[1], reverse=desc)
            for i, (_, _, k) in enumerate(rows):
                self.tree.move(k, "", i)
        except Exception:
            pass

    # ------------------------------------------------------ 复制选中节点链接
    def _popup_tree_menu(self, event):
        """右键测速结果：先选中右键所在行，再弹菜单"""
        iid = self.tree.identify_row(event.y)
        if iid:
            self.tree.selection_set(iid)
        try:
            self.tree_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.tree_menu.grab_release()

    def _copy_node_link(self):
        """把选中节点的原始链接（vless://…）复制到剪贴板，供 v2rayN 单独测试"""
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("提示", "请先在「定时测速」结果表格里选中一个节点。")
            return
        iid = sel[0]
        link = getattr(self, "_tree_links", {}).get(iid, "")
        if not link:
            messagebox.showwarning("无链接",
                "该节点没有可复制的原始链接（多见于历史遗留的无名节点）。\n"
                "重新跑一轮测速即可补上链接映射。")
            return
        self.clipboard_clear()
        self.clipboard_append(link)
        messagebox.showinfo("已复制", "节点链接已复制到剪贴板 ✓\n\n可直接粘贴到 v2rayN 进行单独测速。")

    def _fill(self, rows, rnd, cancelled=False):
        try:
            self._tree_links = {}
            for i in self.tree.get_children():
                self.tree.delete(i)
            lm = self._load_linkmap()
            for r in rows:
                name = r.get("node", "")
                host = r.get("host", "")
                port = r.get("port", "")
                # 候选键：与 analyze / linkmap 的 key 规则对齐（无名节点 name->host:port）
                if str(name).strip().lower() == "node":
                    cands = [f"{host}:{port}@{host}:{port}", f"node@{host}:{port}"]
                else:
                    cands = [f"{name}@{host}:{port}", f"node@{host}:{port}"]
                link = next((lm[k] for k in cands if k in lm), "")
                iid = self.tree.insert("", "end", values=(
                    r["node"], r["proto"], r["host"], r["port"],
                    r["avg_delay_ms"], r["avg_speed_kbs"], f'{r.get("avail%", 0)}%',
                    r["slots"], r["group"], r["score"]))
                self._tree_links[iid] = link
            cnt = summarize(rows)
            txt = "统计: " + " · ".join(f"{k} {v}个" for k, v in sorted(cnt.items()))
            if _LAST_DROPPED:
                txt += f"   ｜ 已剔除 {len(_LAST_DROPPED)} 个故障轮（整轮失败，数据作废）"
            self.lbl_stats.set(txt)
        except Exception:
            err = traceback.format_exc()
            messagebox.showerror("渲染结果失败", "测速结果渲染表格时出错：\n\n" + err[-1200:])
        finally:
            self._busy = False
            try:
                self.btn_once.config(state="normal")
            except Exception:
                pass
            self.btn_toggle.config(state="normal")
            self._pb_finish(cancelled)
            if cancelled:
                self.status.set(f"第 {rnd} 轮已取消 — 已测节点结果已记录，未测节点跳过")
            else:
                self.status.set("单轮测速完成 ✓  — 最终订阅 = 核心(稳) ∪ 新秀(动态)")
            # 定时模式：无论本轮是否取消，都按原计划排下一轮（取消=跳过本轮）
            if self._running:
                self._schedule_next()

    # ------------------------------------------------------ 进度条 / 取消 辅助
    def _pb_to_determinate(self, n):
        try:
            self.pb.stop()
        except Exception:
            pass
        self._pb_phase = ""
        self.pb.config(mode="determinate", maximum=max(int(n), 1), value=0)
        conc = self.conc.get() or "20"
        self.lbl_progress.set(f"共 {n} 个节点 · 并发 {conc} · 正在测延迟…（点「取消本轮」可中止）")

    def _pb_tick(self, done, total, phase=""):
        # 阶段切换时重置进度条量程（延迟=全部节点；速度=top-N 最快节点）
        if phase and phase != getattr(self, "_pb_phase", ""):
            self._pb_phase = phase
            try:
                self.pb.config(maximum=max(int(total), 1), value=0)
            except Exception:
                pass
        try:
            self.pb["value"] = done
        except Exception:
            pass
        if phase == "speed":
            self.lbl_progress.set(f"下载测速 {done}/{total}（对延迟最快的节点实测 2MB 下载）…")
        else:
            self.lbl_progress.set(f"延迟测试 {done}/{total} …")

    def _pb_finish(self, cancelled):
        try:
            self.pb.stop()
        except Exception:
            pass
        self.pb.config(mode="determinate")
        if not cancelled:
            try:
                self.pb["value"] = self.pb["maximum"]
            except Exception:
                pass
        self.btn_cancel.config(state="disabled")
        if cancelled:
            self.lbl_progress.set("已取消本轮（已测节点结果已记录）")
        else:
            self.lbl_progress.set("本轮测速完成 ✓")

    def _pb_stop(self):
        try:
            self.pb.stop()
        except Exception:
            pass
        self.pb.config(mode="determinate", value=0)
        self.lbl_progress.set("")
        self.btn_cancel.config(state="disabled")

    def _cancel_round(self):
        if self._cancel_event.is_set():
            return
        self._cancel_event.set()
        self.status_msg("正在取消本轮测速…（当前节点测完后停止，已测结果会保留）")

    # ------------------------------------------------------ 定时控制
    def _toggle_timer(self):
        self._save_config()
        if not self._running:
            self._running = True
            self.btn_toggle.config(text="⏸ 停止定时测速")
            self._run_round()
        else:
            self._running = False
            self.btn_toggle.config(text="▶ 启动定时测速")
            if self._timer:
                self.after_cancel(self._timer)
                self._timer = None
            self.status.set("定时测速已停止。")

    def _schedule_next(self):
        if not self._running:
            return
        hrs = float(self.interval.get() or 3)
        ms = int(hrs * 3600 * 1000)
        self._timer = self.after(ms, self._run_round)
        nxt = datetime.datetime.now() + datetime.timedelta(hours=hrs)
        self.status.set(f"定时测速运行中 · 下次 {nxt.strftime('%m-%d %H:%M')}")


# ============================================================ 单例与残留清理
def _pid_info(pid):
    """用 tasklist 查某个 PID 的映像名（用于判断进程是否还活着、是不是本程序）"""
    try:
        out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                             capture_output=True, text=True, timeout=8,
                             creationflags=0x08000000)
        return out.stdout or ""
    except Exception:
        return ""


def single_instance_guard():
    """
    只允许一个实例运行。若已有实例在跑（很可能最小化在托盘里），返回它的 PID。
    否则登记自己并返回 None。
    """
    lock = os.path.join(BASE_DIR, ".app.lock")
    try:
        if os.path.exists(lock):
            d = json.load(open(lock, encoding="utf-8"))
            pid = int(d.get("pid", 0))
            if pid and pid != os.getpid() and "NodeTracker" in _pid_info(pid):
                return pid
    except Exception:
        pass
    try:
        json.dump({"pid": os.getpid(), "ts": datetime.datetime.now().isoformat()},
                  open(lock, "w", encoding="utf-8"))
    except Exception:
        pass
    return None


def release_instance_lock():
    try:
        p = os.path.join(BASE_DIR, ".app.lock")
        if os.path.exists(p):
            os.remove(p)
    except Exception:
        pass


def main():
    # 1) 清掉上次异常退出残留的内核进程（只杀我们自己的，不动 v2rayN 的）
    try:
        n = sb.kill_stale_kernels()
        if n:
            print(f"[启动] 已清理 {n} 个残留内核进程")
    except Exception:
        pass

    # 2) 单例：已在跑就提示，不再开第二个（否则两个实例抢端口、互相干扰）
    other = single_instance_guard()
    if other:
        root = tk.Tk()
        root.withdraw()
        messagebox.showinfo(
            "程序已经在运行",
            f"NodeTracker 已经在运行了（进程 {other}）。\n\n"
            "它很可能最小化在 Windows 右下角托盘里 —— 双击托盘图标就能打开。\n"
            "要彻底退出：右键托盘图标 →「退出程序」。")
        root.destroy()
        return

    app = App()
    try:
        app.mainloop()
    finally:
        release_instance_lock()


if __name__ == "__main__":
    main()
