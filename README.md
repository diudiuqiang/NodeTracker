# NodeTracker

**订阅节点稳定性追踪器 / Subscription Node Stability Tracker**

NodeTracker 是一个本地的图形化工具，用于**长期追踪代理订阅里各个节点的连通性与测速稳定性**，并对外提供一个干净的订阅接口。

它解决的核心问题是：免费 / 公开订阅里的节点质量波动极大，今天能用的节点明天可能全灭。NodeTracker 通过周期性测速、记录历史、按稳定性排序，帮你从一大堆节点里持续筛选出**真正稳定**的那一小撮，并通过内置订阅服务把结果直接喂给你的客户端。

> 本项目的定位是**网络质量诊断与节点稳定性分析工具**。请在你所在司法辖区允许的范围内使用，并遵守相关服务条款与法律法规。

---

## 功能特性

- **定时测速**：按设定间隔对节点池做延迟 / 速度探测，支持并发。
- **历史稳定性排序**：基于多轮测速记录，按“可用性 + 延迟 + 速度”综合排序，优先推荐长期稳定的节点。
- **订阅源管理**：支持手动粘贴节点（URI / Clash YAML）和订阅链接，自动合并去重进同一个测速池。
- **内置订阅服务**：启动后在本机开放一个订阅接口（`http://<本机IP>:18099/sub`），客户端（如 v2rayN / sing-box）直接订阅即可，节点列表由 NodeTracker 实时给出最优 Top-N。
- **一键导入 v2rayN**：从 v2rayN 的 `guiNDB.db` 直接导入节点与订阅，无需手动复制。
- **内核自动定位 + 一键下载**：测速探针使用 [sing-box](https://github.com/SagerNet/sing-box) 内核。程序会优先复用你本机 v2rayN 自带的内核；找不到时可手动指定，或通过内置按钮一键下载官方稳定版。
- **可排除指定协议**：例如可开关“订阅排除 vmess”，输出只保留你信任的协议类型。

---

## 运行要求

- **Python 3.8+**（仅使用标准库，`tkinter` 随 CPython 自带，无需 `pip install` 任何第三方包）。
- **Windows 推荐**（界面与内核探测针对 Windows 优化；其他平台理论上可运行但未经充分测试）。
- **sing-box 内核（可选）**：
  - 若本机已安装 v2rayN，程序会自动定位其自带内核；
  - 否则在「来源」页点「📦 一键下载内核」自动获取，或用「📂 指定内核」手动选择 `sing-box.exe`。

---

## 快速开始

### 方式一：直接运行源码（开发 / 调试）

```bash
cd NodeTracker
python node_stability_tracker.py
```

首次启动会在程序目录下生成 `tracker_config.json`（配置）与运行态数据文件。

### 方式二：打包为独立 exe

```bash
pip install pyinstaller
pyinstaller NodeTracker.spec --noconfirm --distpath dist --workpath build
# 产物： dist/NodeTracker.exe
```

> 打包说明：`NodeTracker.spec` 默认“若检测到本机 v2rayN 的 sing-box 才将其打进 exe”，以避免在不同机器上硬编码路径失败。开源发行版**不内置** sing-box 二进制，请通过程序内「一键下载内核」或自带内核使用（sing-box 为 MIT 许可，版权归 SagerNet）。

---

## 使用流程

1. 打开程序，切到「来源」页。
2. 在文本框粘贴节点（每行一个，支持 `vmess://` `vless://` `ss://` `trojan://` 等 URI，也支持 Clash `proxies:` 段），或填入订阅链接。以 `#` 开头的行会被忽略。
3. 点「📥 一键导入 v2rayN」可一次性导入本机 v2rayN 的全部节点与订阅。
4. 确认「内核」状态标签显示 `✅ 就绪`；若 `⚠️ 未找到`，用「📦 一键下载内核」或「📂 指定内核」补齐。
5. 点「立即测一轮」或「启动定时测速」开始探测。
6. 程序启动后默认开放订阅服务 `http://<本机IP>:18099/sub`，在你的客户端里订阅该地址即可。
7. 在「结果 / 订阅」页查看按稳定性排序的 Top-N 节点与导出链接。

---

## 工作原理（简述）

- **探针**：每次测速临时拉起一个 sing-box 进程，构造最小配置把待测节点作为 outbound，经其访问探测目标（延迟用 `generate_204`，速度用大文件下载），回收结果后关闭进程。
- **历史库**：每轮测速结果写入本地 JSON / SQLite 历史，按节点去重累积，用于稳定性评分。
- **订阅服务**：一个本地 HTTP 服务，按需把当前 Top-N 最优节点按客户端兼容格式（优先 vless 明文 URI，规避部分客户端对旧式 vmess base64 的解析问题）输出。

---

## 目录结构

```
NodeTracker/
├── node_stability_tracker.py   # 主程序（GUI + 调度 + 订阅服务）
├── singbox_probe.py            # sing-box 探针（测速 / 协议解析 / 内核管理）
├── NodeTracker.spec            # PyInstaller 打包配置
├── app_icon.ico                # 程序图标
├── README.md
├── USAGE.md                    # 更详细的使用说明
├── LICENSE                     # MIT
└── .gitignore
```

---

## 许可证

[MIT](./LICENSE) © NodeTracker contributors

sing-box 内核为独立项目（MIT，© SagerNet），本项目不内置其二进制，请按需自备或通过程序内按钮下载。
