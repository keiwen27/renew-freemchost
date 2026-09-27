# 🚀 Freemchost 服务器全自动续期助手 (使用gemini生成)

[注册地址](https://freemchost.com)
![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)
![Platform](https://img.shields.io/badge/platform-GitHub%20Actions-orange)

本脚本用于全自动管理 **Freemchost** 游戏/应用服务器（基于 Pterodactyl 翼龙面板）的续期流程。针对免费微型套餐（Free mini）**每 48 小时需手动续期一次**的严格限制，本系统采用全新的**"挑战令牌 + 三接口链式"机制**，配合 GitHub Actions 实现每日全自动安全续期、多维度状态校验以及消息推送。

> ⚠️ **2026-09-13 重要更新**：站点域名从 `new.freemchost.com` 迁回 `freemchost.com`，并且续期接口新增了**防机器人挑战机制**（`token` / `hp` / `dwell_ms` 三参数），旧版单接口脚本会续期失败。本版已完整适配（依据真实抓包 + 前端 JS 逆向）。

---

## ✨ 核心特性

* **全自动链式运行**：自动模拟登录获取个人专属 Access Token，并动态注入后续所有内部函数路由。
* **三接口闭环验证（2026-09 最新）**：
  * **接口 0 (Challenge 路由)**：提交 `{id}` 获取防机器人签名挑战令牌（格式 `user_id.server_id.nonce.时间戳.HMAC签名`）。
  * **接口 A (Action 路由)**：携带 `id + token + hp + dwell_ms` 四参数下发续期指令。其中 `dwell_ms` 为"弹窗打开到提交"的停留毫秒数，脚本自动模拟 **6.5 秒**真人停留（浏览器实测 5063ms，太快会被服务端拒绝）。
  * **接口 B (Detail 路由)**：续期动作生效后，紧接着拉取最终服务器完整状态（服务器名称、在线状态、权威到期时间），确保续期结果 100% 真实有效。
* **健壮的 TSS 响应解析**：递归拍平 TanStack Start 序列化结构，响应字段结构变化时也能兜底提取 `token` / `expires_at` / `error` 等关键字段。
* **透明化步骤监控**：输出挑战令牌快照、停留时长、续期时长（Hours）、Discord 加成（Boosted）与执行状态码，让每一笔自动化续期都有据可查。
* **零依赖云端托管**：完全基于 GitHub Actions 虚拟环境运行，无需本地服务器或常驻后台，完全免费。
* **安全凭证防护**：账户、密码、密钥全线接入 GitHub Secrets 加密存储，拒绝源码泄露风险，安全防封。

---

## 🔍 核心参数获取指引（最新抓包教程）

当网站后端升级或你更换了新的服务器时，脚本中的路由参数需要同步更新。请按照以下步骤获取最新值：

### 1. 抓取三接口路由 (`RENEW_CHALLENGE_URL` / `RENEW_ACTION_URL` / `RENEW_DETAIL_URL`)
1. 使用电脑浏览器登录 [Freemchost 官网](https://freemchost.com)。
2. 进入你的服务器控制台管理页面（此时地址栏通常显示为 `https://freemchost.com/app/servers/xxxxx`）。
3. 按下键盘上的 **F12** 键（或右键点击页面选择“检查”），切换到 **Network（网络）** 标签页。
4. 在过滤框中输入 `_serverFn` 锁定目标请求，并清空旧的抓包记录。
5. **获取【接口 0：Challenge 路由】**：在网页上点击 **"Renew"（续期）按钮打开弹窗**。弹窗打开的瞬间会立刻发出一个 `POST` 请求（body 中只有 `id` 一个参数），它就是挑战令牌接口 `RENEW_CHALLENGE_URL`，复制其 Request URL。
6. **获取【接口 A：Action 路由】**：在弹窗中等待几秒后点击确认续期。此时网络面板会弹出一个 `POST` 请求（body 中含 `id, token, hp, dwell_ms` 四个参数），复制其 Request URL，即为 `RENEW_ACTION_URL`。
7. **获取【接口 B：Detail 路由】**：续期完成后，点击网页上的刷新按钮或者切换一下菜单让页面刷新。此时网络面板会弹出另一个 `_serverFn` 请求，里面返回了包含服务器名称、面板地址在内的完整大 JSON。复制该请求的 **Request URL**，它就是最新的 `RENEW_DETAIL_URL`。

### 2. 获取 `SERVER_ID`
* 最简单的方法：直接在**浏览器地址栏**的 URL 尾部（`/app/servers/` 后面那一串 36 位长、带连字符的 UUID）复制即可。
* 可选：将 `SERVER_ID` 配置为 GitHub Secret（见下表）；不配置时使用脚本内的默认值。

> 🚨 **2026-09-27 教训**：免费服务器到期 48 小时后会被平台**直接删除数据库记录**，此时挑战/详情接口会返回 PostgREST 错误 `Cannot coerce the result to a single JSON object`（PGRST116），脚本连续失败且毫无头绪。**重新开通服务器后，务必第一时间更新 GitHub Secret 里的 `SERVER_ID`**，否则自动化会一直空转失败。脚本已在失败时自动识别该错误并打印提示。

### 3. 抓取 `ANON_KEY` (Supabase 公钥)
1. 退出当前的登录状态，回到 Freemchost 登录页面。打开 F12 开发者工具，切换到 **Network（网络）** 标签。
2. 在过滤框中输入 `token?grant_type=password`。
3. 输入邮箱和密码点击登录，点击下方的抓包请求。
4. 在右侧 **Headers（标头）** -> **Request Headers（请求标头）** 区域中找到 `apikey` 或 `authorization` 字段。后面那串以 `eyJhbGci...` 开头的几百位超长字符串就是 `ANON_KEY`（复制 `authorization` 时注意去掉前面的 `Bearer ` 关键字）。
5. 当前抓包确认的公钥（Supabase 项目 ref：`laehfeigoiycigkfknfn`，有效期至 2036 年，如 Secret 里已是此值则无需更换）：
   `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImxhZWhmZWlnb2l5Y2lna2ZrbmZuIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODAyNzk1NTgsImV4cCI6MjA5NTg1NTU1OH0.r-CQTnTFWYj5Vawvn1Ky91QnPJMcp1feIRFWJrhq7T8`

---

## 🛠️ 快速部署指南

### 1. 配置 GitHub Secrets
将本仓库 Fork 或推送到你的私有/公开 GitHub 仓库后，点击仓库顶部的 **Settings** -> **Secrets and variables** -> **Actions** -> **New repository secret**，依次添加以下加密变量：

| Secret 名称 | 填入的值 / 示例 | 说明 |
| :--- | :--- | :--- |
| `MY_EMAIL` | `your_email@gmail.com` | 你的 Freemchost 登录邮箱 (必填) |
| `MY_PASSWORD` | `your_password` | 你的 Freemchost 登录密码 (必填) |
| `ANON_KEY` | `eyJhbGciOiJIUzI1NiIs...` | 前端抓取到的 Supabase 专属公钥 (必填) |
| `SERVER_ID` | `c6484ab8-1345-4170-...` | 你的服务器 UUID（强烈建议配置；不填时用脚本内的默认值） |
| `SCKEY` | `SCT123456T...` | （可选）Server酱微信推送公钥 |
| `TG_TOKEN` / `TG_ID` | `123456:AA...` / `654321` | （可选）Actions 工作流的 Telegram 推送（注意：Secret 名称必须与工作流中 `secrets.TG_TOKEN` / `secrets.TG_ID` 一致） |

### 2. 配置文件结构
请确保你的 GitHub 仓库中包含以下核心文件且路径严格一致：
```text
├── .github/
│   └── workflows/
│       └── AutoRenew.yml       # GitHub Actions 工作流配置文件
├── renew.py                    # 完美改造后的挑战令牌 + 链式核心 Python 续期脚本
└── README.md                   # 本说明文件
```
