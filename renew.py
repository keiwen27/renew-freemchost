import os
import re
import sys
import json
import time
from datetime import datetime
import requests

# ==================== 🔧 核心配置区 ====================
# 1. 登录配置（完全从 GitHub Secrets 读取，不留任何默认值兜底）
# Supabase 项目 ref 未变（laehfeigoiycigkfknfn），登录链路无需更换
LOGIN_URL = "https://laehfeigoiycigkfknfn.supabase.co/auth/v1/token?grant_type=password"
EMAIL = os.getenv("MY_EMAIL")
PASSWORD = os.getenv("MY_PASSWORD")

# 2. 网页前端固定死公钥（完全从 GitHub Secrets 读取）
SUPABASE_ANON_KEY = os.getenv("ANON_KEY")

# 3. 路由配置 (2026-09-13 抓包逆向三步链路：挑战 -> 续期 -> 详情)
# ⚠️ 站点域名已从 new.freemchost.com 迁回 freemchost.com，请求头 origin/referer 必须同步
SITE_ORIGIN = "https://freemchost.com"
# 【接口 0】续期挑战 Challenge：提交 {id}，返回防机器人签名 token（新增，必须先调用！）
RENEW_CHALLENGE_URL = "https://freemchost.com/_serverFn/8a85876cf1da47edc9a524dcba6145449f36592433445062fd5cb967b0bc9453"
# 【接口 A】触发续期的 Action 路由（哈希未变，但请求体新增 token/hp/dwell_ms 三个参数）
RENEW_ACTION_URL = "https://freemchost.com/_serverFn/798181797bd95a02dee916a26c18d3539a58152db8660e097ca48d7cdd8ee50c"
# 【接口 B】获取最终完整状态的 Detail 路由（哈希未变）
RENEW_DETAIL_URL = "https://freemchost.com/_serverFn/c3a45c08362f2f613bbb6d511a3733a9e85e561709d48bec9280e82a4aa4f47d"

# 服务器 ID：优先读环境变量 SERVER_ID（浏览器地址栏 /app/servers/ 后面的 UUID），
# 注意用 or 兜底：Secret 未配置时传入空字符串也要回退到默认值
# ⚠️ 2026-09-27 更换：旧服务器 8e273bce-... 已到期被平台回收，新服务器 "kwn" 于 2026-09-27 创建
SERVER_ID = os.getenv("SERVER_ID") or "c6484ab8-1345-4170-a684-2d67cd8acd41"

# 4. 人性化停留时间：网页端从弹窗打开到点击续期实测 dwell_ms=5063ms，
#    服务端校验"挑战签发 -> 续期提交"之间的停留时长，太快会被判定为机器人。
#    这里取 6.5 秒留足余量（token 本身有效期远长于此，无需担心）。
MIN_DWELL_MS = 6500

# 5. 消息推送配置（可选，可从 GitHub Secrets 读取，不需要保持 None）
SCKEY = os.getenv("SCKEY")

# 🚨 安全校验：如果必备的环境变量为空，直接中断运行并报错提示，使 GitHub Actions 显式失败
def check_credentials():
    if not all([EMAIL, PASSWORD, SUPABASE_ANON_KEY]):
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{now}] 🛑 错误: 未能在环境中检测到必要的凭证 (MY_EMAIL, MY_PASSWORD 或 ANON_KEY)。")
        print(f"[{now}] 请检查你的 GitHub Repository -> Settings -> Secrets and variables -> Actions 是否配置正确！")
        sys.exit(1)

# =====================================================

def log(message):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{now}] {message}")

def notify(title, content):
    if SCKEY:
        try:
            requests.post(f"https://sctapi.ftqq.com/{SCKEY}.send", data={"title": title, "desp": content}, timeout=5)
        except Exception as e:
            log(f"🔔 推送通知失败: {e}")

# ==================== TanStack Start (TSS) 序列化工具 ====================

def build_payload(params):
    """按站点同款 TSS 编码构造请求体。
    字符串编码为 {"t":1,"s":...}，数字编码为 {"t":0,"s":...}（与抓包逐字节一致）。
    """
    keys = list(params.keys())
    values = []
    for v in params.values():
        if isinstance(v, bool):
            values.append({"t": 1, "s": str(v).lower()})
        elif isinstance(v, (int, float)):
            values.append({"t": 0, "s": v})
        else:
            values.append({"t": 1, "s": str(v)})
    return {
        "t": {"t": 10, "i": 0, "p": {"k": ["data"], "v": [
            {"t": 10, "i": 1, "p": {"k": keys, "v": values}, "o": 0}
        ]}, "o": 0},
        "f": 63,
        "m": []
    }

def _unwrap(node, depth=0):
    """把 TSS 节点还原为 Python 值：{"t":1,"s":"x"} -> "x"；对象节点 {"p":{"k":..,"v":..}} -> dict；
    普通嵌套 dict 逐层递归还原（用于 error.message 这类内嵌结构）"""
    if depth > 12 or not isinstance(node, dict):
        return node
    if "t" in node and "s" in node:
        return node["s"]
    p = node.get("p")
    if isinstance(p, dict) and "k" in p and "v" in p:
        out = {}
        for k, v in zip(p.get("k", []), p.get("v", [])):
            out[k] = _unwrap(v, depth + 1)
        return out
    return {k: _unwrap(v, depth + 1) for k, v in node.items()}

def flatten_tss(res_json, depth=0):
    """递归拍平 TSS 响应，返回 {键: 原始值}。响应结构变化时也能兜底取值。"""
    flat = {}
    if depth > 12:
        return flat
    if isinstance(res_json, list):
        for item in res_json:
            flat.update(flatten_tss(item, depth + 1))
        return flat
    if not isinstance(res_json, dict):
        return flat
    p = res_json.get("p")
    if isinstance(p, dict) and "k" in p and "v" in p:
        ks, vs = p.get("k", []), p.get("v", [])
        for i, k in enumerate(ks):
            if i < len(vs) and k not in flat:
                flat[k] = _unwrap(vs[i])
        for v in vs:
            for fk, fv in flatten_tss(v, depth + 1).items():
                flat.setdefault(fk, fv)
    for k, v in res_json.items():
        if k == "p":
            continue
        if k not in flat:
            flat[k] = _unwrap(v)
        if isinstance(v, (dict, list)):
            for fk, fv in flatten_tss(v, depth + 1).items():
                flat.setdefault(fk, fv)
    return flat

def parse_response_objects(res):
    """把响应体解析为 JSON 对象列表：兼容旧版单帧 JSON 与新版 NDJSON 多行流式帧。
    整体解析失败时按行切分逐行解析（TSS framed 响应为每行一个 JSON 帧）。"""
    text = res.text or ""
    try:
        return [json.loads(text)]
    except ValueError:
        objs = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                objs.append(json.loads(line))
            except ValueError:
                pass
        return objs

TOKEN_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\."   # user_id
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\."   # server_id
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\."   # challenge nonce
    r"\d{13}\.[0-9a-f]{64}"                                             # 签发时间戳 + HMAC 签名
)

def extract_token(res_text, res_json):
    """从挑战响应中提取防机器人 token；优先按 TSS 结构取 token 键，失败则用特征正则兜底"""
    flat = flatten_tss(res_json)
    token = flat.get("token")
    if isinstance(token, str) and token.count(".") >= 4:
        return token
    m = TOKEN_RE.search(res_text or "")
    if m:
        return m.group(0)
    return None

def _humanize_error(err):
    """把各种形态的 error 字段转成人类可读消息；无错误时返回 None"""
    if err is None or err == "" or err == 1 or err == "1" or err == "null":
        return None
    if isinstance(err, str):
        return err
    if isinstance(err, dict):
        msg = err.get("message")
        if isinstance(msg, dict) and "s" in msg:
            return msg["s"]
        if isinstance(msg, str):
            return msg
        return json.dumps(err, ensure_ascii=False)
    return str(err)

def extract_error_message(res_json, flat):
    """提取服务端错误信息。兼容两种形态（后者见 2026-09-12 真实日志）：
    1) TSS 帧内 error 键（值可能是字符串或 {'message': {'t':1,'s':..}} 嵌套结构）
    2) 顶层 $TSR/Error 错误节点 {"t":25,"s":{"message":..},"c":"$TSR/Error"}
    res_json 支持传入单对象或 NDJSON 解析出的对象列表。
    """
    candidates = [flat.get("error")]
    nodes = res_json if isinstance(res_json, list) else [res_json]
    for node in nodes:
        if isinstance(node, dict) and node.get("c") == "$TSR/Error":
            candidates.append(node.get("s"))
    for err in candidates:
        msg = _humanize_error(err)
        if msg:
            return msg
    return None

# ==================== 主流程 ====================

def get_new_token():
    """通过模拟登录，动态换取最新的个人专属 Access Token"""
    log("🔑 正在尝试模拟登录以获取个人 Token...")

    headers = {
        "accept": "*/*",
        "accept-language": "zh-CN,zh;q=0.9",
        "content-type": "application/json",
        "apikey": SUPABASE_ANON_KEY,
        "authorization": f"Bearer {SUPABASE_ANON_KEY}",
        "origin": SITE_ORIGIN,
        "referer": f"{SITE_ORIGIN}/",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36"
    }

    payload = {
        "email": EMAIL,
        "password": PASSWORD,
        "gotrue_meta_security": {}
    }

    try:
        response = requests.post(LOGIN_URL, headers=headers, json=payload, timeout=15)
        if response.status_code == 200:
            token = response.json().get("access_token")
            if token:
                log("✅ 成功模拟登录，已捕获最新专属 Token！")
                return token
        log(f"❌ 登录失败，状态码: {response.status_code} 响应: {response.text[:200]}")
    except Exception as e:
        log(f"💥 登录请求引发异常: {e}")
    return None

def fetch_detail(base_headers):
    """调用【接口 B】拉取服务器最新状态，返回 (name, status, expires_at)"""
    try:
        detail_res = requests.post(
            RENEW_DETAIL_URL,
            headers=base_headers,
            json=build_payload({"id": SERVER_ID}),
            timeout=15
        )
        if detail_res.status_code == 200:
            detail_objects = parse_response_objects(detail_res)
            detail_flat = flatten_tss(detail_objects or None)
            return (
                detail_flat.get("name", "未知"),
                detail_flat.get("status", "未知"),
                detail_flat.get("expires_at"),
            )
        log(f"⚠️ 详情刷新接口返回状态码 {detail_res.status_code}，将使用缺省值。响应: {detail_res.text[:200]!r}")
    except Exception as e:
        log(f"⚠️ 刷新最终详情时发生非致命异常: {e}")
    return "未知", "未知", None

def run_auto_renew():
    check_credentials()
    log("▶️ 开始全自动登录 + 挑战令牌 + 链式续期确认流程...")

    # 1. 获取专属 Token
    access_token = get_new_token()
    if not access_token:
        log("🛑 未能取得有效 Token，流程被迫中断。")
        notify("服务器自动续期失败", "模拟登录未成功获取 Token，请查看本地日志。")
        sys.exit(1)

    base_headers = {
        "accept": "application/x-tss-framed, application/x-ndjson, application/json",
        "authorization": f"Bearer {access_token}",
        "content-type": "application/json",
        "origin": SITE_ORIGIN,
        "referer": f"{SITE_ORIGIN}/app/servers/{SERVER_ID}",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36",
        "x-tsr-serverFn": "true"
    }

    # 2. 步骤 0/2：请求续期挑战，获取防机器人签名 token（站点新增的反自动化机制）
    log("🧩 步骤 0/2: 正在请求续期挑战令牌 (Challenge Token)...")
    challenge_started_at = time.monotonic()
    challenge_token = None
    challenge_res = None
    try:
        challenge_res = requests.post(
            RENEW_CHALLENGE_URL,
            headers=base_headers,
            json=build_payload({"id": SERVER_ID}),
            timeout=15
        )
        if challenge_res.status_code == 200:
            res_objects = parse_response_objects(challenge_res)
            challenge_token = extract_token(challenge_res.text, res_objects or None)
        else:
            log(f"❌ 挑战令牌请求失败，状态码: {challenge_res.status_code}")
    except Exception as e:
        log(f"💥 挑战令牌接口引发异常: {e}")

    if not challenge_token:
        # 取证：打印原始响应辅助定位协议变化（仅失败时输出，成功时不刷屏）
        if challenge_res is not None:
            log(f"🔍 [调试] 挑战接口 HTTP {challenge_res.status_code} | Content-Type: {challenge_res.headers.get('content-type', '无')}")
            log(f"🔍 [调试] 响应体前 800 字符: {challenge_res.text[:800]!r}")
            if "Cannot coerce" in challenge_res.text:
                log("💡 提示: 该错误为 PostgREST PGRST116 —— SERVER_ID 对应的服务器记录在数据库中不存在。")
                log("   大概率是旧服务器到期后被平台回收。请到官网重新开通服务器，并把新 UUID 更新到")
                log("   GitHub Secret SERVER_ID（浏览器地址栏 /app/servers/ 后面那一串）。")
        log("🛑 未能取得挑战令牌 (token)，续期无法继续。站点可能再次升级，请重新抓包。")
        notify("服务器自动续期失败", "未获取到续期挑战 token，请重新抓包检查挑战接口。")
        sys.exit(1)

    token_preview = challenge_token[:44] + "..."
    log(f"✅ 已捕获挑战令牌: {token_preview}")

    # 3. 人性化停留：网页端从弹窗打开到提交实测 5 秒左右，这里等待足够时长再提交
    remaining = MIN_DWELL_MS / 1000.0 - (time.monotonic() - challenge_started_at)
    if remaining > 0:
        log(f"⏳ 模拟真人停留 {remaining:.1f} 秒后提交续期 (dwell_ms 门槛)...")
        time.sleep(remaining)
    dwell_ms = int((time.monotonic() - challenge_started_at) * 1000)

    # 4. 发送【接口 A】请求：携带 token/hp/dwell_ms 触发续期动作
    log("⚡ 步骤 1/2: 正在向后端发送续期指令...")
    expires_at = None
    err_msg = None
    action_flat = {}
    try:
        action_res = requests.post(
            RENEW_ACTION_URL,
            headers=base_headers,
            json=build_payload({"id": SERVER_ID, "token": challenge_token, "hp": "", "dwell_ms": dwell_ms}),
            timeout=15
        )
        if action_res.status_code == 200:
            action_objects = parse_response_objects(action_res)
            action_json = action_objects[0] if len(action_objects) == 1 else action_objects
            action_flat = flatten_tss(action_json)
            expires_at = action_flat.get("expires_at")
            err_msg = extract_error_message(action_json, action_flat)

            log("   📥 [接口A 返回快照] ----------------------------")
            log(f"   提交停留时长 (Dwell MS)     : {dwell_ms}")
            if "hours" in action_flat:
                log(f"   本次续期时长 (Hours)        : {action_flat['hours']}")
            if "boosted" in action_flat:
                log(f"   Discord 加成 (Boosted)      : {action_flat['boosted']}")
            log(f"   服务端校验结果              : {err_msg or '无错误返回'}")
            log(f"   捕获动作到期时间 (Expires At): {expires_at}")
            log("   ------------------------------------------------")
        else:
            log(f"❌ 续期动作请求失败，状态码: {action_res.status_code} 响应: {action_res.text[:200]}")
            notify("服务器自动续期失败", f"续期 Action 接口返回异常状态码: {action_res.status_code}")
            sys.exit(1)
    except Exception as e:
        log(f"💥 续期动作接口引发异常: {e}")
        notify("服务器自动续期异常", f"Action 阶段异常: {e}")
        sys.exit(1)

    if err_msg:
        if "too early to renew" in err_msg.lower():
            # 未到续期窗口属正常状态（服务端要求到期前 46 小时内才能续期）：
            # 拉取当前状态后按成功退出，避免 GitHub Actions 误报失败
            server_name, server_status, detail_expires = fetch_detail(base_headers)
            log("⏭️ 未到续期窗口（到期前 46 小时才开放续期），本次自动跳过。")
            log("🎉【当前服务器状态】-----------------------")
            log("TG_SUMMARY_START")
            log(f"服务器名称: {server_name}")
            log(f"服务器状态: {server_status}")
            log(f"到期时间: {detail_expires}")
            log("TG_SUMMARY_END")
            log("-------------------------------------------")
            notify("服务器暂无需续期", f"服务器 [{server_name}] 仍在有效期内，本次跳过续期。\n原因：{err_msg}\n当前到期时间：{detail_expires}")
            sys.exit(0)
        log(f"🛑 服务端拒绝续期: {err_msg}")
        notify("服务器自动续期失败", f"服务端拒绝续期: {err_msg}")
        sys.exit(1)

    # 5. 发送【接口 B】请求：拉取续期后的最终详情状态
    log("🔍 步骤 2/2: 续期指令已生效，正在拉取最终服务器完整状态确认...")
    server_name, server_status, detail_expires = fetch_detail(base_headers)
    # 详情接口携带权威到期时间，优先采用
    if detail_expires:
        expires_at = detail_expires

    # 6. 终验：必须从接口 A 或接口 B 至少一处拿到新到期时间，否则按失败处理（防止误报成功）
    if not expires_at:
        log("🛑 续期请求已发送，但未能从任何接口确认新到期时间，请人工核查。")
        notify("服务器自动续期失败", "续期请求已发送，但未能确认新到期时间，请人工核查。")
        sys.exit(1)

    # 7. 打印最终完美闭环结果并推送
    # （TG_SUMMARY 标记块由工作流提取后推送 Telegram，键名格式勿随意改动）
    log("🎉【全链路全自动续期成功】-----------------------")
    log("TG_SUMMARY_START")
    log(f"服务器名称: {server_name}")
    log(f"服务器状态: {server_status}")
    if action_flat.get("hours"):
        log(f"本次续期: +{action_flat['hours']} 小时")
    if "boosted" in action_flat:
        log(f"Discord加成: {action_flat['boosted']}")
    log(f"到期时间: {expires_at}")
    log("TG_SUMMARY_END")
    log("--------------------------------------------------")

    notify(
        "服务器自动续期成功",
        f"服务器 [{server_name}] 续期成功！\n"
        f"当前运行状态：{server_status}\n"
        f"最新到期时间：{expires_at}"
    )

if __name__ == "__main__":
    run_auto_renew()
