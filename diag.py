import os
import json
import requests

LOGIN_URL = "https://laehfeigoiycigkfknfn.supabase.co/auth/v1/token?grant_type=password"
SITE = "https://freemchost.com"
EMAIL = os.getenv("MY_EMAIL")
PASSWORD = os.getenv("MY_PASSWORD")
ANON = os.getenv("ANON_KEY")
SERVER_ID = os.getenv("SERVER_ID") or "8e273bce-81da-45ae-8f33-2be0ce5d3ba5"
CH = "https://freemchost.com/_serverFn/8a85876cf1da47edc9a524dcba6145449f36592433445062fd5cb967b0bc9453"
AC = "https://freemchost.com/_serverFn/798181797bd95a02dee916a26c18d3539a58152db8660e097ca48d7cdd8ee50c"
DE = "https://freemchost.com/_serverFn/c3a45c08362f2f613bbb6d511a3733a9e85e561709d48bec9280e82a4aa4f47d"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36"


def payload(params, f=63):
    keys = list(params.keys())
    values = []
    for v in params.values():
        if isinstance(v, (int, float)):
            values.append({"t": 0, "s": v})
        else:
            values.append({"t": 1, "s": str(v)})
    return {"t": {"t": 10, "i": 0, "p": {"k": ["data"], "v": [
        {"t": 10, "i": 1, "p": {"k": keys, "v": values}, "o": 0}
    ]}, "o": 0}, "f": f, "m": []}


def probe(name, url, body, accept):
    hh = {
        "accept": accept,
        "authorization": f"Bearer {tok}",
        "content-type": "application/json",
        "origin": SITE,
        "referer": f"{SITE}/app/servers/{SERVER_ID}",
        "user-agent": UA,
        "x-tsr-serverFn": "true",
    }
    r = requests.post(url, headers=hh, json=body, timeout=15)
    print(f"--- {name}")
    print(f"    HTTP {r.status_code} | CT: {r.headers.get('content-type', '无')} | x-tss-serialized: {r.headers.get('x-tss-serialized')}")
    print(f"    body: {r.text[:400]!r}")


r = requests.post(LOGIN_URL, headers={
    "apikey": ANON, "authorization": f"Bearer {ANON}", "content-type": "application/json",
    "origin": SITE, "user-agent": UA,
}, json={"email": EMAIL, "password": PASSWORD, "gotrue_meta_security": {}}, timeout=15)
tok = r.json().get("access_token")
print("login:", r.status_code, "| token:", bool(tok))

base = "application/x-tss-framed, application/x-ndjson, application/json"
if tok:
    probe("DETAIL (f63, framed)", DE, payload({"id": SERVER_ID}), base)
    probe("CHALLENGE (f63, framed)", CH, payload({"id": SERVER_ID}), base)
    probe("CHALLENGE (ndjson only)", CH, payload({"id": SERVER_ID}), "application/x-ndjson")
    probe("CHALLENGE (json only)", CH, payload({"id": SERVER_ID}), "application/json")
    probe("CHALLENGE (f=0)", CH, payload({"id": SERVER_ID}, f=0), base)
    probe("ACTION (f63, 假token)", AC, payload({"id": SERVER_ID, "token": "fake", "hp": "", "dwell_ms": 9000}), base)
else:
    print("登录失败:", r.text[:200])
