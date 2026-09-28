#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
run_credits.py — WorkBuddy 每日积分一键（签到 + 派猫猫旅行）并推送飞书

设计（对应需求）：
  · 云端运行：从环境变量(secret) 读 WORKBUDDY_TOKEN / UID / DOMAIN / ENTID；
    云端没有本机登录态，绝不尝试读本机文件。
  · 本机验收：若上述环境变量为空，则自动调用同目录 decrypt-token.js 读本机登录态
    （仅用于本地跑通验收，云端 secret 已设时不会走此分支）。
  · 顺序：先签到；再做猫猫——「先领掉已到家的旅行积分，再判断能否派新一趟，
    今天已派过就不派」。
  · 隔离：猫猫环节任何失败都被捕获，不影响签到结论；签到成功即整体成功（exit 0）。
  · 推送：飞书消息把「签到」「猫猫」两件事分开写清楚。
  · 脱敏：令牌仅在内存使用，绝不打印/写日志原文；RAW_DUMP=1 时输出脱敏后的
    原始 HTTP 返回（token/uid 打码），满足验收「贴原始返回」需求。

仅依赖 Python 标准库（urllib / json / hmac / hashlib / base64）。
"""
import os
import sys
import json
import time
import hmac
import hashlib
import base64
import shutil
import subprocess
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path

BASE = "https://copilot.tencent.com"
API_CHECKIN = BASE + "/v2/billing/meter"          # 签到带 /v2/ 前缀
API_TRAVEL = BASE + "/activity/growth/buddy/travel"  # 猫猫不带 /v2/ 前缀


# ------------------------- 脱敏工具 -------------------------
def mask_secret(s, head=4, tail=2):
    if not s:
        return "<空>"
    if len(s) <= head + tail + 3:
        return "***"
    return s[:head] + "***" + s[-tail:]


def mask_in_text(text, token="", uid=""):
    if token and token in text:
        text = text.replace(token, "***TOKEN***")
    if uid and uid in text:
        text = text.replace(uid, mask_secret(uid, 3, 2))
    return text


def log(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


# ------------------------- 凭据解析 -------------------------
def find_node():
    for var in ("WB_NODE", "WB_CHECKIN_NODE"):
        p = os.environ.get(var)
        if p and Path(p).exists():
            return p
    found = shutil.which("node")
    return found or "node"


def find_decrypt_js():
    for var in ("WB_DECRYPT_JS", "WB_CHECKIN_DECRYPT_JS"):
        p = os.environ.get(var)
        if p and Path(p).exists():
            return p
    d = Path(__file__).resolve().parent / "decrypt-token.js"
    if d.exists():
        return str(d)
    return ""


def resolve_credentials():
    token = os.environ.get("WORKBUDDY_TOKEN", "").strip()
    uid = os.environ.get("WORKBUDDY_UID", "").strip()
    domain = os.environ.get("WORKBUDDY_DOMAIN", "").strip()
    entid = os.environ.get("WORKBUDDY_ENTID", "").strip()

    if not token:
        # 仅本机验收分支：自动读本机登录态
        dec = find_decrypt_js()
        if dec:
            try:
                out = subprocess.run(
                    [find_node(), dec], capture_output=True, text=True, timeout=60
                ).stdout or ""
                for line in out.splitlines():
                    if line.startswith("TOKEN:"):
                        token = line[6:].strip()
                    elif line.startswith("ACCOUNT_UID:"):
                        uid = line[12:].strip()
                    elif line.startswith("AUTH_DOMAIN:"):
                        domain = line[12:].strip()
                    elif line.startswith("ENTERPRISE_ID:"):
                        entid = line[14:].strip()
                if token:
                    log("凭据来源: 本机登录态(decrypt-token.js) — 仅本地验收走此分支")
            except Exception as e:  # noqa: BLE001
                log("本机解密失败: " + str(e))
        if not token:
            log("凭据来源: 未获取到（云端请检查 secret WORKBUDDY_TOKEN）")
    else:
        log("凭据来源: 环境变量(secret)")
    return token, uid, domain, entid


def build_headers(token, uid, domain, entid):
    h = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "User-Agent": "workbuddy-credits-action/1.0",
    }
    if uid:
        h["X-User-Id"] = uid
    if domain and domain != "-":
        h["X-Domain"] = domain
    if entid and entid != "-":
        h["X-Enterprise-Id"] = entid
    return h


# ------------------------- HTTP -------------------------
def http(method, url, headers, body=None, timeout=30):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return 0, json.dumps({"_error": str(e)})


def parse(body):
    try:
        return json.loads(body)
    except Exception:
        return {}


# ------------------------- 签到 -------------------------
def do_checkin(headers, token, raw_collect):
    res = {"ok": False, "level": "info", "message": ""}
    # 1) 状态（today_checked_in 不可靠，仅参考；命中即跳过由 code=10001 兜底）
    s, b = http("POST", API_CHECKIN + "/checkin-status", headers)
    raw_collect.append(("POST /v2/billing/meter/checkin-status", s, b))
    if s in (401, 403):
        res.update(level="error", message=f"令牌失效(HTTP {s})，请重新运行 refresh_token.sh 注入最新 token")
        return res
    if s == 0:
        res.update(level="error", message="网络异常，签到未执行")
        return res
    # 2) 执行签到
    c, cb = http("POST", API_CHECKIN + "/daily-checkin", headers)
    raw_collect.append(("POST /v2/billing/meter/daily-checkin", c, cb))
    if c in (401, 403):
        res.update(level="error", message=f"令牌失效(HTTP {c})，请重新运行 refresh_token.sh 注入最新 token")
        return res
    if c == 0:
        res.update(level="error", message="网络异常，签到未执行")
        return res
    r = parse(cb)
    code = r.get("code")
    if c == 200 and code == 0:
        d = r.get("data", {}) or {}
        credit = d.get("credit", d.get("reward_credit", "?"))
        streak = d.get("streak", d.get("continuous_days", "?"))
        res.update(ok=True, message=f"签到成功，领取 {credit} 积分（连续 {streak} 天）")
        return res
    if code == 10001:  # 今日已签到（含 HTTP 400 + code=10001 的返回形态）
        res.update(ok=True, message="今日已签到（幂等跳过）")
        return res
    res.update(level="error", message=f"签到失败 HTTP {c} code={code} msg={r.get('msg', '')}")
    return res


# ------------------------- 派猫猫旅行 -------------------------
def do_travel(headers, token, raw_collect):
    res = {"ok": True, "level": "info", "message": "", "acted": False}

    def get_status():
        s, b = http("GET", API_TRAVEL + "/status", headers)
        raw_collect.append(("GET /activity/growth/buddy/travel/status", s, b))
        return s, parse(b)

    def claim(rid):
        code, rawb = http("POST", API_TRAVEL + "/claim", headers, {"record_id": rid})
        raw_collect.append(("POST /activity/growth/buddy/travel/claim", code,
                            json.dumps(parse(rawb), ensure_ascii=False)))
        if code == 200 and parse(rawb).get("code") == 0:
            return True, (parse(rawb).get("data") or {}).get("reward_credit", "?")
        return False, None

    def depart(lid):
        code, rawb = http("POST", API_TRAVEL + "/depart", headers, {"location_id": int(lid)})
        raw_collect.append(("POST /activity/growth/buddy/travel/depart", code,
                            json.dumps(parse(rawb), ensure_ascii=False)))
        return code == 200 and parse(rawb).get("code") == 0

    s, body = get_status()
    if s in (401, 403):
        res.update(ok=False, level="error", message=f"令牌失效(HTTP {s})")
        return res
    if s == 0:
        res.update(ok=False, level="error", message="网络异常")
        return res
    if s != 200:
        res.update(ok=False, level="warn", message=f"状态接口异常 HTTP {s}")
        return res

    data = body.get("data", body)
    state = data.get("state") or data.get("status") or ""
    limit = bool(data.get("daily_limit_reached"))
    record_id = data.get("record_id") or (data.get("current_record") or {}).get("id")
    loc = (os.environ.get("WB_TRAVEL_LOCATION") or "").strip() or "1"
    if not loc.isdigit():
        loc = "1"
    log(f"猫猫状态 state={state} daily_limit_reached={limit} record_id={record_id}")

    parts = []
    if state == "arrived":
        # 先领掉已到家的积分
        ok, reward = claim(record_id)
        if ok:
            parts.append(f"已领回到家积分 +{reward}")
            res["acted"] = True
            # 再判断能否派新一趟：重新查状态拿最新 daily_limit_reached
            _, body2 = get_status()
            limit2 = bool((body2.get("data", body2)).get("daily_limit_reached"))
            if not limit2:
                if depart(loc):
                    parts.append(f"已派出新一趟(地点{loc})")
                    res["acted"] = True
                else:
                    parts.append("派新一趟失败(服务端)")
            else:
                parts.append("今日已派过，不再派")
        else:
            parts.append("领回到家积分失败(服务端)")
    elif state == "idle" and not limit:
        if depart(loc):
            parts.append(f"空闲已派出(地点{loc})，预计 1~4h 后回家")
            res["acted"] = True
        else:
            parts.append("派出失败(服务端)")
    elif state == "traveling":
        parts.append("猫猫旅行中，本次不派（今天已派过）")
    elif state == "idle" and limit:
        parts.append("今日已达派出上限，明天恢复")
    else:
        parts.append(f"未知状态({state})，未动作")

    res["message"] = "；".join(parts) if parts else "无动作"
    return res


# ------------------------- 飞书 -------------------------
def push_feishu(ci, tr, token, uid):
    webhook = os.environ.get("FEISHU_WEBHOOK", "").strip()
    secret = os.environ.get("FEISHU_SECRET", "").strip()

    ci_icon = "✅" if ci["ok"] else ("⚠️" if ci["level"] == "error" else "ℹ️")
    text = "## 🐯 WorkBuddy 每日积分\n\n"
    text += f"**一、每日签到**\n\n{ci_icon} {ci['message']}\n\n"
    text += f"**二、派猫猫旅行**\n\n🐱 {tr['message']}\n\n"
    text += f"> 执行时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    text += f"> 本次成败看签到：{'成功' if ci['ok'] else '失败'}（猫猫失败不影响签到结论）"

    if not webhook:
        log("FEISHU_WEBHOOK 未设置，跳过真实推送，仅输出消息预览：")
        print("---- FEISHU MESSAGE PREVIEW ----")
        print(text)
        print("--------------------------------")
        return

    payload = {"msg_type": "markdown", "content": {"text": text}}
    if secret:
        ts = str(int(time.time()))
        sign = base64.b64encode(
            hmac.new(secret.encode("utf-8"),
                     (ts + "\n" + secret).encode("utf-8"),
                     hashlib.sha256).digest()
        ).decode("utf-8")
        payload["timestamp"] = ts
        payload["sign"] = sign

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(webhook, data=data,
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            rb = resp.read().decode("utf-8", "replace")
            rj = parse(rb)
            if rj.get("code") == 0:
                log("飞书推送成功")
            else:
                log("飞书推送返回异常: " + mask_in_text(rb, token, uid)[:300])
    except Exception as e:  # noqa: BLE001
        log("飞书推送失败: " + str(e))


# ------------------------- 脱敏原始返回 -------------------------
def dump_raw(raw_collect, token, uid):
    print("==== RAW (脱敏) ====")
    for label, st, b in raw_collect:
        print(f"[{label}] HTTP {st}")
        print(mask_in_text(b, token, uid)[:1000])
    print("=====================")


# ------------------------- main -------------------------
def main():
    token, uid, domain, entid = resolve_credentials()
    raw_collect = []

    if not token:
        # 仍推送飞书告警，提示去刷新 secret
        push_feishu(
            {"ok": False, "level": "error", "message": "未获取到 token（云端请检查 secret WORKBUDDY_TOKEN）"},
            {"ok": True, "level": "info", "message": "未执行"},
            "", uid,
        )
        sys.exit(1)

    headers = build_headers(token, uid, domain, entid)

    log("【1/2】签到开始")
    ci = do_checkin(headers, token, raw_collect)
    log("签到结论: " + ci["message"])

    log("【2/2】派猫猫旅行开始（任何失败不影响签到结论）")
    try:
        tr = do_travel(headers, token, raw_collect)
    except Exception as e:  # noqa: BLE001
        tr = {"ok": True, "level": "warn", "message": f"猫猫环节异常: {e}（不影响签到）"}
        log("猫猫环节捕获异常: " + str(e))
    log("猫猫结论: " + tr["message"])

    push_feishu(ci, tr, token, uid)

    if os.environ.get("RAW_DUMP"):
        dump_raw(raw_collect, token, uid)

    # 退出码：仅看签到是否成功
    sys.exit(0 if ci["ok"] else 1)


if __name__ == "__main__":
    main()
