"""Cloud sender: sends approved Outreach drafts from GitHub Actions at 9:30 in each recipient's time zone, with the
computer off. Gmail has no scheduling API (and its Scheduled folder holds about 100 emails), so the drafts wait in
Gmail and this job sends each one at its time.

plan.enc (written by `outreach.py cloud-sync` when a batch is imported) lists each approved draft: queue id, Gmail
draft id, send time, time zone, company domain and the hash of the approved text. plan.enc and state.enc are
encrypted with the PLAN_KEY secret, so this repository shows no names, addresses, companies or text.

A draft is sent only when
  - its send time has come and it is 9:30-17:00 on a weekday where the recipient is (a late run sends it the same
    day; otherwise it waits for the next morning),
  - the draft in Gmail still hashes to the approved text (edited after approval -> held),
  - fewer than `daily_cap` emails went out in the last 24 hours (Gmail's limit is a rolling one),
  - its company has not failed the bounce guard. Bounce notices are read here, so the guard works with the Mac off:
    3+ bounces at 30%+ stops that company, and a new company gets 5 emails, then a 30-minute wait for bounces.
Outcomes go to state.enc, which the Mac reads back into its queue.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import sys
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

HERE = Path(__file__).resolve().parent
PLAN, STATE = HERE / "plan.enc", HERE / "state.enc"
OPEN, CLOSE = (9, 30), (17, 0)  # the recipient's local sending hours
GAP = 3.0  # seconds between sends: bursts with no gap made Gmail refuse after about 30
MAX_RUN = 90  # sends per run; the 15-minute clock starts the next one
GUARD_BOUNCES, GUARD_RATE = 3, 0.30  # this many bounces at this rate stops a company
LOOKAHEAD = 18 * 60  # a run stays this long for an upcoming send: the clock restarts about every 16 minutes
RAMP_TOTAL, RAMP_BURST, RAMP_WAIT = 15, 5, timedelta(minutes=30)  # a company's first emails go out in small groups


def fernet():
    from cryptography.fernet import Fernet
    return Fernet(os.environ["PLAN_KEY"].encode())


def read_enc(path: Path, default: dict) -> dict:
    return json.loads(fernet().decrypt(path.read_bytes())) if path.exists() and path.stat().st_size else default


def write_enc(path: Path, data: dict) -> None:
    path.write_bytes(fernet().encrypt(json.dumps(data).encode()))


def normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip()


def content_hash(subject: str, text: str) -> str:
    return hashlib.sha256((normalize(subject) + "\n" + normalize(text)).encode("utf-8")).hexdigest()


def plain_text(part: dict) -> str:
    if part.get("mimeType") == "text/plain" and part.get("body", {}).get("data"):
        return base64.urlsafe_b64decode(part["body"]["data"] + "==").decode("utf-8", "replace")
    for sub in part.get("parts", []) or []:
        t = plain_text(sub)
        if t:
            return t
    return ""


def gmail():
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials
    from googleapiclient.discovery import build
    data = json.loads(os.environ["GMAIL_TOKEN"])
    creds = Credentials.from_authorized_user_info(data, data.get("scopes"))
    if not creds.valid:
        creds.refresh(Request())
    return build("gmail", "v1", credentials=creds, cache_discovery=False)


def in_hours(tz: str, now: datetime) -> bool:
    local = now.astimezone(ZoneInfo(tz))
    return local.weekday() < 5 and OPEN <= (local.hour, local.minute) < CLOSE


def read_bounces(svc, state: dict) -> None:
    """Count new bounce notices by the failed address's domain."""
    seen = set(state.setdefault("seen", []))
    r = svc.users().messages().list(userId="me", q="from:mailer-daemon newer_than:14d", maxResults=200).execute()
    for m in r.get("messages", []):
        if m["id"] in seen:
            continue
        msg = svc.users().messages().get(userId="me", id=m["id"], format="metadata",
                                         metadataHeaders=["X-Failed-Recipients"]).execute()
        heads = msg.get("payload", {}).get("headers", [])
        text = " ".join(h.get("value", "") for h in heads) or msg.get("snippet", "")
        for dom in {d.lower() for d in re.findall(r"[\w.+'-]+@([\w.-]+\.\w+)", text)}:
            state.setdefault("bounces", {})[dom] = state.get("bounces", {}).get(dom, 0) + 1
        seen.add(m["id"])
    state["seen"] = sorted(seen)[-1000:]


def guard_stop(dom: str, plan: dict, state: dict, fresh: Counter) -> bool:
    if plan.get("guard_off"):
        return False
    sent0, bounced0 = plan.get("dom_stats", {}).get(dom, [0, 0])
    bounced = max(bounced0, state.get("bounces", {}).get(dom, 0))
    sent = max(sent0 + fresh[dom], bounced, 1)
    return bounced >= GUARD_BOUNCES and bounced / sent >= GUARD_RATE


def ramp_wait(dom: str, plan: dict, state: dict, fresh: Counter, now: datetime) -> bool:
    if plan.get("dom_stats", {}).get(dom, [0, 0])[0] + fresh[dom] >= RAMP_TOTAL:
        return False
    recent = sum(1 for r in state["results"].values() if r.get("dom") == dom and r.get("status") == "sent"
                 and now - datetime.fromisoformat(r["sent_at"]) < RAMP_WAIT)
    return recent >= RAMP_BURST


def set_output(more: bool) -> None:
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"more={'true' if more else 'false'}\n")


def one_pass(plan: dict, state: dict) -> tuple[int, float | None]:
    """Send everything due now. Returns (exit code, seconds until the next scheduled send, or None)."""
    from googleapiclient.errors import HttpError
    results = state["results"]
    now = datetime.now(timezone.utc)
    pending = [it for it in plan.get("items", []) if str(it["id"]) not in results]
    cap = int(plan.get("daily_cap", 400))
    synced = set(map(str, plan.get("synced_ids", [])))
    unsynced = [r for k, r in results.items() if r.get("status") == "sent" and k not in synced]
    stamps = list(plan.get("sent_recent", [])) + [r["sent_at"] for r in unsynced]
    sent_24h = sum(1 for s in stamps if now - datetime.fromisoformat(s) < timedelta(hours=24))
    fresh = Counter(r.get("dom", "") for r in unsynced)
    open_now = lambda it, at: it.get("test") or in_hours(it["tz"], at)
    due = sorted([it for it in pending if datetime.fromisoformat(it["send_at"]) <= now and open_now(it, now)],
                 key=lambda it: it["send_at"])
    print(f"{now:%H:%M:%S}Z {len(pending)} pending, {len(due)} due now; {sent_24h} sent in 24h (cap {cap})", flush=True)
    state["guarded"] = {}
    sent_now, failures, tried, trouble = 0, 0, 0, 0
    if due and now.timestamp() >= state.get("paused_until", 0):
        svc = gmail()
        read_bounces(svc, state)
        for it in due:
            dom = it.get("dom", "")
            if sent_24h >= cap or sent_now >= MAX_RUN:
                print("Cap for now reached; the rest wait for the next run")
                break
            if not it.get("test") and guard_stop(dom, plan, state, fresh):
                state["guarded"][dom] = state["guarded"].get(dom, 0) + 1
                continue
            if not it.get("test") and ramp_wait(dom, plan, state, fresh, datetime.now(timezone.utc)):
                continue
            tried += 1
            rec = {"at": datetime.now(timezone.utc).isoformat(), "dom": dom}
            try:
                msg = svc.users().drafts().get(userId="me", id=it["draft_id"], format="full").execute()["message"]
                payload = msg.get("payload", {})
                subject = next((h["value"] for h in payload.get("headers", []) if h.get("name", "").lower() == "subject"), "")
                if content_hash(subject, plain_text(payload)) != it["hash"]:
                    rec.update(status="held", why="edited in Gmail after approval")
                else:
                    svc.users().drafts().send(userId="me", body={"id": it["draft_id"]}).execute()
                    rec.update(status="sent", sent_at=datetime.now(timezone.utc).isoformat())
                    sent_now += 1
                    sent_24h += 1
                    fresh[dom] += 1
                    print(f"sent #{it['id']} at {datetime.now(timezone.utc):%H:%M:%S}Z ({sent_now} this pass)", flush=True)
                trouble = 0
            except HttpError as e:
                if e.resp.status == 404:
                    rec.update(status="cancelled", why="draft no longer in Gmail")
                elif (e.resp.status in (403, 429) and "imit" in str(e)) or (e.resp.status == 400 and "recondition" in str(e)):
                    state["paused_until"] = time.time() + 1800  # Gmail is throttling: back off, retried later
                    print(f"Gmail refused at #{it['id']} (HTTP {e.resp.status}); pausing 30 minutes")
                    break
                else:
                    failures += 1
                    rec.update(status="failed", why=str(e)[:200])
                    print(f"FAILED #{it['id']}: HTTP {e.resp.status}")
            except Exception as e:  # a network blip must never end the run: this email is retried by the next one
                trouble += 1
                print(f"#{it['id']} not sent ({type(e).__name__}); retrying later")
                if trouble >= 3:
                    break
                time.sleep(10)
                continue
            results[str(it["id"])] = rec
            write_enc(STATE, state)  # after every send, so a crash never resends
            time.sleep(GAP)
    write_enc(STATE, state)
    if state["guarded"]:
        print(f"Bounce guard is holding {sum(state['guarded'].values())} email(s)")
    later = datetime.now(timezone.utc)
    upcoming = [datetime.fromisoformat(it["send_at"]) for it in plan.get("items", []) if str(it["id"]) not in results
                and datetime.fromisoformat(it["send_at"]) > later and open_now(it, datetime.fromisoformat(it["send_at"]))]
    wait = (min(upcoming) - later).total_seconds() if upcoming else None
    return (1 if tried and failures == tried else 0), wait


def main() -> int:
    plan = read_enc(PLAN, {"items": []})
    state = read_enc(STATE, {"results": {}})
    state.setdefault("results", {})
    if os.environ.get("CHECK_TOKEN") == "true":
        print(f"Gmail sign-in OK: {gmail().users().getProfile(userId='me').execute().get('messagesTotal', '?')} messages")
    if plan.get("stopped"):
        print("Sending is stopped by the kill switch; nothing sent.")
        set_output(False)
        return 0
    started, code = time.time(), 0
    while True:  # a send time coming up before the next clock tick: stay and send it on the minute
        code, wait = one_pass(plan, state)
        if wait is None or wait > LOOKAHEAD or time.time() + wait - started > LOOKAHEAD + 120:
            break
        print(f"next send in {wait:.0f}s; waiting for it", flush=True)
        time.sleep(wait + 1)
    open_items = [it for it in plan.get("items", []) if str(it["id"]) not in state["results"]
                  and it.get("dom", "") not in state["guarded"]]
    set_output(bool(open_items))  # the 15-minute clock keeps running while anything is left to send
    return code  # a red run (and GitHub's email) when nothing could be sent


if __name__ == "__main__":
    sys.exit(main())
