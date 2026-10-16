#!/usr/bin/env python3
"""Harvest vless:// links from public GitHub repos into out/v.txt (max MAX_LINKS, one per line).

Stdlib only. Needs GITHUB_TOKEN (the Actions token is enough) for the search/tree APIs;
file bodies come from raw.githubusercontent.com, which has no API quota.
"""
import base64
import html
import json
import os
import random
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

MAX_LINKS = 20000
MAX_REPOS = int(os.environ.get("MAX_REPOS", "300"))
MAX_FILES_PER_REPO = 15
MAX_FILE_BYTES = 6_000_000
TOKEN = os.environ.get("GITHUB_TOKEN", "")
OUT = os.environ.get("OUT_DIR", "out")

# Lists the app already trusts; always harvested even if search misses them.
SEED_REPOS = [
    "zieng2/wl", "igareck/vpn-configs-for-russia", "MahanKenway/Freedom-V2Ray",
    "ebrasha/free-v2ray-public-list", "barry-far/V2ray-Config", "hamedcode/port-based-v2ray-configs",
    "Epodonios/v2ray-configs", "peasoft/NoMoreWalls", "ermaozi/get_subscribe",
    "chengaopan/AutoMergePublicNodes",
]
REPO_QUERIES = [
    "v2ray configs", "vless subscription", "free vless", "xray configs", "v2ray subscription free",
    "vless reality configs", "free proxy configs collector", "v2ray vless trojan vmess",
]
CODE_QUERIES = ["vless:// extension:txt", "vless:// extension:md", "vless:// extension:json", "vless:// extension:yaml"]
GOOD_EXT = {"txt", "md", "json", "yaml", "yml", "conf", "list", "sub", "csv", "lst", "text", "html", ""}
NAME_HINT = re.compile(r"vless|v2ray|xray|sub|config|node|proxy|free|mix|all|reality|vpn|server|link|white|black|cidr", re.I)

VLESS_RE = re.compile(
    r"vless://[A-Za-z0-9._~-]{8,64}@(?:\[[0-9a-fA-F:]+\]|[A-Za-z0-9._-]+):\d{1,5}[^\s\"'<>`\\|]*"
)
B64_RE = re.compile(r"^[A-Za-z0-9+/=_-]{200,}$")


def log(*a):
    print(*a, file=sys.stderr, flush=True)


def api(url, pause=0.0):
    """GET a GitHub API url -> parsed JSON or None. Sleeps through rate limits (up to 2 min)."""
    for _ in range(5):
        if pause:
            time.sleep(pause)
        req = urllib.request.Request(url, headers={
            "Authorization": f"Bearer {TOKEN}", "Accept": "application/vnd.github+json",
            "User-Agent": "list-collector", "X-GitHub-Api-Version": "2022-11-28"})
        try:
            with urllib.request.urlopen(req, timeout=40) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code in (403, 429):
                wait = int(e.headers.get("Retry-After") or 0)
                if not wait and e.headers.get("X-RateLimit-Remaining") == "0":
                    wait = max(0, int(e.headers.get("X-RateLimit-Reset", "0")) - int(time.time())) + 1
                wait = wait or 20
                if wait > 120:
                    return None
                time.sleep(wait)
                continue
            if e.code in (404, 409, 422, 451):
                return None
            time.sleep(3)
        except Exception:
            time.sleep(3)
    return None


def raw(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "list-collector"})
        with urllib.request.urlopen(req, timeout=40) as r:
            data = r.read(MAX_FILE_BYTES + 1)
        return data[:MAX_FILE_BYTES].decode("utf-8", "ignore")
    except Exception:
        return ""


def discover():
    """Repo full names, most promising first: seeds, then search hits by freshness."""
    since = (datetime.now(timezone.utc) - timedelta(days=21)).strftime("%Y-%m-%d")
    found = {}
    for q in REPO_QUERIES:
        for page in (1, 2):
            url = ("https://api.github.com/search/repositories?q="
                   + urllib.parse.quote(f"{q} pushed:>{since}") + f"&sort=updated&per_page=100&page={page}")
            res = api(url, pause=2.5)
            for it in (res or {}).get("items", []):
                if not it.get("fork") and not it.get("archived"):
                    found[it["full_name"]] = it.get("pushed_at", "")
    for q in CODE_QUERIES:
        for page in range(1, 6):
            url = ("https://api.github.com/search/code?q=" + urllib.parse.quote(q)
                   + f"&per_page=100&page={page}")
            res = api(url, pause=7)
            items = (res or {}).get("items", [])
            for it in items:
                found.setdefault(it["repository"]["full_name"], "")
            if len(items) < 100:
                break
    ordered = sorted(found, key=lambda r: found[r], reverse=True)
    repos = SEED_REPOS + [r for r in ordered if r not in SEED_REPOS]
    log(f"candidate repos: {len(repos)} (taking {MAX_REPOS})")
    return repos[:MAX_REPOS]


def pick_files(repo):
    info = api(f"https://api.github.com/repos/{repo}")
    if not info:
        return None, []
    branch = info.get("default_branch", "main")
    tree = api(f"https://api.github.com/repos/{repo}/git/trees/{branch}?recursive=1")
    if not tree:
        return branch, []
    cands = []
    for e in tree.get("tree", []):
        if e.get("type") != "blob" or e.get("size", 0) > MAX_FILE_BYTES or e.get("size", 0) < 40:
            continue
        name = e["path"].rsplit("/", 1)[-1]
        ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
        if ext not in GOOD_EXT:
            continue
        score = (2 if "vless" in e["path"].lower() else 0) + (1 if NAME_HINT.search(name) else 0)
        if score or ext in ("txt", "sub", "list", "lst"):
            cands.append((score, e["size"], e["path"]))
    cands.sort(reverse=True)
    return branch, [p for _, _, p in cands[:MAX_FILES_PER_REPO]]


def b64_decode(s):
    s = re.sub(r"\s+", "", s).replace("-", "+").replace("_", "/")
    try:
        return base64.b64decode(s + "=" * (-len(s) % 4)).decode("utf-8", "ignore")
    except Exception:
        return ""


def extract(text):
    text = html.unescape(text.replace("\\u0026", "&").replace("\\/", "/"))
    if "vless://" not in text:
        stripped = text.strip()
        if B64_RE.match(re.sub(r"\s+", "", stripped)):
            text = b64_decode(stripped)
        else:  # per-line base64
            text = "\n".join(b64_decode(ln) if B64_RE.match(ln.strip()) else "" for ln in text.splitlines())
    return [m.group(0).rstrip(".,;") for m in VLESS_RE.finditer(text)]


def key(link):
    m = re.match(r"vless://([^@]+)@(\[[^\]]+\]|[^:/?#]+):(\d+)", link, re.I)
    if not m:
        return None
    uid, host, port = m.group(1).lower(), m.group(2).lower(), int(m.group(3))
    return (uid, host, port) if 0 < port < 65536 else None


def harvest(repo):
    branch, files = pick_files(repo)
    links = []
    for path in files:
        body = raw(f"https://raw.githubusercontent.com/{repo}/{branch}/{path}")
        links += extract(body)
    return repo, links


def main():
    if not TOKEN:
        sys.exit("GITHUB_TOKEN is required")
    repos = discover()
    per_repo = {}
    with ThreadPoolExecutor(max_workers=8) as ex:
        for repo, links in ex.map(harvest, repos):
            seen, uniq = set(), []
            for ln in links:
                k = key(ln)
                if k and k not in seen:
                    seen.add(k)
                    uniq.append(ln)
            if uniq:
                per_repo[repo] = uniq
                log(f"{repo}: {len(uniq)}")
    # Round-robin across sources so one giant list cannot crowd out the rest.
    queues = [per_repo[r] for r in repos if r in per_repo]
    for q in queues:
        random.shuffle(q)
    out, seen = [], set()
    depth = max((len(q) for q in queues), default=0)
    for i in range(depth):
        for q in queues:
            if i < len(q):
                k = key(q[i])
                if k not in seen:
                    seen.add(k)
                    out.append(q[i])
        if len(out) >= MAX_LINKS:
            break
    out = out[:MAX_LINKS]
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "v.txt"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(out) + "\n")
    log(f"done: {len(out)} links from {len(per_repo)} repos")
    if len(out) < 50:  # a broken run must not replace a good published file
        sys.exit("too few links, refusing to publish")


if __name__ == "__main__":
    main()
