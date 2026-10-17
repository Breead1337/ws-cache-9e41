"""Real-traffic liveness check: runs links through Xray and requires `GET /generate_204` -> 204 over the tunnel
(what Happ's URL-test does). Stdlib only; the Xray binary is downloaded from the XTLS release page.
Links it cannot express as an Xray outbound are returned in `unknown` so the caller can fall back to TCP."""
import io, json, os, re, socket, subprocess, sys, tempfile, time, urllib.parse, urllib.request, zipfile
from concurrent.futures import ThreadPoolExecutor

BATCH = 300
BASE_PORT = 30000
PROBE_HOST = b"connectivitycheck.gstatic.com"
PROBE_TIMEOUT = 8.0


def get_xray(workdir):
    asset = {"win32": "Xray-windows-64.zip", "linux": "Xray-linux-64.zip", "darwin": "Xray-macos-64.zip"}[
        "linux" if sys.platform.startswith("linux") else sys.platform]
    with urllib.request.urlopen(urllib.request.Request(
            f"https://github.com/XTLS/Xray-core/releases/latest/download/{asset}", headers={"User-Agent": "list-collector"}),
            timeout=120) as r:
        zipfile.ZipFile(io.BytesIO(r.read())).extractall(workdir)
    exe = os.path.join(workdir, "xray.exe" if sys.platform == "win32" else "xray")
    os.chmod(exe, 0o755)
    return exe


def outbound(link, tag):
    """vless:// link -> Xray outbound dict, or None when the transport is not supported here."""
    u = urllib.parse.urlsplit(link)
    q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
    host, port = u.hostname, u.port
    if not (u.username and host and port):
        return None
    net = {"raw": "tcp"}.get(q.get("type", "tcp"), q.get("type", "tcp"))  # `raw` is the new name of plain tcp
    sec = {"false": "none", "": "none"}.get(q.get("security", "none"), q.get("security", "none"))
    if net == "tcp" and q.get("headerType", "none") not in ("none", ""):
        return None
    if net not in ("tcp", "ws", "grpc", "httpupgrade", "xhttp", "splithttp") or sec not in ("none", "tls", "reality"):
        return None
    ss = {"network": "xhttp" if net == "splithttp" else net, "security": sec}
    path, hosth = urllib.parse.unquote(q.get("path", "/")), q.get("host", "")
    if net == "ws":
        ss["wsSettings"] = {"path": path, **({"headers": {"Host": hosth}} if hosth else {})}
    elif net == "grpc":
        ss["grpcSettings"] = {"serviceName": q.get("serviceName", ""), "multiMode": q.get("mode") == "multi"}
    elif net == "httpupgrade":
        ss["httpupgradeSettings"] = {"path": path, "host": hosth}
    elif net in ("xhttp", "splithttp"):
        ss["xhttpSettings"] = {"path": path, "host": hosth, "mode": q.get("mode", "auto")}
    if sec == "tls":
        ss["tlsSettings"] = {"serverName": q.get("sni") or hosth or host, "fingerprint": q.get("fp", "chrome"),
                             "allowInsecure": q.get("allowInsecure") in ("1", "true"),
                             **({"alpn": q["alpn"].split(",")} if q.get("alpn") else {})}
    elif sec == "reality":
        if not q.get("pbk"):
            return None
        ss["realitySettings"] = {"serverName": q.get("sni", ""), "fingerprint": q.get("fp", "chrome"), "publicKey": q["pbk"],
                                 "shortId": q.get("sid", ""), "spiderX": urllib.parse.unquote(q.get("spx", ""))}
    user = {"id": urllib.parse.unquote(u.username), "encryption": q.get("encryption", "none")}
    if q.get("flow"):
        user["flow"] = q["flow"]
    return {"tag": tag, "protocol": "vless", "streamSettings": ss,
            "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]}}


def probe(port):
    """True when the tunnel behind this local SOCKS port answers `GET /generate_204` with 204."""
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=PROBE_TIMEOUT)
        s.settimeout(PROBE_TIMEOUT)
        with s:
            s.sendall(b"\x05\x01\x00")
            if s.recv(2) != b"\x05\x00":
                return False
            s.sendall(b"\x05\x01\x00\x03" + bytes([len(PROBE_HOST)]) + PROBE_HOST + (80).to_bytes(2, "big"))
            if s.recv(10)[1:2] != b"\x00":
                return False
            s.sendall(b"GET /generate_204 HTTP/1.1\r\nHost: " + PROBE_HOST + b"\r\nConnection: close\r\n\r\n")
            return s.recv(32).startswith(b"HTTP/1.1 204")
    except Exception:
        return False


def run_batch(exe, workdir, outs, depth=0):
    """outs: [(link, outbound)] -> {link: bool}. Bisects when Xray refuses the config (one bad outbound)."""
    if not outs:
        return {}
    cfg = {"log": {"loglevel": "none"},
           "inbounds": [{"tag": f"i{i}", "listen": "127.0.0.1", "port": BASE_PORT + i, "protocol": "socks",
                         "settings": {"auth": "noauth", "udp": False}} for i in range(len(outs))],
           "outbounds": [dict(o, tag=f"o{i}") for i, (_, o) in enumerate(outs)],
           "routing": {"rules": [{"type": "field", "inboundTag": [f"i{i}"], "outboundTag": f"o{i}"} for i in range(len(outs))]}}
    path = os.path.join(workdir, f"cfg{depth}_{os.getpid()}.json")
    json.dump(cfg, open(path, "w"))
    p = subprocess.Popen([exe, "run", "-c", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        up = False
        for _ in range(40):  # up to ~10 s for the last inbound to listen
            if p.poll() is not None:
                break
            try:
                socket.create_connection(("127.0.0.1", BASE_PORT + len(outs) - 1), timeout=0.5).close()
                up = True
                break
            except OSError:
                time.sleep(0.25)
        if not up:
            if len(outs) == 1:
                return {outs[0][0]: False}
            mid = len(outs) // 2
            p.kill()
            p.wait()
            return {**run_batch(exe, workdir, outs[:mid], depth + 1), **run_batch(exe, workdir, outs[mid:], depth + 1)}
        with ThreadPoolExecutor(max_workers=len(outs)) as ex:
            res = list(ex.map(probe, [BASE_PORT + i for i in range(len(outs))]))
        return {link: ok for (link, _), ok in zip(outs, res)}
    finally:
        p.kill()
        p.wait()
        time.sleep(0.5)


def check(links, deadline, log=lambda *a: None):
    """-> (ok_set, unknown_list, checked_count). Links not reached before `deadline` are in neither set."""
    work = tempfile.mkdtemp()
    exe = get_xray(work)
    ok, unknown, built = set(), [], []
    for ln in links:
        o = outbound(ln, "x")
        (built.append((ln, o)) if o else unknown.append(ln))
    done = 0
    for i in range(0, len(built), BATCH):
        if time.time() > deadline:
            break
        res = run_batch(exe, work, built[i:i + BATCH])
        ok |= {ln for ln, good in res.items() if good}
        done += len(res)
        log(f"get check: {done}/{len(built)} done, {len(ok)} ok")
    return ok, unknown, done


if __name__ == "__main__":  # python geturl_check.py links.txt [limit]
    ls = [x.strip() for x in open(sys.argv[1], encoding="utf-8") if x.startswith("vless://")][:int(sys.argv[2]) if len(sys.argv) > 2 else 200]
    good, unk, n = check(ls, time.time() + 600, lambda *a: print(*a, file=sys.stderr))
    print(f"{len(good)} ok of {n} checked, {len(unk)} unsupported")
