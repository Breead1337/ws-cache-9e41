"""Real-traffic liveness check: runs links through Xray and requires `GET /generate_204` -> 204 over the tunnel
(what Happ's URL-test does). Stdlib only; the Xray binary is downloaded from the XTLS release page.
Links it cannot express as an Xray outbound are returned in `unknown` so the caller can fall back to TCP."""
import io, json, os, re, socket, subprocess, sys, tempfile, time, urllib.parse, urllib.request, zipfile
from concurrent.futures import ThreadPoolExecutor

BATCH = 200
BASE_PORT = 30000
PROBE_HOST = b"connectivitycheck.gstatic.com"
PROBE_TIMEOUT = 12.0
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
PBK_RE = re.compile(r"^[A-Za-z0-9_-]{43}=?$")
SID_RE = re.compile(r"^(?:[0-9a-fA-F]{2}){0,8}$")
FP = {"chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized"}


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
    # Xray refuses the WHOLE config over one malformed outbound, so anything it would reject is filtered here.
    if not UUID_RE.match(urllib.parse.unquote(u.username)) or q.get("flow", "") not in ("", "xtls-rprx-vision"):
        return None
    if q.get("encryption", "none") != "none":
        return None
    if q.get("allowInsecure") in ("1", "true"):  # Xray removed allowInsecure and rejects the whole config over it: not testable here
        return None
    if q.get("fp", "chrome") not in FP:
        q["fp"] = "chrome"
    if q.get("security") == "reality" and ({"raw": "tcp"}.get(q.get("type", "tcp"), q.get("type", "tcp")) not in ("tcp", "xhttp", "grpc")
                                           or not (PBK_RE.match(q.get("pbk", "")) and SID_RE.match(q.get("sid", "")))):
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
        ss["xhttpSettings"] = {"path": path, "host": hosth, "mode": q["mode"] if q.get("mode") in ("auto", "packet-up", "stream-up", "stream-one") else "auto"}
    if sec == "tls":
        ss["tlsSettings"] = {"serverName": q.get("sni") or hosth or host, "fingerprint": q.get("fp", "chrome"),
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
        for _ in range(40):  # Xray brings hundreds of inbounds up in no fixed order and resets early connections
            try:
                s = socket.create_connection(("127.0.0.1", port), timeout=PROBE_TIMEOUT)
                s.settimeout(PROBE_TIMEOUT)
                s.sendall(b"\x05\x01\x00")
                if s.recv(2) == b"\x05\x00":
                    break
                s.close()
            except (ConnectionRefusedError, ConnectionResetError):
                pass
            time.sleep(0.5)
        else:
            return False
        with s:
            s.sendall(b"\x05\x01\x00\x03" + bytes([len(PROBE_HOST)]) + PROBE_HOST + (80).to_bytes(2, "big"))
            if s.recv(10)[1:2] != b"\x00":
                return False
            s.sendall(b"GET /generate_204 HTTP/1.1\r\nHost: " + PROBE_HOST + b"\r\nConnection: close\r\n\r\n")
            return s.recv(32).startswith(b"HTTP/1.1 204")
    except Exception as e:
        WHY[type(e).__name__] = WHY.get(type(e).__name__, 0) + 1
        return False


WHY = {}  # failure reasons of probe(), for diagnostics only


def build_cfg(outs):
    return {"log": {"loglevel": "none"},
            "inbounds": [{"tag": f"i{i}", "listen": "127.0.0.1", "port": BASE_PORT + i, "protocol": "socks",
                          "settings": {"auth": "noauth", "udp": False}} for i in range(len(outs))],
            "outbounds": [dict(o, tag=f"o{i}") for i, (_, o) in enumerate(outs)],
            "routing": {"rules": [{"type": "field", "inboundTag": [f"i{i}"], "outboundTag": f"o{i}"} for i in range(len(outs))]}}


def loads(exe, workdir, outs):
    """True when Xray accepts the config (`run -test` only parses it: fast, nothing is bound)."""
    path = os.path.join(workdir, f"t_{os.getpid()}.json")
    json.dump(build_cfg(outs), open(path, "w"))
    return subprocess.run([exe, "run", "-test", "-c", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def accepted(exe, workdir, outs):
    """Xray rejects the WHOLE config over one bad outbound: bisect with `-test` to drop only the bad ones."""
    if not outs or loads(exe, workdir, outs):
        return list(outs), []
    if len(outs) == 1:
        return [], list(outs)
    mid = len(outs) // 2
    a, ra = accepted(exe, workdir, outs[:mid])
    b, rb = accepted(exe, workdir, outs[mid:])
    return a + b, ra + rb


def run_batch(exe, workdir, outs):
    """outs: [(link, outbound)] -> {link: bool}. Outbounds Xray refuses to load count as failed-to-test (False)."""
    good, rejected = accepted(exe, workdir, outs)
    res = {ln: False for ln, _ in rejected}
    if not good:
        return res
    path = os.path.join(workdir, f"cfg_{os.getpid()}.json")
    json.dump(build_cfg(good), open(path, "w"))
    p = subprocess.Popen([exe, "run", "-c", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(60):  # up to ~15 s for the last inbound to listen
            if p.poll() is not None:
                return {**res, **{ln: False for ln, _ in good}}
            try:
                socket.create_connection(("127.0.0.1", BASE_PORT + len(good) - 1), timeout=0.5).close()
                break
            except OSError:
                time.sleep(0.25)
        with ThreadPoolExecutor(max_workers=len(good)) as ex:
            probed = list(ex.map(probe, [BASE_PORT + i for i in range(len(good))]))
        return {**res, **{ln: ok for (ln, _), ok in zip(good, probed)}}
    finally:
        p.kill()
        p.wait()
        time.sleep(0.5)


def check(links, deadline, log=lambda *a: None):
    """-> (ok_set, failed_set, unknown_list, checked_count). Links not reached before `deadline` are in neither set."""
    work = tempfile.mkdtemp()
    exe = get_xray(work)
    ok, failed, unknown, built = set(), set(), [], []
    for ln in links:
        o = outbound(ln, "x")
        (built.append((ln, o)) if o else unknown.append(ln))
    done = 0
    for i in range(0, len(built), BATCH):
        if time.time() > deadline:
            break
        res = run_batch(exe, work, built[i:i + BATCH])
        ok |= {ln for ln, good in res.items() if good}
        failed |= {ln for ln, good in res.items() if not good}
        done += len(res)
        log(f"get check: {done}/{len(built)} done, {len(ok)} ok")
    return ok, failed, unknown, done


if __name__ == "__main__":  # python geturl_check.py links.txt [limit]
    ls = [x.strip() for x in open(sys.argv[1], encoding="utf-8") if x.startswith("vless://")][:int(sys.argv[2]) if len(sys.argv) > 2 else 200]
    good, bad, unk, n = check(ls, time.time() + 600, lambda *a: print(*a, file=sys.stderr))
    print(f"{len(good)} ok of {n} checked, {len(unk)} unsupported")
