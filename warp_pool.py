"""Pool of fresh throw-away Cloudflare WARP accounts -> w.json, same shape the in-app generators return:
[{privKey, peer_pub, client_ipv4, client_ipv6}]. Stdlib only (X25519 below is RFC 7748)."""
import base64, datetime, json, os, sys, time, urllib.request

P = 2**255 - 19


def x25519_pub(priv: bytes) -> bytes:
    k = bytearray(priv)
    k[0] &= 248; k[31] &= 127; k[31] |= 64
    k = int.from_bytes(k, "little")
    x1, x2, z2, x3, z3, swap = 9, 1, 0, 9, 1, 0
    for t in range(254, -1, -1):
        bit = (k >> t) & 1
        if swap ^ bit:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = bit
        a, b = (x2 + z2) % P, (x2 - z2) % P
        c, d = (x3 + z3) % P, (x3 - z3) % P
        aa, bb, da, cb = a * a % P, b * b % P, d * a % P, c * b % P
        x3, z3 = (da + cb) ** 2 % P, x1 * (da - cb) ** 2 % P
        x2, z2 = aa * bb % P, (aa - bb) * (aa + 121665 * (aa - bb)) % P
    if swap:
        x2, z2 = x3, z3
    return (x2 * pow(z2, P - 2, P) % P).to_bytes(32, "little")


def register():
    priv = os.urandom(32)
    pub = base64.b64encode(x25519_pub(priv)).decode()
    body = json.dumps({"key": pub, "install_id": "", "fcm_token": "", "model": "PC", "type": "Android", "locale": "en_US",
                       "tos": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")}).encode()
    req = urllib.request.Request("https://api.cloudflareclient.com/v0a2158/reg", body, {
        "Content-Type": "application/json", "User-Agent": "okhttp/3.12.1", "CF-Client-Version": "a-6.3-2158"})
    cfg = json.load(urllib.request.urlopen(req, timeout=15))["config"]
    a = cfg["interface"]["addresses"]
    return {"privKey": base64.b64encode(priv).decode(), "peer_pub": cfg["peers"][0]["public_key"],
            "client_ipv4": a["v4"], "client_ipv6": a.get("v6")}


def build(path, n=60, minimum=10):
    """Tops the pool in `path` (the previous run's, if any) up with new accounts and keeps the newest n.
    Cloudflare throttles registrations from CI IPs, so one run alone yields only a handful."""
    try:
        pool = json.load(open(path))
    except Exception:
        pool = []
    fresh = 0
    for _ in range(25):
        if fresh >= 20:
            break
        try:
            pool.append(register())
            fresh += 1
            time.sleep(1.5)
        except Exception as e:  # rate limit / transient: back off, keep going
            print("warp skip:", e, file=sys.stderr)
            time.sleep(8)
    pool = pool[-n:]
    if len(pool) < minimum:
        raise RuntimeError(f"only {len(pool)} WARP accounts")
    json.dump(pool, open(path, "w"))
    return len(pool)


if __name__ == "__main__":  # self-check: RFC 7748 §6.1 Alice
    a = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    assert x25519_pub(a).hex() == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    print("ok")
