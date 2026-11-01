#!/usr/bin/env python3
"""Builds Marcyrl's own threat database (known-bad URLs and hosts) as small static shard files.

Every entry is stored as a SHA-256 hash: shard = first 2 hex chars (file name), entry = next 16 hex chars.
Lookups are done by Apps Script (Code.gs) with exactly the same canonicalization as `canon_url` / `host_of` below.
Output goes to ./site (published to GitHub Pages by the workflow).
"""
import hashlib, json, os, re, sys, time, urllib.request

# ---- Sources. Enable others only after you checked their terms of use. ----
SOURCES = [
    {"name": "phishing-database-links",   "kind": "url",  "enabled": True,  "min": 100000,
     "url": "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE.txt"},
    {"name": "phishing-database-domains", "kind": "host", "enabled": True,  "min": 100000,
     "url": "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt"},
    {"name": "openphish-community",       "kind": "url",  "enabled": False, "min": 100,
     "url": "https://openphish.com/feed.txt"},
    {"name": "phishunt",                  "kind": "url",  "enabled": False, "min": 100,
     "url": "https://phishunt.io/feed.txt"},
]
OUT = "site"

def canon_url(u):
    """Same rules as normalizeUrl() in Code.gs."""
    u = u.strip()
    if not u or len(u) > 2000 or re.search(r"\s", u):
        return None
    m = re.match(r"^(https?)://([^/?#]+)([^#]*)", u, re.I)
    if not m:
        return None
    host = m.group(2).lower()
    if not re.search(r"\.[^.]", host):
        return None
    rest = m.group(3) or "/"
    if rest[0] == "?":
        rest = "/" + rest
    return m.group(1).lower() + "://" + host + rest

def host_of(canon):
    """Same rules as hostPlain() in Code.gs: no scheme, no user info, no port."""
    auth = re.match(r"^https?://([^/?#]+)", canon).group(1)
    return auth.split("@")[-1].split(":")[0]

def clean_host(h):
    h = h.strip().lower().rstrip(".")
    return h if re.fullmatch(r"[a-z0-9._-]+\.[a-z0-9-]{2,}", h) else None

def sha_parts(s):
    d = hashlib.sha256(s.encode("utf-8")).hexdigest()
    return d[:2], d[2:18]

def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "marcyrl-threat-db/1.0"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read().decode("utf-8", "replace").splitlines()

def main():
    shards = {"u": {}, "h": {}}
    stats, failed = [], 0
    for src in SOURCES:
        if not src["enabled"]:
            continue
        try:
            lines = fetch(src["url"])
            n = 0
            for line in lines:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if src["kind"] == "url":
                    c = canon_url(line)
                    if not c:
                        continue
                    k = "u"; val = c
                else:
                    h = clean_host(line)
                    if not h:
                        continue
                    k = "h"; val = h
                p, e = sha_parts(val)
                shards[k].setdefault(p, set()).add(e)
                n += 1
            if n < src["min"]:
                raise RuntimeError("only %d usable entries (expected at least %d)" % (n, src["min"]))
            stats.append({"name": src["name"], "kind": src["kind"], "entries": n})
            print("OK   %-28s %8d entries" % (src["name"], n))
        except Exception as ex:  # a broken source must never wipe the database
            failed += 1
            print("FAIL %-28s %s" % (src["name"], ex), file=sys.stderr)
    if not stats:
        sys.exit("All sources failed: keeping the previously published database.")
    if failed:
        # Partial data would silently drop protection: fail the run so the old database stays online.
        sys.exit("%d source(s) failed: not publishing a partial database." % failed)

    total = 0
    for k in ("u", "h"):
        os.makedirs(os.path.join(OUT, "db", k), exist_ok=True)
        for i in range(256):
            p = "%02x" % i
            entries = sorted(shards[k].get(p, ()))
            total += len(entries)
            with open(os.path.join(OUT, "db", k, p + ".txt"), "w") as f:
                f.write("".join(e + "\n" for e in entries))
    meta = {"updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "entries": total, "sources": stats}
    with open(os.path.join(OUT, "db", "meta.json"), "w") as f:
        json.dump(meta, f)
    with open(os.path.join(OUT, "index.html"), "w") as f:
        f.write("<!doctype html><meta charset=utf-8><title>Marcyrl threat db</title><p>Marcyrl Cybersecurity threat database. Updated: %s. Entries: %d</p>" % (meta["updated"], total))
    print("Built %d hashed entries -> %s/" % (total, OUT))

if __name__ == "__main__":
    main()
