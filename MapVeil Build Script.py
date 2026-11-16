#!/usr/bin/env python3
"""
MapVeil build script — compile database.yaml into an encrypted,
self-contained index.html directory.

Workflow
--------
1. Ask whether to REUSE previously queried coordinates (geo_lat/geo_lon in
   the YAML) or RE-QUERY everything from the geocoder.
2. Load database.yaml (the only supported data source) and position records:
   - Manual coordinates (lat/lon in the YAML) are AUTHORITATIVE and are
     never modified or deleted — no geocoder call is made for them.
   - Otherwise, if reusing is enabled and a matching cache entry exists
     (geo_lat/geo_lon computed for the SAME address), it is reused.
   - Otherwise the address is geocoded via public Photon (rate-limited) and
     the result is WRITTEN BACK into database.yaml as geo_lat/geo_lon +
     geo_addr, so the next build can skip the network call.
   - Unresolvable addresses are tolerated: coordinates become null and the
     record still ships (a "no map location" card in the app). Existing
     cache entries are kept on failure so a later build can retry.
3. Cache fields (geo_lat/geo_lon/geo_addr) are internal: they are stripped
   from the payload before encryption, so they never appear as fields on
   the app's cards.
4. Encrypt the JSON payload with AES-256, key = SHA-256(master password),
   CryptoJS-compatible (the browser decrypts with the same hash).
5. Inject the ciphertext into template.html and scan the output for leaked
   plaintext. Quoted base64 chunks are excluded (they are ciphertext, and
   short strings like 'ICT' occur inside them by pure chance).

YAML coordinate examples
------------------------
    # Fixed position (authoritative, never overwritten by the script):
    - name: Chania Office
      address: '37°01''32.9"N 25°23''25.4"E'
      lat: 37.02581
      lon: 25.39039

    # Geocoded position (managed by the script — do not edit by hand):
    - name: Some Supplier
      address: Musterstrasse 1, 8000 Zürich
      geo_lat: 47.3769
      geo_lon: 8.5417
      geo_addr: Musterstrasse 1, 8000 Zürich

Comment preservation: the script prefers ruamel.yaml (pip install
ruamel.yaml) in round-trip mode, which keeps your comments and formatting
intact when writing back. Without it, PyYAML is used and comments in
database.yaml WILL BE LOST (the script warns about this).

Usage
-----
    pip install -r requirement.txt
    python build.py          # prompts for cache choice + master password
"""

import base64
import getpass
import hashlib
import io
import json
import re
import sys
from pathlib import Path

import yaml
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from geopy.extra.rate_limiter import RateLimiter
from geopy.geocoders import Photon

try:
    from ruamel.yaml import YAML as RuamelYAML

    HAVE_RUAMEL = True
except ImportError:
    HAVE_RUAMEL = False

BASE_DIR = Path(__file__).resolve().parent
YAML_PATH = BASE_DIR / "database.yaml"
TEMPLATE_PATH = BASE_DIR / "MapVeil App Template.html"
OUTPUT_PATH = BASE_DIR / "MapVeil_Directory.html"

# The payload marker must appear in template.html EXACTLY ONCE — in the
# JavaScript slot where the base64 chunks are joined. Never spell it out
# in comments: str.replace() would inject the ciphertext there too.
PAYLOAD_MARKER = "__PAYLOAD_LINES__"
GEO_DELAY = 1.1  # seconds between Photon requests

COORD_KEYS = ("lat", "lon")  # user-fixed coordinates
CACHE_LAT, CACHE_LON, CACHE_ADDR = "geo_lat", "geo_lon", "geo_addr"  # geocoder cache
CACHE_KEYS = (CACHE_LAT, CACHE_LON, CACHE_ADDR)

# Quoted base64 payload chunks (>= 64 chars of the base64 alphabet).
# These are ciphertext — they cannot contain plaintext, and short
# alphanumeric strings occur inside them purely by chance, so they are
# excluded from the leak scan.
B64_CHUNK_RE = re.compile(r'"[A-Za-z0-9+/]{64,}={0,2}"')


# --------------------------------------------------------------------------- #
# YAML I/O (round-trip via ruamel if available, else PyYAML)
# --------------------------------------------------------------------------- #


def load_yaml_doc(text):
    """Parse YAML text, returning (document, backend_name)."""
    if HAVE_RUAMEL:
        yml = RuamelYAML(typ="rt")  # round-trip: keeps comments
        return yml.load(text), "ruamel"
    return yaml.safe_load(text), "pyyaml"


def dump_yaml_doc(doc, backend):
    """Serialize the document back to text, preserving comments when possible."""
    stream = io.StringIO()
    if backend == "ruamel":
        yml = RuamelYAML(typ="rt")
        yml.default_flow_style = False
        yml.dump(doc, stream)
    else:
        yaml.safe_dump(doc, stream, sort_keys=False, allow_unicode=True)
    return stream.getvalue()


# --------------------------------------------------------------------------- #
# 1. Load data
# --------------------------------------------------------------------------- #


def _check_coord_pair(rec, name, k1, k2, label, problems):
    """Validate that k1/k2 are either both absent or both numbers in range."""
    has1 = rec.get(k1) is not None
    has2 = rec.get(k2) is not None
    if has1 != has2:
        problems.append(
            f"record '{name}': '{k1}' and '{k2}' must be given together "
            f"(got {'only ' + k1 if has1 else 'only ' + k2})"
        )
        return
    if not has1:
        return
    v1, v2 = rec[k1], rec[k2]
    if not isinstance(v1, (int, float)) or not isinstance(v2, (int, float)):
        problems.append(
            f"record '{name}': '{label}' coordinates must be decimal numbers "
            f"(got {v1!r}, {v2!r})"
        )
    elif not (-90 <= v1 <= 90) or not (-180 <= v2 <= 180):
        problems.append(
            f"record '{name}': '{label}' coordinates out of range "
            f"(valid: lat -90..90, lon -180..180)"
        )


def load_data():
    """Read database.yaml. Returns (records, tag_colors, top_tags_visible,
    raw_document, backend_name)."""
    try:
        text = YAML_PATH.read_text(encoding="utf-8")
    except FileNotFoundError:
        sys.exit(
            f"ERROR: {YAML_PATH.name} not found. YAML is the only supported source format."
        )

    doc, backend = load_yaml_doc(text)

    if backend == "pyyaml":
        print(
            "WARNING: ruamel.yaml is not installed — comments and formatting in "
            "database.yaml will be lost when the geocoder writes back coordinates."
        )
        print("         Recommended: pip install ruamel.yaml")

    records_raw = doc.get("records") if isinstance(doc, dict) else None
    if not isinstance(records_raw, list) or not records_raw:
        sys.exit(
            "ERROR: database.yaml must contain a non-empty top-level 'records:' list."
        )

    settings = doc.get("settings") or {}
    tag_colors = settings.get("tag_colors") or {}
    top_tags_visible = int(settings.get("top_tags_visible", 10))

    records, problems = [], []
    for i, rec in enumerate(records_raw, 1):
        rec = dict(rec or {})
        name = str(rec.get("name") or "").strip()
        if not name:
            problems.append(f"record #{i}: missing 'name'")
            continue

        # Manual coordinates (authoritative) and cache coordinates both
        # validated; manual ones must be paired, cache ones must be sane.
        _check_coord_pair(rec, name, "lat", "lon", "manual", problems)
        _check_coord_pair(rec, name, CACHE_LAT, CACHE_LON, "cache", problems)

        records.append(rec)

    if problems:
        sys.exit("ERROR: invalid database.yaml:\n  - " + "\n  - ".join(problems))

    return records, tag_colors, top_tags_visible, doc, backend


# --------------------------------------------------------------------------- #
# 2. Positioning (manual > cache > geocoder)
# --------------------------------------------------------------------------- #


def ask_use_cache():
    """Startup prompt: reuse previously queried coordinates or start fresh?"""
    print("Coordinate lookup mode:")
    print("  - reuse : use geo_lat/geo_lon already stored in database.yaml")
    print("            (no network calls for those records)")
    print("  - fresh : query the geocoder again for every record without")
    print("            manual lat/lon, overwriting the stored cache")
    while True:
        ans = input("Reuse previously queried data? [Y/n]: ").strip().lower()
        if ans in ("", "y", "yes"):
            return True
        if ans in ("n", "no"):
            return False
        print("Please answer y or n.")


def position_records(records, use_cache):
    """
    Fill rec['lat']/rec['lon'] for every record. Priority:
      1. manual lat/lon from the YAML (never modified, never removed)
      2. cached geo_lat/geo_lon — only if reusing is on AND the stored
         geo_addr matches the current address (stale cache is re-queried)
      3. Photon geocoding — on success the cache in the YAML is updated
    Failures become None; existing cache entries are preserved so a later
    build can retry.
    """
    manual_n = sum(1 for r in records if r.get("lat") is not None)
    pool = [r for r in records if r.get("lat") is None]
    reusable = sum(
        1
        for r in pool
        if use_cache
        and isinstance(r.get(CACHE_LAT), (int, float))
        and str(r.get(CACHE_ADDR) or "").strip() == str(r.get("address") or "").strip()
        and str(r.get("address") or "").strip() != ""
    )
    print(
        f"[2/5] Positioning records: {manual_n} manual, {reusable} cached"
        f"{' (reusing)' if use_cache else ' (IGNORED — fresh query)'}, "
        f"{len(pool) - reusable} to geocode at {GEO_DELAY}s/request..."
    )

    geocode = RateLimiter(
        Photon(user_agent="mapveil-builder", timeout=50).geocode,
        min_delay_seconds=GEO_DELAY,
        max_retries=2,
        error_wait_seconds=3,
    )

    located, reused, failed = 0, 0, []

    for rec in records:
        name = rec["name"]

        # 1. Manual coordinates: authoritative — never touched, never deleted.
        if rec.get("lat") is not None:
            rec["lat"], rec["lon"] = round(float(rec["lat"]), 6), round(
                float(rec["lon"]), 6
            )
            print(f"  -> {name}: manual ({rec['lat']}, {rec['lon']})")
            continue

        address = str(rec.get("address") or "").strip()

        # 2. Cached coordinates from a previous run (same address only).
        if (
            use_cache
            and isinstance(rec.get(CACHE_LAT), (int, float))
            and address != ""
            and address == str(rec.get(CACHE_ADDR) or "").strip()
        ):
            rec["lat"] = round(float(rec[CACHE_LAT]), 6)
            rec["lon"] = round(float(rec[CACHE_LON]), 6)
            reused += 1
            print(f"  -> {name}: cached ({rec['lat']}, {rec['lon']})")
            continue

        # 3. Geocode.
        if not address:
            rec["lat"] = rec["lon"] = None
            failed.append((name, "no address given and no manual coordinates"))
            continue

        location = None
        try:
            location = geocode(address)
        except Exception as exc:
            failed.append((name, f"geocoder error: {exc.__class__.__name__}"))
            rec["lat"] = rec["lon"] = None
            continue

        if location and location.latitude is not None:
            rec["lat"] = round(location.latitude, 6)
            rec["lon"] = round(location.longitude, 6)
            # Update the cache — keyed to THIS address, so a later edit of
            # the address invalidates it automatically.
            rec[CACHE_LAT], rec[CACHE_LON], rec[CACHE_ADDR] = (
                rec["lat"],
                rec["lon"],
                address,
            )
            located += 1
            print(f"  -> {name}: geocoded ({rec['lat']}, {rec['lon']})")
        else:
            rec["lat"] = rec["lon"] = None
            # Cache left untouched: if a cached value existed it stays valid
            # for future runs once the geocoder recovers.
            failed.append((name, "address not found"))

    print(
        f"  -> {located} geocoded, {reused} reused from cache, "
        f"{manual_n} manual, {len(failed)} without coordinates"
    )
    return failed


def write_back_cache(doc, records, backend):
    """Store geo_lat/geo_lon/geo_addr for geocoded records into the YAML doc
    and write database.yaml back to disk. Manual lat/lon are not modified."""
    raw_records = doc.get("records") or []
    updated = 0
    for raw_rec, rec in zip(raw_records, records):
        for key in CACHE_KEYS:
            try:
                raw_rec.pop(key, None)  # remove stale cache first
            except (KeyError, AttributeError):
                pass
        if rec.get(CACHE_LAT) is not None:
            raw_rec[CACHE_LAT] = rec[CACHE_LAT]
            raw_rec[CACHE_LON] = rec[CACHE_LON]
            raw_rec[CACHE_ADDR] = rec[CACHE_ADDR]
            updated += 1
    YAML_PATH.write_text(dump_yaml_doc(doc, backend), encoding="utf-8")
    print(
        f"  -> {YAML_PATH.name} updated with cached coordinates for {updated} record(s)"
    )


# --------------------------------------------------------------------------- #
# 3. Encryption (CryptoJS-compatible)
# --------------------------------------------------------------------------- #


def encrypt_payload(payload_bytes, password):
    """AES-256-ECB with key = SHA-256(password); the template mirrors this."""
    key = bytes.fromhex(hashlib.sha256(password.encode("utf-8")).hexdigest())
    cipher = AES.new(key, AES.MODE_ECB)
    return base64.b64encode(cipher.encrypt(pad(payload_bytes, AES.block_size))).decode(
        "ascii"
    )


# --------------------------------------------------------------------------- #
# 4. Injection + leak scan
# --------------------------------------------------------------------------- #


def inject_payload(template_text, payload_b64, home):
    count = template_text.count(PAYLOAD_MARKER)
    if count == 0:
        sys.exit(f"ERROR: marker {PAYLOAD_MARKER} not found in template.html")
    if count > 1:
        sys.exit(
            f"ERROR: marker {PAYLOAD_MARKER} appears {count} times in template.html.\n"
            "It must appear exactly once (in the JS payload slot). Remove it from\n"
            "comments — every occurrence gets replaced with the full ciphertext."
        )

    chunks = [payload_b64[i : i + 1000] for i in range(0, len(payload_b64), 1000)]
    lines = ",\n".join(f'"{c}"' for c in chunks)

    # Home position is NOT secret: injected directly into the JS constant.
    template_text = (
        template_text.replace("__HOME_LAT__", str(home["lat"]))
        .replace("__HOME_LON__", str(home["lon"]))
        .replace("__HOME_ZOOM__", str(home["zoom"]))
    )
    return template_text.replace(PAYLOAD_MARKER, lines)


def scan_for_leaks(final_html, template_baseline, records):
    """Abort if a record string appears in the output but not in the template.

    Strings already present in the pre-injection template (CSS classes, tile
    attributions, generic UI words) are not leaks and are ignored. Quoted
    base64 payload chunks are stripped first: they are ciphertext, and random
    letter sequences inside them would trigger false positives (e.g. the tag
    'ICT' legitimately occurring by chance in base64 output).
    """
    html_for_scan = B64_CHUNK_RE.sub('""', final_html)

    leaks = []
    for rec in records:
        for field, value in rec.items():
            if value is None:
                continue
            for item in (value if isinstance(value, list) else [value]):
                text = str(item).strip()
                if len(text) < 3:
                    continue
                if text in html_for_scan and text not in template_baseline:
                    leaks.append(f"'{rec['name']}' field '{field}': {text!r}")

    if leaks:
        print("\n!!! LEAK SCAN FAILED — plaintext found in index.html:")
        for leak in leaks:
            print("  -", leak)
        OUTPUT_PATH.unlink(missing_ok=True)
        sys.exit("Build aborted. Fix the leak, then rebuild.")
    print("[4/5] Leak scan passed: no record plaintext found in the output.")


# --------------------------------------------------------------------------- #
# 5. Main
# --------------------------------------------------------------------------- #


def main():
    print("=" * 64)
    print("MapVeil builder")
    print("=" * 64)
    use_cache = ask_use_cache()

    print(f"\n[1/5] Loading {YAML_PATH.name}...")
    records, tag_colors, top_tags_visible, doc, backend = load_data()
    print(f"  -> loaded {len(records)} record(s)")

    failed_geo = position_records(records, use_cache)

    # Persist the geocoder results into database.yaml BEFORE stripping the
    # cache fields, so the next build can reuse them (possibly with reuse
    # disabled now and enabled later).
    print(f"\n[3/5] Writing geocoder cache back to {YAML_PATH.name}...")
    write_back_cache(doc, records, backend)

    # Cache fields are internal bookkeeping: strip them from the payload so
    # they never appear as fields on the app's cards.
    for rec in records:
        for key in CACHE_KEYS:
            rec.pop(key, None)

    print("[4/5] Setting master password (input hidden).")
    password = getpass.getpass("Set master password: ")
    if not password:
        sys.exit("ERROR: empty password.")
    if getpass.getpass("Confirm master password: ") != password:
        sys.exit("ERROR: passwords do not match.")

    _settings = doc.get("settings") or {}

    def _tag_list(name):
        v = _settings.get(name) or []
        if isinstance(v, str):            # tolerate a single scalar value
            v = [v]
        return [str(t).strip().lower() for t in v if str(t).strip()]
    
    payload = {
        "tagColors": tag_colors,
        "topTagsVisible": top_tags_visible,
        "tagSelect": _tag_list("tag_select"),
        "tagExclude": _tag_list("tag_exclude"),
        "records": records,
    }
    payload_b64 = encrypt_payload(
        json.dumps(payload, ensure_ascii=False).encode("utf-8"), password
    )

    home = (doc.get("settings") or {}).get("home") or {}
    home = {
        "lat": float(home.get("lat", 0.0)),
        "lon": float(home.get("lon", 0.0)),
        "zoom": int(home.get("zoom", 8)),
    }

    print("[5/5] Injecting encrypted payload and scanning for leaks...")
    template_text = TEMPLATE_PATH.read_text(encoding="utf-8")
    final_html = inject_payload(template_text, payload_b64, home)
    scan_for_leaks(final_html, template_text, records)

    OUTPUT_PATH.write_text(final_html, encoding="utf-8")

    print("Done.")
    print(f"  -> {OUTPUT_PATH.name} written ({OUTPUT_PATH.stat().st_size:,} bytes)")
    print(
        f"  -> {len(tag_colors)} explicit tag color(s), top-tags visible: {top_tags_visible}"
    )
    if failed_geo:
        print("  -> Records shown without a map location:")
        for name, reason in failed_geo:
            print(f"     * {name} ({reason})")


if __name__ == "__main__":
    main()
