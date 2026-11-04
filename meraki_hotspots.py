#!/usr/bin/env python3
"""
meraki_hotspots.py - How many personal hotspots are running in this building?

Every phone hotspot is an access point nobody planned around. Meraki's auto-RF
cannot plan around what it does not manage, and at close range a phone is
louder at a neighbouring laptop than the corporate AP that laptop is using:
free-space loss over six feet at 5 GHz is about 52 dB, so a phone at 13 dBm
arrives around -39 dBm while the ceiling AP arrives around -45 dBm.

They also matter as a measurement: a hotspot exists because someone gave up on
the Wi-Fi. Counting them puts a number on that.

DISCRIMINATION. Names are the weak signal -- people rename their phones. The
physics is the strong one. A phone sitting at one desk is heard LOUDLY by the
nearest AP and much more faintly by the rest, so its detections have a steep
gradient. A neighbouring building's network is heard FAINTLY by many APs with
a flat gradient. Peak level and spread carry more weight here than the SSID.

A NOTE ON BSSIDs. A locally-administered first octet (bit 0x02 set) is NOT a
malformed detection -- I wrongly filtered that family out of the area deep dive
as a firmware artifact, and daep's laptop has since been observed associating
to one of them. Here it counts as positive evidence instead: phones routinely
generate locally-administered BSSIDs for their hotspots. Only the multicast bit
(0x01) makes a BSSID genuinely impossible.

SAFETY: same three layers as the other scripts --
  1. PREFLIGHT  - aborts unless the key's admin account is read-only
  2. SIMULATE   - SDK constructed with simulate=True; writes become no-ops
  3. READ-ONLY  - only get* methods are called

Usage:
    export MERAKI_DASHBOARD_API_KEY='...'
    python3 meraki_hotspots.py --org-id 1586134
    python3 meraki_hotspots.py --org-id 1586134 --timespan 86400
    python3 meraki_hotspots.py --org-id 1586134 --all      # external nets too
    python3 meraki_hotspots.py --org-id 1586134 --fast     # skip channel checks
"""

import argparse
import os
import re
import sys
import time
from collections import defaultdict
from statistics import median

try:
    import meraki
except ImportError:
    sys.exit("Missing SDK. Install with: pip install meraki --break-system-packages")

MAX_RPS = 4.0
_last = [0.0]

# Device names people never change, and the carrier hotspot hardware.
DEVICE_HINTS = (
    r"iphone", r"\bipad\b", r"galaxy", r"\bpixel\b", r"androidap", r"\bandroid\b",
    r"\bmoto\b", r"oneplus", r"xiaomi", r"redmi", r"huawei", r"\bnokia\b",
    r"hotspot", r"\bmifi\b", r"jetpack", r"nighthawk", r"inseego", r"franklin",
    r"tether", r"\bhot spot\b", r"personal ?hotspot",
)
# "Jane's iPhone", "Bob's Phone" -- an apostrophe-s in an SSID is close to
# conclusive on its own; infrastructure SSIDs are almost never possessive.
POSSESSIVE = re.compile(r"\w['’]s\b", re.I)

# A detection this strong is inside the building, not across the street.
LOUD_SNR = 30
# One loud detection with the rest far weaker = a single device near one AP.
STEEP_SPREAD = 12

PROBABLE, POSSIBLE = 7, 4


def throttle():
    gap = 1.0 / MAX_RPS
    d = time.time() - _last[0]
    if d < gap:
        time.sleep(gap - d)
    _last[0] = time.time()


def safe(label, fn, *a, **kw):
    throttle()
    try:
        return fn(*a, **kw)
    except Exception as e:
        print(f"    ! {label}: {type(e).__name__} {str(e)[:90]}", file=sys.stderr)
        return None


def preflight(dash):
    throttle()
    me = dash.administered.getAdministeredIdentitiesMe()
    email = (me.get("email") or "").lower()
    bad = []
    throttle()
    for org in dash.organizations.getOrganizations():
        throttle()
        try:
            admins = dash.organizations.getOrganizationAdmins(org["id"])
        except Exception:
            continue
        for a in admins:
            if a.get("email", "").lower() == email and a.get("orgAccess") != "read-only":
                bad.append(f"{org['name']} = {a.get('orgAccess')}")
    if bad:
        sys.exit("ABORT: API key has WRITE access to: " + ", ".join(bad))
    return email


def snr_of(v):
    """Air Marshal reports SNR in dB -- higher is stronger, not dBm. Values at
    or above 100 (252-255 in practice) are 'no reading' sentinels, not signals."""
    if not isinstance(v, (int, float)) or isinstance(v, bool):
        return None
    v = int(v)
    v = -v if v < 0 else v
    return None if v >= 100 else v


def impossible(bssid):
    """Only the multicast bit makes a BSSID impossible -- a BSSID is by
    definition a unicast address. Locally-administered is legitimate and is
    scored as evidence below, not discarded."""
    parts = (bssid or "").split(":")
    if len(parts) != 6:
        return True
    try:
        o = [int(p, 16) for p in parts]
    except ValueError:
        return True
    return bool(o[0] & 0x01) or all(x == 0 for x in o)


def is_laa(bssid):
    try:
        return bool(int((bssid or "").split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


def band_of(chan):
    if chan is None:
        return "?"
    if 1 <= chan <= 14:
        return "2.4"
    if 32 <= chan <= 177:
        return "5"
    return "?"


def floor_of(name):
    m = re.match(r"\s*sfap\s*[-_]?(\d)", str(name or ""), re.I)
    return m.group(1) if m else "?"


def classify(name, laa, n_bssids, peak, spread, heard_by, own):
    """Returns (score, [reasons]). Explainable on purpose -- a classifier you
    cannot argue with is one you cannot correct."""
    s, why = 0, []
    low = (name or "").lower()
    if own and low in own:
        return -99, ["own SSID"]
    if any(re.search(p, low) for p in DEVICE_HINTS):
        s += 4
        why.append("device name")
    if POSSESSIVE.search(name or ""):
        s += 3
        why.append("possessive")
    if n_bssids == 1:
        s += 2
        why.append("single BSSID")
    if laa:
        s += 2
        why.append("locally-admin BSSID")
    if peak is not None and peak >= LOUD_SNR:
        s += 3
        why.append(f"loud ({peak} dB)")
    if spread is not None and spread >= STEEP_SPREAD:
        s += 2
        why.append(f"steep ({spread} dB)")
    if heard_by >= 10 and (spread or 0) < 6:
        s -= 2
        why.append("flat across many APs")
    return s, why


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--org-id", required=True)
    p.add_argument("--timespan", type=int, default=3600,
                   help="seconds of Air Marshal history (default 3600)")
    p.add_argument("--all", action="store_true",
                   help="also list the external networks, not just a count")
    p.add_argument("--fast", action="store_true",
                   help="skip the per-AP channel lookups")
    args = p.parse_args()

    key = os.environ.get("MERAKI_DASHBOARD_API_KEY")
    if not key:
        sys.exit("Set MERAKI_DASHBOARD_API_KEY first.")

    dash = meraki.DashboardAPI(api_key=key, simulate=True, wait_on_rate_limit=True,
                               maximum_retries=5, suppress_logging=True,
                               print_console=False)
    who = preflight(dash)

    nets = safe("networks", dash.organizations.getOrganizationNetworks,
                args.org_id, total_pages="all") or []
    wn = [n for n in nets if "wireless" in (n.get("productTypes") or [])]
    if not wn:
        sys.exit("No wireless network found.")
    net = wn[0]
    net_id = net["id"]

    names = {}
    for d in (safe("devices", dash.organizations.getOrganizationDevices,
                   args.org_id, total_pages="all", productTypes=["wireless"]) or []):
        names[d.get("serial")] = d.get("name") or d.get("serial")

    own = set()
    for s in (safe("ssids", dash.wireless.getNetworkWirelessSsids, net_id) or []):
        if s.get("enabled") and s.get("name"):
            own.add(s["name"].lower())

    am = safe("air marshal", dash.wireless.getNetworkWirelessAirMarshal,
              net_id, timespan=args.timespan) or []

    print("=" * 78)
    print("PERSONAL HOTSPOTS DETECTED IN THE BUILDING")
    print("=" * 78)
    print(f"  key        read-only ({who})")
    print(f"  network    {net.get('name')}")
    print(f"  window     {args.timespan/3600:.1f}h")
    print(f"  own SSIDs  {', '.join(sorted(own)) or '(none found)'}")
    print(f"  SSIDs seen {len(am)}")

    rows, dropped = [], 0
    for entry in am:
        ssid = entry.get("ssid") or "(hidden)"
        dets, chans, laa, nb = [], set(), False, 0
        for b in (entry.get("bssids") or []):
            mac = b.get("bssid")
            if impossible(mac):
                dropped += 1
                continue
            nb += 1
            if is_laa(mac):
                laa = True
            for d in (b.get("detectedBy") or []):
                v = snr_of(d.get("rssi"))
                if v is not None:
                    dets.append((v, d.get("device")))
            for c in (b.get("channels") or ([b["channel"]] if b.get("channel") else [])):
                if isinstance(c, int):
                    chans.add(c)
        for c in (entry.get("channels") or []):
            if isinstance(c, int):
                chans.add(c)
        if not dets:
            continue
        dets.sort(reverse=True)
        peak, top_serial = dets[0]
        spread = peak - int(median([v for v, _ in dets])) if len(dets) > 1 else None
        heard_by = len({s for _, s in dets})
        score, why = classify(ssid, laa, nb, peak, spread, heard_by, own)
        chan = sorted(chans)[0] if chans else None
        rows.append({"ssid": ssid, "peak": peak, "spread": spread,
                     "heard_by": heard_by, "ap": names.get(top_serial, top_serial),
                     "serial": top_serial, "chan": chan, "band": band_of(chan),
                     "score": score, "why": why, "nb": nb})

    probable = sorted([r for r in rows if r["score"] >= PROBABLE],
                      key=lambda r: -r["peak"])
    possible = sorted([r for r in rows if PROBABLE > r["score"] >= POSSIBLE],
                      key=lambda r: -r["peak"])
    external = [r for r in rows if 0 <= r["score"] < POSSIBLE]

    if dropped:
        print(f"  discarded  {dropped} BSSID(s) with the multicast bit set")

    print()
    print("-" * 78)
    print(f"1. PROBABLE PERSONAL HOTSPOTS ({len(probable)})")
    print("-" * 78)
    if probable:
        print(f"  {'ssid':26} {'band':>4} {'ch':>4} {'peak':>5} {'sprd':>5} "
              f"{'APs':>4} {'loudest AP':12} fl")
        for r in probable:
            print(f"  {r['ssid'][:26]:26} {r['band']:>4} "
                  f"{str(r['chan'] or '-'):>4} {r['peak']:>5} "
                  f"{str(r['spread'] if r['spread'] is not None else '-'):>5} "
                  f"{r['heard_by']:>4} {str(r['ap'])[:12]:12} {floor_of(r['ap'])}")
        print()
        for r in probable:
            print(f"    {r['ssid'][:26]:26} score {r['score']:>3}  "
                  f"{', '.join(r['why'])}")
    else:
        print("  None detected in this window.")

    print()
    print("-" * 78)
    print("2. BY FLOOR AND BAND")
    print("-" * 78)
    grid = defaultdict(lambda: defaultdict(int))
    for r in probable:
        grid[floor_of(r["ap"])][r["band"]] += 1
    if grid:
        print(f"  {'floor':>6} {'2.4 GHz':>8} {'5 GHz':>7} {'?':>3}  total")
        for fl in sorted(grid):
            g = grid[fl]
            tot = sum(g.values())
            print(f"  {fl:>6} {g.get('2.4',0):>8} {g.get('5',0):>7} "
                  f"{g.get('?',0):>3}  {tot}")
        print(f"  {'all':>6} {sum(g.get('2.4',0) for g in grid.values()):>8} "
              f"{sum(g.get('5',0) for g in grid.values()):>7} "
              f"{sum(g.get('?',0) for g in grid.values()):>3}  {len(probable)}")
        print()
        print("  A 2.4 GHz hotspot cannot contend with a 5 GHz client, and the")
        print("  AP 2.4 radios here appear to be switched off. Only the 5 GHz")
        print("  column can cost a corporate client airtime.")
    else:
        print("  Nothing to summarise.")

    # ---------------------------------------------------------------- 3
    fives = [r for r in probable if r["band"] == "5" and r["chan"]]
    print()
    print("-" * 78)
    print("3. CHANNEL COLLISIONS")
    print("-" * 78)
    if args.fast:
        print("  Skipped (--fast).")
    elif not fives:
        print("  No 5 GHz hotspots with a known channel - nothing can collide.")
    else:
        # Only the APs that actually hear a 5 GHz hotspot loudest are worth a
        # lookup; querying all 85 to answer a question about six of them is
        # eighty wasted calls.
        want = {r["serial"] for r in fives if r["serial"]}
        apchan = {}
        for s in sorted(want):
            st = safe(f"status {names.get(s, s)}",
                      dash.wireless.getDeviceWirelessStatus, s)
            for bss in ((st or {}).get("basicServiceSets") or []):
                if str(bss.get("band", "")).startswith("5") and bss.get("channel"):
                    apchan[s] = bss["channel"]
                    break
        print(f"  {'ssid':26} {'hotspot ch':>10} {'AP':12} {'AP ch':>6}  verdict")
        for r in fives:
            ac = apchan.get(r["serial"])
            if ac is None:
                v = "AP channel unknown"
            elif ac == r["chan"]:
                v = "SAME CHANNEL - contends for airtime"
            elif abs(ac - r["chan"]) <= 4:
                v = "adjacent - possible desense"
            else:
                v = "clear"
            print(f"  {r['ssid'][:26]:26} {r['chan']:>10} {str(r['ap'])[:12]:12} "
                  f"{str(ac or '-'):>6}  {v}")
        print()
        print("  'Same channel' is the only case that costs a nearby corporate")
        print("  client real airtime. Everything else is at most a receiver")
        print("  front-end effect, which is second-order.")

    print()
    print("-" * 78)
    print("4. THE REST")
    print("-" * 78)
    print(f"  possible hotspots (weaker evidence): {len(possible)}")
    for r in possible[:12]:
        print(f"    {r['ssid'][:26]:26} peak {r['peak']:>3} dB  "
              f"{str(r['ap'])[:12]:12} score {r['score']}  {', '.join(r['why'])}")
    print(f"  probable external networks:          {len(external)}")
    if args.all:
        for r in sorted(external, key=lambda x: -x["peak"])[:40]:
            print(f"    {r['ssid'][:26]:26} peak {r['peak']:>3} dB  "
                  f"heard by {r['heard_by']:>2} AP(s)")
    print()
    print(f"  {len(probable)} probable hotspot(s) in a {args.timespan/3600:.1f}h window.")
    print("  Each one is a user who stopped trusting the network. That number")
    print("  is worth tracking over time more than any single reading of it.")
    print()


if __name__ == "__main__":
    main()
