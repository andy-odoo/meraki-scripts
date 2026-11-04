#!/usr/bin/env python3
"""
meraki_qos_removal_impact.py - Did removing switch QoS change what users see?

READ THIS BEFORE QUOTING ANYTHING IT PRINTS.

Meraki cannot see the drops that were fixed. The 118,112,889 discards were
counters on Catalyst switch ports, and Meraki's wireless loss and latency
metrics measure the AIR interface -- frames an access point transmitted
against frames the client acknowledged. A packet discarded on the wire before
it reached the access point was never transmitted, so it never appears here.

The direct proof is on the switches: clear counters in the morning, read
`show interfaces | include output drops` in the evening. This script answers
the different question of whether the people on those floors can tell.

THE CONFOUND THAT WILL RUIN A NAIVE COMPARISON. The office emptied on 27
October and refilled this week. Fewer clients means less contention means
better numbers, with or without a QoS change -- and the reverse as people
return. So both windows default to FULL-OCCUPANCY WEEKDAYS and the empty
stretch is excluded. Section 1 checks that the two windows really are
comparable before any of the rest is worth reading.

THE PREDICTION, which is what makes this a test rather than a fishing trip.
The damage was not spread evenly:

    floor 3   17.4% loss in queue 4, 16.1% of traffic marked AF11,
              2.5% overall across 33 access-point ports   <- worst
    floor 5    3.1% lifetime, through queue 1 rather than the scavenger
              queue, because only 6.0% of its traffic was AF11
    floors 1, 2   little measured either way

If removing switch QoS is what helped, floor 3 improves most and the floors
rank in that order. If every floor improves by about the same amount,
something else changed -- occupancy, the radio work, or the weather -- and
the QoS removal is not what you are looking at. Section 4 checks the ranking.

What the core still does is unchanged by any of this: its priority queue has
dropped 59,559,422 EF/CS4/CS5 packets and its service-policy is on its own
uplink ports, untouched by `no mls qos` on an access switch. So voice should
improve PARTIALLY, not completely. If voice improves fully, the core's drops
were not reaching users. If voice does not improve at all, the core is doing
all the damage. Either answer is worth having.

SAFETY: same three layers as the other scripts --
  1. PREFLIGHT  - aborts unless the key's admin account is read-only
  2. SIMULATE   - SDK constructed with simulate=True; writes become no-ops
  3. READ-ONLY  - only get* methods are called

Usage:
    export MERAKI_DASHBOARD_API_KEY='...'
    python3 meraki_qos_removal_impact.py --org-id 1586134
    python3 meraki_qos_removal_impact.py --org-id 1586134 \
        --before 2026-10-17:2026-10-24 --after 2026-10-31:
"""

import argparse
import csv
import os
import re
import statistics
import sys
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone

try:
    from zoneinfo import ZoneInfo
except ImportError:
    sys.exit("Need Python 3.9+ for zoneinfo.")

try:
    import meraki
except ImportError:
    sys.exit("Missing SDK. Install with: pip install meraki --break-system-packages")

LOCAL = ZoneInfo("America/Los_Angeles")
BIZ_START, BIZ_END = 9, 17

# Meraki's four 802.11 access categories, and what each one tells you here.
CATEGORIES = {
    "voiceTraffic": "EF and CS4 - the core still polices these",
    "videoTraffic": "video - shared floor 3's voice queue",
    "bestEffortTraffic": "unmarked bulk - the default queue",
    "backgroundTraffic": "AF11 and CS1 - floor 3's starved scavenger queue",
}

# What each floor lost before the change, from the switch counters. Used in
# section 4 to check whether the improvement ranks the way the cause implies.
EXPECTED = {
    "3": ("worst", "17.4% in queue 4, 16.1% AF11, 2.5% across 33 AP ports"),
    "5": ("moderate", "3.1% lifetime, through queue 1 rather than queue 4"),
    "2": ("little measured", "no per-queue data captured"),
    "1": ("little measured", "5 APs, no per-queue data captured"),
}

MAX_RPS = 4.0
_last = [0.0]


def throttle():
    gap = 1.0 / MAX_RPS
    d = time.time() - _last[0]
    if d < gap:
        time.sleep(gap - d)
    _last[0] = time.time()


def safe(label, fn, *a, **kw):
    if fn is None:
        print(f"    ! {label}: endpoint not in this SDK release", file=sys.stderr)
        return None
    throttle()
    try:
        return fn(*a, **kw)
    except Exception as e:
        print(f"    ! {label}: {type(e).__name__} {str(e)[:110]}", file=sys.stderr)
        return None


def endpoint(dash, group, name):
    return getattr(getattr(dash, group, None), name, None)


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


def floor_of(name):
    m = re.match(r"\s*sfap\s*[-_]?(\d)", str(name or ""), re.I)
    return m.group(1) if m else "?"


def parse_window(spec, default_start, default_end):
    """'YYYY-MM-DD:YYYY-MM-DD', either side may be empty for the default."""
    a, _, b = (spec or "").partition(":")
    def day(s, fallback):
        if not s.strip():
            return fallback
        return datetime.strptime(s.strip(), "%Y-%m-%d").replace(tzinfo=LOCAL)
    return day(a, default_start), day(b, default_end)


def iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def biz(dt_utc):
    """Is this bucket inside a weekday business hour, locally?"""
    lt = dt_utc.astimezone(LOCAL)
    return lt.weekday() < 5 and BIZ_START <= lt.hour < BIZ_END


def parse_ts(s):
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except Exception:
        return None


def pct(x):
    return "-" if x is None else f"{x:.2f}%"


def ms(x):
    return "-" if x is None else f"{x:.1f} ms"


def delta(before, after):
    """Signed change, and whether it is an improvement (lower is better)."""
    if before is None or after is None:
        return None
    return after - before


def arrow(d, better_is_lower=True):
    if d is None:
        return ""
    if abs(d) < 1e-9:
        return "  no change"
    good = (d < 0) if better_is_lower else (d > 0)
    return "  better" if good else "  WORSE"


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--org-id", required=True)
    p.add_argument("--before", default="",
                   help="QoS-on window, YYYY-MM-DD:YYYY-MM-DD (full-occupancy weekdays)")
    p.add_argument("--after", default="",
                   help="QoS-off window, YYYY-MM-DD:YYYY-MM-DD; empty end means now")
    p.add_argument("--band", default="5", help="radio band to measure, or 'all'")
    p.add_argument("--csv", help="write the per-AP rows here")
    args = p.parse_args()

    key = os.environ.get("MERAKI_DASHBOARD_API_KEY")
    if not key:
        sys.exit("Set MERAKI_DASHBOARD_API_KEY first.")

    now = datetime.now(LOCAL)
    # Defaults: a full week of normal occupancy with QoS on, against everything
    # since the change. 27-30 October is left out of both -- the office was
    # empty and the numbers from it mean nothing.
    b0, b1 = parse_window(args.before,
                          datetime(2026, 10, 17, tzinfo=LOCAL),
                          datetime(2026, 10, 24, tzinfo=LOCAL))
    a0, a1 = parse_window(args.after,
                          datetime(2026, 10, 31, tzinfo=LOCAL),
                          now)

    dash = meraki.DashboardAPI(api_key=key, simulate=True, wait_on_rate_limit=True,
                               maximum_retries=5, suppress_logging=True,
                               print_console=False)
    print("Preflight: confirming the key is read-only ...", file=sys.stderr)
    who = preflight(dash)
    print(f"  ok, {who} is read-only everywhere\n", file=sys.stderr)

    print("=" * 78)
    print("SWITCH QoS REMOVAL - WHAT CHANGED FOR USERS")
    print(f"org {args.org_id}   read {now:%Y-%m-%d %H:%M %Z}")
    print(f"  QoS on   {b0:%a %d %b} to {b1:%a %d %b}")
    print(f"  QoS off  {a0:%a %d %b} to {a1:%a %d %b %H:%M}")
    print("  weekday business hours only, 09:00-17:00 local")
    print("=" * 78)
    print()
    print("  Meraki measures the AIR, not the wire. A packet the switch")
    print("  discarded never reached an access point and is not counted here.")
    print("  The switch counters are the direct proof; this is whether anyone")
    print("  on those floors can tell the difference.")

    # ------------------------------------------------------------ networks
    nets = safe("getOrganizationNetworks",
                endpoint(dash, "organizations", "getOrganizationNetworks"),
                args.org_id, total_pages="all") or []
    wnets = [n for n in nets if "wireless" in (n.get("productTypes") or [])]
    if not wnets:
        sys.exit("No wireless networks in this org.")
    # The floors all live in one network; a second site would be its own.
    main_net = max(wnets, key=lambda n: len(n.get("productTypes") or []))

    devs = safe("getOrganizationDevices",
                endpoint(dash, "organizations", "getOrganizationDevices"),
                args.org_id, total_pages="all") or []
    name_of, floor_by_serial = {}, {}
    for d in devs:
        if not str(d.get("model", "")).upper().startswith(("MR", "CW")):
            continue
        nm = d.get("name") or d.get("serial")
        name_of[d["serial"]] = nm
        floor_by_serial[d["serial"]] = floor_of(nm)
    floors = sorted({f for f in floor_by_serial.values() if f != "?"})
    if not floors:
        sys.exit("No access points matched the SFAP<floor> naming convention.")

    band_kw = {} if args.band == "all" else {"bands": [args.band]}

    # ---------------------------------------------------------------- 1
    print()
    print("-" * 78)
    print("1. ARE THE TWO WINDOWS COMPARABLE?")
    print("-" * 78)
    print("  Nothing below this section means anything if they are not. More")
    print("  clients make every metric worse on their own, so a busier 'after'")
    print("  that still looks better is strong evidence, and a quieter 'after'")
    print("  that looks better is no evidence at all.")
    print()

    counts = {}
    cch = endpoint(dash, "wireless", "getNetworkWirelessClientCountHistory")
    for label, (t0, t1) in (("before", (b0, b1)), ("after", (a0, a1))):
        kw = dict(t0=iso(t0), t1=iso(t1), resolution=3600)
        if args.band != "all":
            kw["band"] = args.band
        h = safe(f"client counts {label}", cch, main_net["id"], **kw) or []
        # A bucket with no readable timestamp is discarded, not assumed to be
        # in business hours -- guessing here would quietly pad whichever
        # window happened to have the malformed entries.
        vals = []
        for e in h:
            c = e.get("clientCount")
            ts = parse_ts(e.get("startTs") or e.get("startTime"))
            if c is not None and ts is not None and biz(ts):
                vals.append(c)
        counts[label] = vals

    for label in ("before", "after"):
        v = counts.get(label) or []
        if v:
            print(f"  {label:7} business-hour clients: mean {statistics.mean(v):6.1f}  "
                  f"peak {max(v):4.0f}   ({len(v)} hours sampled)")
        else:
            print(f"  {label:7} business-hour clients: no data")

    cb, ca = counts.get("before") or [], counts.get("after") or []
    if cb and ca:
        mb, ma = statistics.mean(cb), statistics.mean(ca)
        ratio = ma / mb if mb else 0
        print()
        if ratio < 0.75:
            print(f"  WARNING: the 'after' window is {(1 - ratio) * 100:.0f}% quieter.")
            print("  Any improvement below is probably the empty office, not QoS.")
            print("  Re-run once occupancy matches, and treat today as indicative.")
        elif ratio > 1.25:
            print(f"  The 'after' window is {(ratio - 1) * 100:.0f}% BUSIER. An")
            print("  improvement measured against more load is worth more, not less.")
        else:
            print(f"  Load is comparable ({ratio:.2f}x). The comparison holds.")
    if ca and len(ca) < 6:
        print()
        print(f"  Only {len(ca)} business hours of 'after' data so far. Thin.")
        print("  Run this again at the end of the day, and again on Thursday.")

    # ---------------------------------------------------------------- 2
    print()
    print("-" * 78)
    print("2. PACKET LOSS OVER THE AIR, BY FLOOR")
    print("-" * 78)
    print("  Downstream loss is frames the access point sent and the client")
    print("  never acknowledged. It does NOT include anything the switch")
    print("  discarded upstream of the access point.")
    print()

    loss_fn = endpoint(dash, "wireless",
                       "getOrganizationWirelessDevicesPacketLossByDevice")
    loss = {}
    rows = []
    for label, (t0, t1) in (("before", (b0, b1)), ("after", (a0, a1))):
        data = safe(f"packet loss {label}", loss_fn, args.org_id,
                    t0=iso(t0), t1=iso(t1), total_pages="all", **band_kw) or []
        per = defaultdict(lambda: {"sent": 0, "lost": 0})
        for e in data:
            serial = (e.get("device") or {}).get("serial") or e.get("serial")
            fl = floor_by_serial.get(serial)
            if not fl or fl == "?":
                continue
            d = e.get("downstream") or {}
            total, lost = d.get("total"), d.get("lost")
            if total is None:
                continue
            per[fl]["sent"] += total
            per[fl]["lost"] += lost or 0
            rows.append({"window": label, "floor": fl,
                         "ap": name_of.get(serial, serial), "serial": serial,
                         "downstream_total": total, "downstream_lost": lost or 0,
                         "downstream_loss_pct": round(d.get("lossPercentage") or 0, 3)})
        loss[label] = {f: (100.0 * v["lost"] / v["sent"] if v["sent"] else None)
                       for f, v in per.items()}

    print(f"  {'floor':6} {'QoS on':>10} {'QoS off':>10} {'change':>10}")
    improvements = {}
    for f in floors:
        bv, av = loss.get("before", {}).get(f), loss.get("after", {}).get(f)
        d = delta(bv, av)
        improvements[f] = d
        print(f"  {f:6} {pct(bv):>10} {pct(av):>10} "
              f"{(f'{d:+.2f} pt' if d is not None else '-'):>10}{arrow(d)}")
    if not any(v is not None for v in improvements.values()):
        print("  (no packet-loss data returned for either window)")

    # ---------------------------------------------------------------- 3
    print()
    print("-" * 78)
    print("3. LATENCY BY ACCESS CATEGORY, BY FLOOR")
    print("-" * 78)
    print("  This is the section that tests the mechanism rather than just")
    print("  looking for a number going down.")
    print()
    for cat, meaning in CATEGORIES.items():
        print(f"    {cat:20} {meaning}")
    print()

    lat_fn = endpoint(dash, "wireless", "getNetworkWirelessDevicesLatencyStats")
    lat = {}
    for label, (t0, t1) in (("before", (b0, b1)), ("after", (a0, a1))):
        # This endpoint allows at most 7 days between t0 and t1.
        s, e = t0, min(t1, t0 + timedelta(days=7))
        kw = dict(t0=iso(s), t1=iso(e))
        if args.band != "all":
            kw["band"] = args.band
        data = safe(f"latency stats {label}", lat_fn, main_net["id"], **kw) or []
        per = defaultdict(lambda: defaultdict(list))
        for entry in data:
            serial = entry.get("serial")
            fl = floor_by_serial.get(serial)
            if not fl or fl == "?":
                continue
            stats = entry.get("latencyStats") or {}
            for cat in CATEGORIES:
                avg = (stats.get(cat) or {}).get("avg")
                if avg is not None:
                    per[fl][cat].append(avg)
        lat[label] = {f: {c: (statistics.mean(v) if v else None)
                          for c, v in cats.items()} for f, cats in per.items()}

    for cat in CATEGORIES:
        any_row = False
        print(f"  {cat}")
        print(f"    {'floor':6} {'QoS on':>10} {'QoS off':>10} {'change':>11}")
        for f in floors:
            bv = (lat.get("before", {}).get(f) or {}).get(cat)
            av = (lat.get("after", {}).get(f) or {}).get(cat)
            d = delta(bv, av)
            if bv is None and av is None:
                continue
            any_row = True
            print(f"    {f:6} {ms(bv):>10} {ms(av):>10} "
                  f"{(f'{d:+.1f} ms' if d is not None else '-'):>11}{arrow(d)}")
        if not any_row:
            print("    (no data)")
        print()

    # ---------------------------------------------------------------- 4
    print("-" * 78)
    print("4. DOES THE IMPROVEMENT RANK THE WAY THE CAUSE IMPLIES?")
    print("-" * 78)
    print("  The switch damage was uneven. If removing it is what helped, the")
    print("  floors should improve in the order they were being hurt.")
    print()
    print(f"  {'floor':6} {'was hurt':16} {'air-loss change':>16}   measured before")
    ranked = []
    for f in floors:
        sev, why = EXPECTED.get(f, ("unknown", "not characterised"))
        d = improvements.get(f)
        if d is not None:
            ranked.append((d, f))
        print(f"  {f:6} {sev:16} "
              f"{(f'{d:+.2f} pt' if d is not None else '-'):>16}   {why}")
    print()
    if len(ranked) >= 2:
        ranked.sort()
        order = " then ".join(f"floor {f}" for _, f in ranked)
        print(f"  Measured order, most improved first: {order}")
        best = ranked[0][1]
        if best == "3":
            print("  Floor 3 improved most, which is what the switch counters")
            print("  predicted. That is consistent with the QoS removal being")
            print("  the cause rather than a coincidence.")
        else:
            print(f"  Floor 3 was hurt worst but floor {best} improved most.")
            print("  That does not fit the QoS explanation. Look at what else")
            print("  changed on that floor -- the radio work, or occupancy.")
        spread = ranked[-1][0] - ranked[0][0]
        if abs(spread) < 0.1:
            print()
            print("  CAUTION: every floor moved by about the same amount. A")
            print("  uniform change across floors that were damaged very")
            print("  differently is more likely occupancy or a radio change")
            print("  than the QoS removal.")

    print()
    print("-" * 78)
    print("WHAT THIS CANNOT TELL YOU")
    print("-" * 78)
    print("  Whether the switch stopped discarding. Clear counters in the")
    print("  morning and read `show interfaces | include output drops` in the")
    print("  evening; that is the only direct measurement and it is unambiguous.")
    print()
    print("  Whether the core stopped dropping voice. It has not: its")
    print("  service-policy sits on its own uplink ports and `no mls qos` on an")
    print("  access switch does not reach it. Expect voice to improve partially.")
    print("  Full improvement would mean the core's 59.5M drops were not")
    print("  reaching users; no improvement would mean the core is doing all")
    print("  the damage. Both are worth knowing and both change what to do next.")
    print()

    if args.csv and rows:
        with open(args.csv, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["window", "floor", "ap", "serial",
                                              "downstream_total", "downstream_lost",
                                              "downstream_loss_pct"])
            w.writeheader()
            w.writerows(rows)
        print(f"  {len(rows)} per-AP rows written to {args.csv}")
        print()


if __name__ == "__main__":
    main()
