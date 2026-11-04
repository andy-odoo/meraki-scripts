#!/usr/bin/env python3
"""
meraki_fleet_churn.py - Fleet-wide wireless churn and mobility analysis.

Answers the question a single-client check cannot: is reconnection churn a
roaming problem (tracks with how many APs a client touches) or an access
point problem (clusters on specific units)?

Ranks every wireless client by disconnections per 24h alongside the number
of distinct APs used, correlates the two, tallies disconnects per AP, and
breaks results down by hardware manufacturer.

SAFETY: same three layers as the other scripts --
  1. PREFLIGHT  - aborts unless the key's admin account is read-only
  2. SIMULATE   - SDK constructed with simulate=True; writes become no-ops
  3. READ-ONLY  - only get* methods are called

Usage:
    export MERAKI_DASHBOARD_API_KEY='...'
    python3 meraki_fleet_churn.py --org-id 1586134
    python3 meraki_fleet_churn.py --org-id 1586134 --max-clients 200 --csv out.csv
    python3 meraki_fleet_churn.py --org-id 1586134 --floor 3
"""

import argparse
import csv
import os
import re
import sys
import time
from collections import Counter, defaultdict

try:
    import meraki
except ImportError:
    sys.exit("Missing SDK. Install with: pip install meraki --break-system-packages")

MAX_RPS = 4.0
RSSI_FLOOR, RSSI_CEIL = -100, -15
CHURN_THRESHOLD = 4          # disconnects per 24h worth flagging
_last = [0.0]

ASSOC_TYPES = ("assoc", "association", "connection", "roam", "reassoc")
DISC_TYPES = ("disassoc", "disassociation", "deauth", "deauthentication")


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
        print(f"    ! {label}: {type(e).__name__} {str(e)[:80]}")
        return None


def valid_rssi(v):
    return (isinstance(v, (int, float)) and not isinstance(v, bool)
            and RSSI_FLOOR <= v <= RSSI_CEIL)


def preflight(dash):
    throttle()
    me = dash.administered.getAdministeredIdentitiesMe()
    email = (me.get("email") or "").lower()
    throttle()
    orgs = dash.organizations.getOrganizations()
    bad = []
    for org in orgs:
        throttle()
        try:
            admins = dash.organizations.getOrganizationAdmins(org["id"])
        except Exception:
            continue
        for a in admins:
            if a.get("email", "").lower() == email and a.get("orgAccess") != "read-only":
                bad.append(f"{org['name']} = {a.get('orgAccess')}")
    if bad:
        print("ABORT: API key has WRITE access to: " + ", ".join(bad))
        sys.exit(1)


def hdr(t):
    print("\n" + "=" * 74)
    print(t)
    print("=" * 74)


def band_of(evt):
    b = evt.get("band")
    if b:
        return str(b)
    ch = evt.get("channel")
    if ch is None:
        return "?"
    ch = int(ch)
    return "2.4" if ch <= 14 else ("6" if ch >= 190 else "5")


def floor_of(name):
    m = re.match(r"SFAP(\d)\d{2}$", str(name or ""))
    return m.group(1) if m else "?"


def pearson(xs, ys):
    n = len(xs)
    if n < 3:
        return None
    mx, my = sum(xs) / n, sum(ys) / n
    num = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    dx = sum((x - mx) ** 2 for x in xs) ** 0.5
    dy = sum((y - my) ** 2 for y in ys) ** 0.5
    return None if dx == 0 or dy == 0 else num / (dx * dy)


def profile_client(events, apnames, hours):
    """Reduce one client's connectivity events to comparable metrics."""
    assoc = [e for e in events if e.get("type") in ASSOC_TYPES]
    seq = sorted((e for e in assoc if e.get("occurredAt")), key=lambda e: e["occurredAt"])
    aps = [e.get("deviceName") or apnames.get(e.get("deviceSerial")) or e.get("deviceSerial")
           for e in seq]
    aps = [a for a in aps if a]
    changes = sum(1 for i in range(1, len(aps)) if aps[i] != aps[i - 1])

    bands = Counter(band_of(e) for e in assoc)
    tot = sum(bands.values()) or 1
    rssis = [e["rssi"] for e in events if valid_rssi(e.get("rssi"))]
    disc = [e for e in events if e.get("type") in DISC_TYPES]
    scale = 24.0 / hours if hours else 1

    return {
        "events": len(events),
        "distinct_aps": len(set(aps)),
        "ap_changes": changes,
        "disconnects": len(disc),
        "disc_24h": round(len(disc) * scale, 1),
        "auths": sum(1 for e in events if e.get("type") in ("auth", "authentication")),
        "dhcp_fail": sum(1 for e in events if e.get("failureStep") == "dhcp"),
        "pct_24ghz": round(100 * bands.get("2.4", 0) / tot),
        "rssi_mean": round(sum(rssis) / len(rssis)) if rssis else None,
        "aps_used": aps,
        "floors": sorted({floor_of(a) for a in aps} - {"?"}),
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--org-id", required=True)
    p.add_argument("--network-id")
    p.add_argument("--timespan", type=int, default=86400)
    p.add_argument("--max-clients", type=int, default=150)
    p.add_argument("--floor", help="restrict to clients seen on this floor, e.g. 3")
    p.add_argument("--csv", help="write the full per-client table here")
    args = p.parse_args()

    key = os.environ.get("MERAKI_DASHBOARD_API_KEY")
    if not key:
        sys.exit("Set MERAKI_DASHBOARD_API_KEY first.")

    dash = meraki.DashboardAPI(api_key=key, simulate=True, wait_on_rate_limit=True,
                               maximum_retries=5, suppress_logging=True, print_console=False)
    preflight(dash)

    net_id = args.network_id
    if not net_id:
        nets = safe("networks", dash.organizations.getOrganizationNetworks,
                    args.org_id, total_pages="all") or []
        wn = [n for n in nets if "wireless" in n.get("productTypes", [])]
        if not wn:
            sys.exit("No wireless networks found.")
        net_id = wn[0]["id"]

    devs = safe("devices", dash.organizations.getOrganizationDevices,
                args.org_id, total_pages="all", productTypes=["wireless"]) or []
    apnames = {d["serial"]: d.get("name") for d in devs if d.get("name")}

    hdr("CLIENTS")
    clients = safe("clients", dash.networks.getNetworkClients, net_id,
                   total_pages="all", timespan=args.timespan, perPage=1000) or []
    wireless = [c for c in clients if c.get("ssid")]
    print(f"  {len(wireless)} wireless clients seen in the window")
    if len(wireless) > args.max_clients:
        wireless.sort(key=lambda c: c.get("lastSeen") or "", reverse=True)
        wireless = wireless[:args.max_clients]
        print(f"  analysing the {len(wireless)} most recently seen "
              f"(raise with --max-clients)")

    hours = args.timespan / 3600
    rows = []
    print(f"  pulling connectivity events ({len(wireless)} calls at {MAX_RPS}/s"
          f" \u2248 {len(wireless)/MAX_RPS:.0f}s)")
    for i, c in enumerate(wireless, 1):
        if i % 25 == 0:
            print(f"    {i}/{len(wireless)}...")
        ev = safe(f"events {c.get('mac')}",
                  dash.wireless.getNetworkWirelessClientConnectivityEvents,
                  net_id, c["id"], total_pages="all", timespan=args.timespan) or []
        if not ev:
            continue
        m = profile_client(ev, apnames, hours)
        if args.floor and args.floor not in m["floors"]:
            continue
        m["host"] = c.get("description") or "(no hostname)"
        m["mac"] = c.get("mac")
        m["mfr"] = (c.get("manufacturer") or "?")[:22]
        rows.append(m)

    if not rows:
        print("\nNo clients with connectivity events. Nothing to analyse.")
        return

    rows.sort(key=lambda r: -r["disc_24h"])

    hdr(f"RANKED BY DISCONNECTIONS ({len(rows)} clients)")
    print(f"  {'host':22} {'disc/24h':>9} {'APs':>4} {'chg':>4} {'auth':>5} "
          f"{'%2.4':>5} {'RSSI':>6} {'floor':>6}")
    print("  " + "-" * 70)
    for r in rows[:30]:
        print(f"  {r['host'][:22]:22} {r['disc_24h']:>9} {r['distinct_aps']:>4} "
              f"{r['ap_changes']:>4} {r['auths']:>5} {r['pct_24ghz']:>4}% "
              f"{str(r['rssi_mean'] or '-'):>6} {','.join(r['floors']) or '-':>6}")
    if len(rows) > 30:
        print(f"  ... {len(rows)-30} more (use --csv for the full table)")

    # ---- the key question: does churn track mobility?
    hdr("IS THIS A ROAMING PROBLEM OR AN AP PROBLEM?")
    xs = [r["distinct_aps"] for r in rows]
    ys = [r["disc_24h"] for r in rows]
    r_val = pearson(xs, ys)

    buckets = defaultdict(list)
    for r in rows:
        n = r["distinct_aps"]
        k = "1 AP" if n <= 1 else "2 APs" if n == 2 else "3-4 APs" if n <= 4 else "5+ APs"
        buckets[k].append(r["disc_24h"])
    print(f"  {'distinct APs used':20} {'clients':>8} {'mean disc/24h':>15}")
    print("  " + "-" * 46)
    for k in ("1 AP", "2 APs", "3-4 APs", "5+ APs"):
        v = buckets.get(k)
        if v:
            print(f"  {k:20} {len(v):>8} {sum(v)/len(v):>15.1f}")

    if r_val is not None:
        print(f"\n  Correlation (distinct APs vs disconnects): r = {r_val:+.2f}")
        if r_val >= 0.5:
            print("  STRONG POSITIVE - churn tracks mobility. This is a roaming")
            print("  problem: disable client balancing, enable Adaptive 802.11r,")
            print("  and raise minimum bitrates to size cells properly.")
        elif r_val >= 0.25:
            print("  MODERATE - mobility explains part of it. Check the per-AP")
            print("  table below for units contributing beyond their share.")
        else:
            print("  WEAK - churn does not track mobility. Suspect specific access")
            print("  points or specific client hardware; see the tables below.")

    # ---- per-AP disconnect concentration
    hdr("DISCONNECTIONS BY ACCESS POINT")
    ap_disc, ap_clients = Counter(), defaultdict(set)
    for r in rows:
        for a in set(r["aps_used"]):
            ap_clients[a].add(r["mac"])
        if r["aps_used"]:
            share = r["disconnects"] / len(set(r["aps_used"]))
            for a in set(r["aps_used"]):
                ap_disc[a] += share
    print(f"  {'access point':16} {'clients':>8} {'disc (apportioned)':>20} {'per client':>11}")
    print("  " + "-" * 60)
    for a, d in ap_disc.most_common(15):
        n = len(ap_clients[a]) or 1
        print(f"  {a[:16]:16} {n:>8} {d:>20.1f} {d/n:>11.1f}")
    print("\n  Apportioned means a client's disconnects are divided across the APs")
    print("  it used, since events do not attribute a drop to one unit. A single")
    print("  AP standing well above its neighbours on 'per client' is suspicious.")

    # ---- hardware breakdown
    hdr("BY MANUFACTURER")
    mfr = defaultdict(list)
    for r in rows:
        mfr[r["mfr"]].append(r["disc_24h"])
    print(f"  {'manufacturer':24} {'clients':>8} {'mean disc/24h':>15}")
    print("  " + "-" * 50)
    for m, v in sorted(mfr.items(), key=lambda kv: -sum(kv[1])/len(kv[1])):
        if len(v) >= 2:
            print(f"  {m:24} {len(v):>8} {sum(v)/len(v):>15.1f}")

    # ---- population affected
    hdr("SUMMARY")
    bad = [r for r in rows if r["disc_24h"] >= CHURN_THRESHOLD]
    print(f"  Clients analysed:                 {len(rows)}")
    print(f"  Above {CHURN_THRESHOLD} disconnects/24h:         {len(bad)} "
          f"({100*len(bad)/len(rows):.0f}%)")
    print(f"  Mean disconnects/24h, all:        {sum(ys)/len(ys):.1f}")
    if bad:
        print(f"  Mean disconnects/24h, affected:   "
              f"{sum(r['disc_24h'] for r in bad)/len(bad):.1f}")
        mob = sum(r['distinct_aps'] for r in bad)/len(bad)
        print(f"  Mean distinct APs, affected:      {mob:.1f}")
        ok = [r for r in rows if r["disc_24h"] < CHURN_THRESHOLD]
        if ok:
            print(f"  Mean distinct APs, unaffected:    "
                  f"{sum(r['distinct_aps'] for r in ok)/len(ok):.1f}")
    on24 = [r for r in rows if r["pct_24ghz"] > 0]
    print(f"  Clients touching 2.4 GHz:         {len(on24)} "
          f"({100*len(on24)/len(rows):.0f}%)")

    if args.csv:
        with open(args.csv, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["host", "mac", "manufacturer", "floors", "distinct_aps",
                        "ap_changes", "disconnects", "disc_per_24h", "auths",
                        "dhcp_failures", "pct_2.4ghz", "rssi_mean", "events"])
            for r in rows:
                w.writerow([r["host"], r["mac"], r["mfr"], "|".join(r["floors"]),
                            r["distinct_aps"], r["ap_changes"], r["disconnects"],
                            r["disc_24h"], r["auths"], r["dhcp_fail"],
                            r["pct_24ghz"], r["rssi_mean"], r["events"]])
        print(f"\n  Wrote {args.csv}")
    print()


if __name__ == "__main__":
    main()
