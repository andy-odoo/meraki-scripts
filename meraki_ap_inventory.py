#!/usr/bin/env python3
"""
meraki_ap_inventory.py - Per-access-point inventory export.

Produces a complete per-AP record suitable for handing to a vendor: identity,
firmware, status, RF profile, actual operating channel/width/power per band,
measured utilization, and the switch port each unit is plugged into.

SAFETY: same three layers as the other scripts --
  1. PREFLIGHT  - aborts unless the key's admin account is read-only
  2. SIMULATE   - SDK constructed with simulate=True; writes become no-ops
  3. READ-ONLY  - only get* methods are called

Usage:
    export MERAKI_DASHBOARD_API_KEY='...'
    python3 meraki_ap_inventory.py --org-id 1586134 --floor 3
    python3 meraki_ap_inventory.py --org-id 1586134 --floor 3 --lldp --csv floor3_aps.csv
    python3 meraki_ap_inventory.py --org-id 1586134 --all --csv all_aps.csv

Floor is matched on the SFAP<floor><nn> naming convention. Use --name-match
for anything that does not follow it.
"""

import argparse
import csv
import os
import re
import sys
import time
from collections import Counter

try:
    import meraki
except ImportError:
    sys.exit("Missing SDK. Install with: pip install meraki --break-system-packages")

MAX_RPS = 4.0
_last = [0.0]


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
        print(f"    ! {label}: {type(e).__name__} {str(e)[:70]}")
        return None


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
    print("\n" + "=" * 78)
    print(t)
    print("=" * 78)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--org-id", required=True)
    p.add_argument("--network-id")
    p.add_argument("--floor", help="floor digit, matched against SFAP<floor><nn>")
    p.add_argument("--name-match", help="regex against AP name, instead of --floor")
    p.add_argument("--all", action="store_true", help="every wireless AP")
    p.add_argument("--lldp", action="store_true",
                   help="also resolve the switch and port each AP uplinks to (+1 call per AP)")
    p.add_argument("--timespan", type=int, default=86400)
    p.add_argument("--csv")
    p.add_argument("--band", choices=["2.4", "5"],
                   help="focus the console output on one band \u2014 use for evidence "
                        "that a band is enabled or disabled on a set of APs")
    args = p.parse_args()

    if not (args.floor or args.name_match or args.all):
        sys.exit("Specify --floor, --name-match, or --all.")

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

    # ---- bulk pulls: five calls total regardless of AP count
    devs = safe("devices", dash.organizations.getOrganizationDevices,
                args.org_id, total_pages="all", productTypes=["wireless"]) or []
    stats = safe("statuses", dash.organizations.getOrganizationDevicesStatuses,
                 args.org_id, total_pages="all", productTypes=["wireless"]) or []
    eth = safe("ethernet", dash.wireless.getOrganizationWirelessDevicesEthernetStatuses,
               args.org_id, total_pages="all") or []
    util = safe("utilization",
                dash.wireless.getOrganizationWirelessDevicesChannelUtilizationByDevice,
                args.org_id, total_pages="all", timespan=args.timespan) or []
    profs = safe("rf profiles", dash.wireless.getNetworkWirelessRfProfiles, net_id) or []

    smap = {s["serial"]: s for s in stats}
    emap = {e.get("serial"): e for e in eth}
    umap = {u["serial"]: u for u in util}
    pmap = {str(p["id"]): p["name"] for p in profs}

    # ---- select the APs in scope
    if args.all:
        sel = devs
        scope = "all access points"
    elif args.name_match:
        rx = re.compile(args.name_match, re.I)
        sel = [d for d in devs if rx.search(d.get("name") or "")]
        scope = f"name matching /{args.name_match}/"
    else:
        rx = re.compile(rf"SFAP{args.floor}\d{{2}}$", re.I)
        sel = [d for d in devs if rx.match((d.get("name") or "").strip())]
        scope = f"floor {args.floor}"

    sel.sort(key=lambda d: (d.get("name") or "zzz"))
    hdr(f"AP INVENTORY \u2014 {scope}  ({len(sel)} of {len(devs)} access points)")
    if not sel:
        print("  Nothing matched. Check the naming convention with --all.")
        return

    per_ap = 2 + (1 if args.lldp else 0)
    print(f"  pulling per-AP detail ({len(sel)*per_ap} calls at {MAX_RPS}/s"
          f" \u2248 {len(sel)*per_ap/MAX_RPS:.0f}s)")

    rows = []
    for i, d in enumerate(sel, 1):
        if i % 10 == 0:
            print(f"    {i}/{len(sel)}...")
        ser = d["serial"]
        st = smap.get(ser, {})
        e = emap.get(ser, {})
        u = umap.get(ser, {})

        radio = safe(f"radio {ser}", dash.wireless.getDeviceWirelessRadioSettings, ser) or {}
        status = safe(f"status {ser}", dash.wireless.getDeviceWirelessStatus, ser) or {}

        # actual operating channel per band, from the live BSS list
        bss = status.get("basicServiceSets") or []
        live = {}
        for b in bss:
            if not b.get("enabled"):
                continue
            band = str(b.get("band", "")).replace(" GHz", "").strip()
            if band and band not in live:
                live[band] = b

        def band_cell(bnd, field):
            return (live.get(bnd) or {}).get(field) or "-"

        ub = {x.get("band"): x for x in (u.get("byBand") or [])}

        def band_util(bnd):
            v = ((ub.get(bnd) or {}).get("total") or {}).get("percentage")
            return f"{v:.1f}" if isinstance(v, (int, float)) else "-"

        r = {
            "name": d.get("name") or "",
            "serial": ser,
            "model": d.get("model") or "",
            "mac": d.get("mac") or "",
            "lan_ip": d.get("lanIp") or "",
            "firmware": d.get("firmware") or "",
            "status": st.get("status") or "",
            "last_reported": (st.get("lastReportedAt") or "")[:19],
            "public_ip": st.get("publicIp") or "",
            "rf_profile": pmap.get(str(radio.get("rfProfileId")), radio.get("rfProfileId") or ""),
            "ch_2g": band_cell("2.4", "channel"),
            "width_2g": band_cell("2.4", "channelWidth"),
            "power_2g": band_cell("2.4", "power"),
            "ch_5g": band_cell("5", "channel"),
            "width_5g": band_cell("5", "channelWidth"),
            "power_5g": band_cell("5", "power"),
            "util_2g": band_util("2.4"),
            "util_5g": band_util("5"),
            "link_speed": e.get("speed") or "",
            "poe_standard": ((e.get("power") or {}).get("ac") or {}).get("isConnected", ""),
            "tags": " ".join(d.get("tags") or []),
            "notes": (d.get("notes") or "").replace("\n", " ")[:60],
            "switch": "", "switch_port": "",
        }

        if args.lldp:
            l = safe(f"lldp {ser}", dash.devices.getDeviceLldpCdp, ser) or {}
            for _, per_port in (l.get("ports") or {}).items():
                nb = per_port.get("lldp") or per_port.get("cdp") or {}
                r["switch"] = nb.get("systemName") or nb.get("deviceId") or ""
                r["switch_port"] = nb.get("portId") or nb.get("portDescription") or ""
                if r["switch"]:
                    break

        rows.append(r)

    # ---- band-focused output, for demonstrating whether a band is active
    if args.band:
        b = args.band
        chk, pwk, utk = (f"ch_{'2g' if b=='2.4' else '5g'}",
                         f"power_{'2g' if b=='2.4' else '5g'}",
                         f"util_{'2g' if b=='2.4' else '5g'}")
        active = [r for r in rows if r[chk] not in ("-", "", None)]
        inactive = [r for r in rows if r not in active]
        print(f"\n  {b} GHz RADIO STATE \u2014 {scope}")
        print(f"  {'name':12} {'serial':16} {'status':9} {'channel':>8} "
              f"{'power':>9} {'util':>7}  {'rf profile':28}")
        print("  " + "-" * 96)
        for r in sorted(rows, key=lambda x: x["name"]):
            state = str(r[chk]) if r[chk] not in ("-", "", None) else "DISABLED"
            print(f"  {r['name'][:12]:12} {r['serial']:16} {r['status'][:9]:9} "
                  f"{state:>8} {str(r[pwk]):>9} {str(r[utk]):>6}% {r['rf_profile'][:28]:28}")
        print("\n  " + "=" * 70)
        print(f"  {len(active)} of {len(rows)} access points have an ACTIVE {b} GHz radio")
        if inactive:
            print(f"  {len(inactive)} report no {b} GHz radio: "
                  + ", ".join(r["name"] for r in inactive[:8]))
        chans = Counter(str(r[chk]) for r in active)
        print(f"  channel assignment: " +
              ", ".join(f"ch {c}: {n} APs" for c, n in sorted(chans.items(),
                        key=lambda kv: int(kv[0]) if kv[0].isdigit() else 999)))
        u = [float(r[utk]) for r in active if r[utk] not in ("-", "", None)]
        if u:
            print(f"  utilization: mean {sum(u)/len(u):.1f}%  max {max(u):.1f}%  "
                  f">30%: {sum(1 for x in u if x>30)}  >50%: {sum(1 for x in u if x>50)}")
        print("  " + "=" * 70)
        if args.csv:
            _write_csv(rows, args.csv)
            print(f"\n  Wrote {args.csv} ({len(rows)} access points)\n")
        return

    # ---- console summary
    print(f"\n  {'name':12} {'serial':16} {'model':8} {'status':8} "
          f"{'5G ch':>6} {'5G w':>5} {'pwr':>4} {'u5':>5} {'u2.4':>5} {'profile':22}")
    print("  " + "-" * 105)
    for r in rows:
        print(f"  {r['name'][:12]:12} {r['serial']:16} {r['model'][:8]:8} "
              f"{r['status'][:8]:8} {str(r['ch_5g']):>6} {str(r['width_5g']):>5} "
              f"{str(r['power_5g']):>4} {r['util_5g']:>5} {r['util_2g']:>5} "
              f"{r['rf_profile'][:22]:22}")

    if args.lldp and any(r["switch"] for r in rows):
        print(f"\n  {'name':12} {'lan ip':16} {'switch':24} {'port':12} {'link':8}")
        print("  " + "-" * 76)
        for r in rows:
            print(f"  {r['name'][:12]:12} {r['lan_ip']:16} {r['switch'][:24]:24} "
                  f"{str(r['switch_port'])[:12]:12} {str(r['link_speed']):8}")

    # ---- rollups
    hdr("SUMMARY")
    print("  status:   ", dict(Counter(r["status"] for r in rows)))
    print("  model:    ", dict(Counter(r["model"] for r in rows)))
    print("  firmware: ", dict(Counter(r["firmware"] for r in rows)))
    print("  profile:  ", dict(Counter(r["rf_profile"] for r in rows)))
    ch5 = Counter(str(r["ch_5g"]) for r in rows if r["ch_5g"] != "-")
    ch2 = Counter(str(r["ch_2g"]) for r in rows if r["ch_2g"] != "-")
    print("\n  5 GHz channel plan:  ", dict(sorted(ch5.items(), key=lambda kv: -kv[1])))
    print("  2.4 GHz channel plan:", dict(sorted(ch2.items(), key=lambda kv: -kv[1])))
    reuse = [c for c, n in ch5.items() if n > 1]
    if reuse:
        print(f"\n  5 GHz channels carrying more than one AP: {', '.join(sorted(reuse))}")
    u5 = [float(r["util_5g"]) for r in rows if r["util_5g"] != "-"]
    u2 = [float(r["util_2g"]) for r in rows if r["util_2g"] != "-"]
    if u5:
        print(f"\n  5 GHz utilization:   mean {sum(u5)/len(u5):.1f}%  max {max(u5):.1f}%")
    if u2:
        print(f"  2.4 GHz utilization: mean {sum(u2)/len(u2):.1f}%  max {max(u2):.1f}%")

    if args.csv:
        _write_csv(rows, args.csv)
        print(f"\n  Wrote {args.csv} ({len(rows)} access points)")
    print()


def _write_csv(rows, path):
    cols = ["name", "serial", "model", "mac", "lan_ip", "firmware", "status",
            "last_reported", "rf_profile", "ch_2g", "width_2g", "power_2g",
            "ch_5g", "width_5g", "power_5g", "util_2g", "util_5g",
            "switch", "switch_port", "link_speed", "tags", "notes"]
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


if __name__ == "__main__":
    main()
