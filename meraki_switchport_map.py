#!/usr/bin/env python3
"""
meraki_switchport_map.py - Which switch and port is every access point on?

The Catalyst switches are not in the Meraki dashboard, so you cannot ask the
dashboard about them directly. But every access point reports the CDP and
LLDP neighbour it hears on its uplink, and that neighbour IS the switch:
its hostname, its management address, and the exact port the AP occupies.

So the access points will tell you what the switches will not. That is how
you find a switch whose address nobody wrote down -- ask the things plugged
into it.

What this produces:

  1. Every switch discovered, with its management address and AP count.
     This is the answer to "what is SFSW21's IP".
  2. A live access point -> switch -> port map for the whole building,
     which is the thing the inherited spreadsheet only has for two floors
     and has not been accurate about since.
  3. The access point address allocation, by range.

SAFETY: same three layers as the other scripts --
  1. PREFLIGHT  - aborts unless the key's admin account is read-only
  2. SIMULATE   - SDK constructed with simulate=True; writes become no-ops
  3. READ-ONLY  - only get* methods are called

Runtime: one call per access point, so roughly N/4 seconds for N of them.

Usage:
    export MERAKI_DASHBOARD_API_KEY='...'
    python3 meraki_switchport_map.py --org-id 1586134
    python3 meraki_switchport_map.py --org-id 1586134 --floor 2
    python3 meraki_switchport_map.py --org-id 1586134 --csv ports.csv
"""

import argparse
import csv
import os
import re
import sys
import time
from collections import defaultdict

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
        print(f"    ! {label}: {type(e).__name__} {str(e)[:80]}", file=sys.stderr)
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


def floor_of(name):
    m = re.match(r"\s*sfap\s*[-_]?(\d)", str(name or ""), re.I)
    return m.group(1) if m else "?"


def neighbour(lldpcdp):
    """Pull the switch out of a device's LLDP/CDP record.

    The two protocols carry overlapping but differently-named fields, and
    which of them is populated depends on what the switch is configured to
    send. Prefer LLDP's systemName because it is the switch's configured
    hostname; fall back to CDP's deviceId, which on IOS is the hostname plus
    a domain suffix that is worth trimming.
    """
    ports = (lldpcdp or {}).get("ports") or {}
    for pname in sorted(ports):
        p = ports[pname] or {}
        lldp, cdp = p.get("lldp") or {}, p.get("cdp") or {}
        name = lldp.get("systemName") or cdp.get("deviceId") or ""
        name = str(name).split(".")[0].strip()
        port = lldp.get("portId") or cdp.get("portId") or ""
        addr = (lldp.get("managementAddress") or cdp.get("address")
                or lldp.get("chassisId") or "")
        if name or port:
            return {"switch": name, "port": str(port).strip(),
                    "addr": str(addr).strip(), "uplink": pname}
    return None


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--org-id", required=True)
    p.add_argument("--floor", help="limit the per-AP table to one floor digit")
    p.add_argument("--csv", help="also write the full map to this CSV")
    args = p.parse_args()

    key = os.environ.get("MERAKI_DASHBOARD_API_KEY")
    if not key:
        sys.exit("Set MERAKI_DASHBOARD_API_KEY first.")

    dash = meraki.DashboardAPI(api_key=key, simulate=True, wait_on_rate_limit=True,
                               maximum_retries=5, suppress_logging=True,
                               print_console=False)
    who = preflight(dash)

    devs = safe("devices", dash.organizations.getOrganizationDevices,
                args.org_id, total_pages="all", productTypes=["wireless"]) or []
    devs = [d for d in devs if d.get("serial")]
    devs.sort(key=lambda d: str(d.get("name") or d["serial"]))

    print("=" * 78)
    print("ACCESS POINT TO SWITCHPORT MAP")
    print("=" * 78)
    print(f"  key    read-only ({who})")
    print(f"  APs    {len(devs)}")
    print(f"  asking each one what it hears on its uplink...")
    print()

    rows, blind = [], []
    for i, d in enumerate(devs, 1):
        nm = d.get("name") or d["serial"]
        n = neighbour(safe(f"lldp {nm}", dash.devices.getDeviceLldpCdp, d["serial"]))
        if n is None:
            blind.append(nm)
            continue
        rows.append({"ap": nm, "ap_ip": d.get("lanIp") or "", "model": d.get("model") or "",
                     "floor": floor_of(nm), **n})
        if i % 20 == 0:
            print(f"    {i}/{len(devs)}")

    if not rows:
        sys.exit("No neighbour data at all. Either CDP and LLDP are both off on "
                 "the switches, or the access points have not been up long enough.")

    # ---------------------------------------------------------------- 1
    print()
    print("-" * 78)
    print("1. SWITCHES DISCOVERED")
    print("-" * 78)
    by_sw = defaultdict(list)
    for r in rows:
        by_sw[r["switch"] or "(unnamed)"].append(r)
    print(f"  {'switch':16} {'management IP':16} {'APs':>4}  floors  ports seen")
    for sw in sorted(by_sw):
        rs = by_sw[sw]
        addrs = sorted({r["addr"] for r in rs if r["addr"]})
        floors = sorted({r["floor"] for r in rs})
        mods = sorted({r["port"].split("/")[0] for r in rs if "/" in r["port"]})
        print(f"  {sw[:16]:16} {(addrs[0] if addrs else '-'):16} {len(rs):>4}  "
              f"{','.join(floors):6}  {','.join(mods)[:24]}")
        if len(addrs) > 1:
            print(f"  {'':16} ! reports more than one address: {', '.join(addrs)}")

    print()
    print("  'management IP' is what the switch advertises in LLDP or CDP. That")
    print("  is its own configured address, not an inference -- it is as good a")
    print("  source as the switch's running-config.")

    # ---------------------------------------------------------------- 2
    print()
    print("-" * 78)
    print("2. ACCESS POINTS")
    print("-" * 78)
    shown = [r for r in rows if not args.floor or r["floor"] == str(args.floor)]
    print(f"  {'ap':12} {'ap address':15} {'switch':12} {'port':14} model")
    for r in sorted(shown, key=lambda x: (x["switch"], x["port"])):
        print(f"  {r['ap'][:12]:12} {r['ap_ip'][:15]:15} {r['switch'][:12]:12} "
              f"{r['port'][:14]:14} {r['model']}")
    if not shown:
        print("  (none matched)")

    # ---------------------------------------------------------------- 3
    print()
    print("-" * 78)
    print("3. ACCESS POINT ADDRESSING")
    print("-" * 78)
    # Group the last octet into runs per floor, so a floor whose addresses sit
    # outside the documented blocks is obvious rather than buried in a list.
    for fl in sorted({r["floor"] for r in rows}):
        octs = []
        for r in rows:
            if r["floor"] != fl:
                continue
            m = re.match(r"(\d+\.\d+\.\d+)\.(\d+)$", r["ap_ip"] or "")
            if m:
                octs.append((m.group(1), int(m.group(2))))
        if not octs:
            print(f"  floor {fl}: no addresses reported")
            continue
        for net in sorted({o[0] for o in octs}):
            ns = sorted(n for p, n in octs if p == net)
            runs, start, prev = [], ns[0], ns[0]
            for n in ns[1:]:
                if n != prev + 1:
                    runs.append((start, prev)); start = n
                prev = n
            runs.append((start, prev))
            txt = ", ".join(f"{a}" if a == b else f"{a}-{b}" for a, b in runs)
            print(f"  floor {fl}: {net}.[{txt}]  ({len(ns)} APs)")

    if blind:
        print()
        print("-" * 78)
        print(f"4. NO NEIGHBOUR DATA ({len(blind)})")
        print("-" * 78)
        print(f"  {', '.join(sorted(blind))[:300]}")
        print()
        print("  An AP reports nothing when CDP and LLDP are both off on its")
        print("  switch port, or when it has not been up long enough to hear a")
        print("  neighbour advertisement. Not a fault on its own.")

    if args.csv:
        with open(args.csv, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["ap", "ap_ip", "model", "floor",
                                              "switch", "port", "addr", "uplink"])
            w.writeheader()
            w.writerows(rows)
        print()
        print(f"  Full map written to {args.csv}")
    print()


if __name__ == "__main__":
    main()
