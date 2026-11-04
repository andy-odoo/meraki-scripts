#!/usr/bin/env python3
"""
meraki_find_switches.py - Discover non-Meraki switches via LLDP/CDP from the APs.

Catalyst switches are not in the Meraki inventory, but every Meraki AP hears
its upstream switch over LLDP and CDP. Both protocols carry the neighbour's
management address, so the APs collectively map the whole access layer:
switch name, management IP, platform, and which AP sits on which port.

SAFETY: same three layers as the other scripts --
  1. PREFLIGHT  - aborts unless the key's admin account is read-only
  2. SIMULATE   - SDK constructed with simulate=True; writes become no-ops
  3. READ-ONLY  - only get* methods are called

Usage:
    export MERAKI_DASHBOARD_API_KEY='...'
    python3 meraki_find_switches.py --org-id 1586134
    python3 meraki_find_switches.py --org-id 1586134 --csv switches.csv --ports ports.csv
    python3 meraki_find_switches.py --org-id 1586134 --ssh-config > ~/.ssh/config.switches
"""

import argparse
import csv
import ipaddress
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
        print(f"    ! {label}: {type(e).__name__} {str(e)[:70]}", file=sys.stderr)
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
        sys.exit("ABORT: API key has WRITE access to: " + ", ".join(bad))


def is_ip(s):
    try:
        ipaddress.ip_address(str(s))
        return True
    except ValueError:
        return False


def harvest(entry):
    """Pull (name, mgmt_ip, platform, port) out of one port's lldp/cdp block.
    Field names differ between the two protocols and across firmware, so try
    every plausible key rather than assuming one shape."""
    out = []
    for proto in ("cdp", "lldp"):
        d = entry.get(proto)
        if not isinstance(d, dict):
            continue
        name = (d.get("deviceId") or d.get("systemName")
                or d.get("chassisId") or "")
        ip = ""
        for k in ("address", "managementAddress", "mgmtAddress",
                  "managementAddresses", "ip"):
            v = d.get(k)
            if isinstance(v, list):
                v = next((x for x in v if is_ip(x)), None)
            if v and is_ip(v):
                ip = str(v)
                break
        port = d.get("portId") or d.get("portDescription") or ""
        plat = d.get("platform") or d.get("systemDescription") or ""
        if name or ip:
            out.append((proto, str(name), ip, str(plat)[:60], str(port)))
    return out


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--org-id", required=True)
    p.add_argument("--csv", help="write the switch inventory here")
    p.add_argument("--ports", help="write the AP-to-port mapping here")
    p.add_argument("--ssh-config", action="store_true",
                   help="emit an ~/.ssh/config fragment on stdout and nothing else")
    p.add_argument("--user", default="admin", help="username for --ssh-config")
    args = p.parse_args()

    key = os.environ.get("MERAKI_DASHBOARD_API_KEY")
    if not key:
        sys.exit("Set MERAKI_DASHBOARD_API_KEY first.")

    log = (lambda *a, **k: print(*a, file=sys.stderr)) if args.ssh_config else print

    dash = meraki.DashboardAPI(api_key=key, simulate=True, wait_on_rate_limit=True,
                               maximum_retries=5, suppress_logging=True,
                               print_console=False)
    preflight(dash)

    devs = safe("devices", dash.organizations.getOrganizationDevices,
                args.org_id, total_pages="all") or []
    # Meraki switches appear in the inventory directly; everything else has to
    # be discovered through its neighbours.
    meraki_sw = [d for d in devs if (d.get("model") or "").upper().startswith("MS")]
    probes = [d for d in devs if d.get("lanIp")]

    log(f"  {len(devs)} Meraki devices in the org")
    log(f"  {len(meraki_sw)} are Meraki switches (MS series)")
    log(f"  probing {len(probes)} devices for LLDP/CDP neighbours "
        f"(~{len(probes)/MAX_RPS:.0f}s)")

    switches = defaultdict(lambda: {"ips": set(), "platforms": set(),
                                    "protos": set(), "links": []})
    for i, d in enumerate(probes, 1):
        if i % 25 == 0:
            log(f"    {i}/{len(probes)}...")
        res = safe(f"lldp {d['serial']}", dash.devices.getDeviceLldpCdp, d["serial"])
        if not res:
            continue
        for local_port, entry in (res.get("ports") or {}).items():
            for proto, name, ip, plat, rport in harvest(entry):
                keyname = name or ip
                if not keyname:
                    continue
                s = switches[keyname]
                if ip:
                    s["ips"].add(ip)
                if plat:
                    s["platforms"].add(plat)
                s["protos"].add(proto)
                s["links"].append({
                    "ap": d.get("name") or d["serial"],
                    "ap_serial": d["serial"],
                    "ap_ip": d.get("lanIp") or "",
                    "ap_port": local_port,
                    "switch": keyname,
                    "switch_port": rport,
                })

    if not switches:
        log("\n  No LLDP/CDP neighbours returned.")
        log("  Discovery protocols may be disabled on the switch side, or the")
        log("  APs may not have refreshed their neighbour tables. Fall back to:")
        log("    show cdp neighbors detail   (from any switch you can already reach)")
        log("    arp -an | grep 10.5.0       (from a host on the management VLAN)")
        return

    # ---- ssh config mode: emit only the fragment
    if args.ssh_config:
        print("# generated by meraki_find_switches.py")
        print("# switches discovered via LLDP/CDP from Meraki APs\n")
        for name in sorted(switches):
            ips = sorted(switches[name]["ips"])
            if not ips:
                continue
            short = re.sub(r"\..*$", "", name)          # strip any domain suffix
            short = re.sub(r"[^A-Za-z0-9_-]", "-", short)
            print(f"Host {short}")
            print(f"    HostName {ips[0]}")
            print(f"    User {args.user}")
            print(f"    # {', '.join(sorted(switches[name]['platforms'])) or 'unknown model'}")
            print()
        return

    # ---- switch inventory
    print("\n" + "=" * 78)
    print(f"SWITCHES DISCOVERED  ({len(switches)})")
    print("=" * 78)
    print(f"  {'switch':26} {'management IP':16} {'APs':>4} {'via':>9}  platform")
    print("  " + "-" * 92)
    rows = []
    for name in sorted(switches):
        s = switches[name]
        ips = sorted(s["ips"])
        aps = len({l["ap_serial"] for l in s["links"]})
        plat = "; ".join(sorted(s["platforms"]))[:40]
        print(f"  {name[:26]:26} {(ips[0] if ips else '-'):16} {aps:>4} "
              f"{'/'.join(sorted(s['protos'])):>9}  {plat}")
        if len(ips) > 1:
            print(f"  {'':26} also: {', '.join(ips[1:])}")
        rows.append({"switch": name, "management_ip": ips[0] if ips else "",
                     "other_ips": " ".join(ips[1:]), "ap_count": aps,
                     "protocols": "/".join(sorted(s["protos"])), "platform": plat})

    # ---- subnet summary, so you know what the VPN has to reach
    allips = sorted({ip for s in switches.values() for ip in s["ips"]})
    if allips:
        nets = sorted({str(ipaddress.ip_network(f"{ip}/24", strict=False))
                       for ip in allips if is_ip(ip)})
        print(f"\n  management subnets to route over the VPN: {', '.join(nets)}")
        print(f"  switch IPs: {', '.join(allips)}")

    # ---- which AP is on which port
    print("\n" + "=" * 78)
    print("AP TO SWITCH PORT")
    print("=" * 78)
    print(f"  {'AP':12} {'AP IP':15} {'switch':24} {'port':22}")
    print("  " + "-" * 76)
    links = [l for s in switches.values() for l in s["links"]]
    seen = set()
    for l in sorted(links, key=lambda x: x["ap"]):
        k = (l["ap_serial"], l["switch"], l["switch_port"])
        if k in seen:
            continue
        seen.add(k)
        print(f"  {l['ap'][:12]:12} {l['ap_ip']:15} {l['switch'][:24]:24} "
              f"{str(l['switch_port'])[:22]:22}")

    if args.csv:
        with open(args.csv, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["switch", "management_ip", "other_ips",
                                              "ap_count", "protocols", "platform"])
            w.writeheader()
            w.writerows(rows)
        print(f"\n  Wrote {args.csv}")
    if args.ports:
        with open(args.ports, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["ap", "ap_serial", "ap_ip", "ap_port",
                                              "switch", "switch_port"])
            w.writeheader()
            w.writerows(sorted(links, key=lambda x: x["ap"]))
        print(f"  Wrote {args.ports} ({len(links)} links)")
    print()


if __name__ == "__main__":
    main()
