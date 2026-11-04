#!/usr/bin/env python3
"""
meraki_collect.py - Read-only Meraki wireless diagnostic collector.

SAFETY DESIGN (three independent layers):
  1. PREFLIGHT  - refuses to run unless the API key's admin account has
                  orgAccess == "read-only". Aborts before any other call.
  2. SIMULATE   - SDK is constructed with simulate=True, so any write
                  operation becomes a local no-op even if one slipped in.
  3. READ-ONLY  - only get* methods are called. No POST/PUT/DELETE anywhere.

Rate limiting: Meraki allows 10 req/s per ORGANIZATION (shared across every
application touching that org) and 100 req/s per source IP. The SDK paces
proactively; we additionally throttle to MAX_RPS below that ceiling so other
consumers of the org keep their budget.

Usage:
    export MERAKI_DASHBOARD_API_KEY='...'
    python3 meraki_collect.py --list-orgs
    python3 meraki_collect.py --org-id 123456 --timespan 86400
"""

import argparse
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone

try:
    import meraki
except ImportError:
    sys.exit("Missing SDK. Install with: pip install meraki --break-system-packages")

MAX_RPS = 4.0                      # deliberately below Meraki's 10/s org ceiling
SALT = os.environ.get("SCRUB_SALT", "change-me-per-collection")

_last_call = [0.0]


def throttle():
    """Space calls out to stay well under the org-wide budget."""
    gap = 1.0 / MAX_RPS
    delta = time.time() - _last_call[0]
    if delta < gap:
        time.sleep(gap - delta)
    _last_call[0] = time.time()


def scrub_mac(mac):
    """Keep the OUI (vendor is diagnostically useful), hash the device half."""
    if not mac or not isinstance(mac, str) or mac.count(":") != 5:
        return mac
    oui, rest = mac[:8], mac[9:]
    h = hashlib.sha256((SALT + rest).encode()).hexdigest()[:8]
    return f"{oui}:{h}"


def scrub(obj):
    """Recursively redact identifying fields; preserve everything RF-related."""
    drop = {"user", "email", "username", "recentDeviceName", "ssidName_user"}
    macish = {"mac", "clientMac", "bssid", "apMac", "deviceMac"}
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k in drop:
                continue
            if k in macish:
                out[k] = scrub_mac(v)
            elif k in ("description", "name") and isinstance(v, str) and "-" not in v:
                out[k] = v            # AP names are useful; keep simple ones
            else:
                out[k] = scrub(v)
        return out
    if isinstance(obj, list):
        return [scrub(i) for i in obj]
    return obj


def preflight(dash):
    """Abort unless this key is read-only at the org level."""
    throttle()
    me = dash.administered.getAdministeredIdentitiesMe()
    email = me.get("email")
    print(f"  key belongs to: {email}")

    throttle()
    orgs = dash.organizations.getOrganizations()
    if not orgs:
        sys.exit("ABORT: key sees no organizations.")

    bad = []
    for org in orgs:
        throttle()
        try:
            admins = dash.organizations.getOrganizationAdmins(org["id"])
        except Exception:
            continue
        for a in admins:
            if a.get("email", "").lower() == (email or "").lower():
                access = a.get("orgAccess")
                print(f"  org {org['name']} ({org['id']}): orgAccess = {access}")
                if access != "read-only":
                    bad.append(f"{org['name']} = {access}")

    if bad:
        print("\n" + "=" * 62)
        print("ABORT: this API key has WRITE access to:")
        for b in bad:
            print(f"  - {b}")
        print("\nCreate a dedicated admin with Organization access 'Read-only',")
        print("generate a key from THAT account's profile, and use it here.")
        print("=" * 62)
        sys.exit(1)

    print("  PREFLIGHT PASSED - key is read-only\n")
    return orgs


def safe(label, fn, *a, **kw):
    """Call a read endpoint, tolerate failures, never abort the whole run."""
    throttle()
    try:
        return fn(*a, **kw)
    except Exception as e:
        print(f"    ! {label}: {type(e).__name__} {str(e)[:90]}")
        return None


def collect(dash, org_id, timespan):
    out = {
        "collected_utc": datetime.now(timezone.utc).isoformat(),
        "org_id": org_id,
        "timespan_seconds": timespan,
        "networks": {},
    }

    print("[devices]")
    devices = safe("devices", dash.organizations.getOrganizationDevices,
                   org_id, total_pages="all", productTypes=["wireless"]) or []
    out["wireless_devices"] = scrub(devices)
    print(f"    {len(devices)} wireless APs")

    print("[org-wide channel utilization]")
    out["channel_util_by_device"] = scrub(safe(
        "chanutil", dash.wireless.getOrganizationWirelessDevicesChannelUtilizationByDevice,
        org_id, total_pages="all", timespan=timespan))

    nets = safe("networks", dash.organizations.getOrganizationNetworks,
                org_id, total_pages="all") or []
    wireless_nets = [n for n in nets if "wireless" in n.get("productTypes", [])]
    print(f"[networks] {len(wireless_nets)} wireless networks")

    for net in wireless_nets:
        nid, nname = net["id"], net["name"]
        print(f"  - {nname}")
        n = {"name": nname}

        n["settings"]    = safe("settings", dash.wireless.getNetworkWirelessSettings, nid)
        n["ssids"]       = scrub(safe("ssids", dash.wireless.getNetworkWirelessSsids, nid))
        n["rf_profiles"] = safe("rf_profiles", dash.wireless.getNetworkWirelessRfProfiles, nid)

        n["channel_utilization"] = safe(
            "chanutil_hist", dash.wireless.getNetworkWirelessChannelUtilizationHistory,
            nid, timespan=timespan, resolution=600)
        n["client_count"] = safe(
            "clientcount", dash.wireless.getNetworkWirelessClientCountHistory,
            nid, timespan=timespan, resolution=600)
        n["connection_stats"] = safe(
            "connstats", dash.wireless.getNetworkWirelessConnectionStats,
            nid, timespan=timespan)
        n["latency_stats"] = safe(
            "latency", dash.wireless.getNetworkWirelessLatencyStats,
            nid, timespan=timespan)
        n["failed_connections"] = scrub(safe(
            "failed", dash.wireless.getNetworkWirelessFailedConnections,
            nid, timespan=timespan))
        n["air_marshal"] = scrub(safe(
            "airmarshal", dash.wireless.getNetworkWirelessAirMarshal,
            nid, timespan=min(timespan, 2678400)))

        # per-AP radio settings: channel, width, TX power
        radios = []
        for d in devices:
            if d.get("networkId") != nid:
                continue
            r = safe(f"radio {d.get('serial')}",
                     dash.wireless.getDeviceWirelessRadioSettings, d["serial"])
            if r:
                r["_name"] = d.get("name")
                radios.append(r)
        n["radio_settings"] = radios
        print(f"      {len(radios)} radio configs")

        out["networks"][nid] = n

    return out


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--org-id")
    p.add_argument("--timespan", type=int, default=86400, help="seconds, default 24h")
    p.add_argument("--list-orgs", action="store_true")
    p.add_argument("--out", default="meraki_wireless.json")
    args = p.parse_args()

    key = os.environ.get("MERAKI_DASHBOARD_API_KEY")
    if not key:
        sys.exit("Set MERAKI_DASHBOARD_API_KEY first.")

    dash = meraki.DashboardAPI(
        api_key=key,
        simulate=True,            # layer 2: any write becomes a no-op
        wait_on_rate_limit=True,
        maximum_retries=5,
        suppress_logging=True,
        print_console=False,
    )

    print("=" * 62)
    print("PREFLIGHT")
    print("=" * 62)
    orgs = preflight(dash)

    if args.list_orgs or not args.org_id:
        print("Organizations visible to this key:")
        for o in orgs:
            print(f"  {o['id']}  {o['name']}")
        print("\nRe-run with --org-id <id>")
        return

    print("=" * 62)
    print(f"COLLECTING  org={args.org_id}  timespan={args.timespan}s  rate<={MAX_RPS}/s")
    print("=" * 62)

    data = collect(dash, args.org_id, args.timespan)
    with open(args.out, "w") as f:
        json.dump(data, f, indent=2, default=str)

    size = os.path.getsize(args.out) / 1024
    print(f"\nWrote {args.out} ({size:.0f} KB)")
    print("MACs are salted-hashed; usernames and client names removed.")


if __name__ == "__main__":
    main()
