#!/usr/bin/env python3
"""
meraki_client_policy.py - What policy, and what bandwidth cap, is a client under?

Two clients on the same SSID with the same PSK can still be under different
group policies, applied by hand, by Systems Manager Sentry, by the provision
API, or by Identity PSK. None of that is visible from the client check, and a
bandwidth cap looks exactly like a slow access point from the user's seat.

This resolves each MAC to its applied policy and prints the actual limit.

SAFETY: same three layers as the other scripts --
  1. PREFLIGHT  - aborts unless the key's admin account is read-only
  2. SIMULATE   - SDK constructed with simulate=True; writes become no-ops
  3. READ-ONLY  - only get* methods are called

Usage:
    export MERAKI_DASHBOARD_API_KEY='...'
    python3 meraki_client_policy.py --org-id 1586134 \
        --macs f4:4e:b4:59:d9:f9,f4:4e:b4:1e:44:f9,10:e1:8e:40:6d:5a
    python3 meraki_client_policy.py --org-id 1586134 --policies
"""

import argparse
import os
import re
import sys
import time

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
        print(f"    ! {label}: {type(e).__name__} {str(e)[:90]}", file=sys.stderr)
        return None


def preflight(dash):
    throttle()
    me = dash.administered.getAdministeredIdentitiesMe()
    email = (me.get("email") or "").lower()
    throttle()
    bad = []
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


def limits_of(policy):
    """Group policy bandwidth lives at a different depth depending on whether
    the policy inherits, ignores or overrides the SSID setting."""
    if not policy:
        return None, None, "-"
    bw = policy.get("bandwidth") or {}
    setting = bw.get("settings") or "-"
    lim = bw.get("bandwidthLimits") or {}
    return lim.get("limitUp"), lim.get("limitDown"), setting


def fmt_kbps(v):
    # Two conventions arrive here: an SSID object uses 0 for unlimited, a
    # group policy simply omits the key. Both mean the same thing.
    if v is None or v == 0:
        return "unlimited"
    return f"{v/1000:.1f} Mbps" if v >= 1000 else f"{v} kbps"


def defn_name(d):
    """A shaping rule's definition value is sometimes a plain string (a host,
    a port) and sometimes an object carrying both an opaque id and a readable
    name. Printing the raw object gives you 'meraki:layer7/category/16', which
    is the one thing you cannot act on."""
    v = (d or {}).get("value")
    if isinstance(v, dict):
        return str(v.get("name") or v.get("id") or v)
    return str(v)


NAME_RATE = re.compile(r"(\d+)\s*mbps", re.I)


def name_mismatch(name, down_kbps):
    """A policy called '10Mbps' that is set to 102400 kbps is worse than one
    with no name at all, because everyone reads the name and nobody opens the
    policy. Flag the disagreement rather than trusting either."""
    m = NAME_RATE.search(name or "")
    if not m or not down_kbps:
        return ""
    claimed = int(m.group(1)) * 1000
    # 1024-based entry (5120 for "5 Mbps") is not a mismatch, just arithmetic.
    if abs(down_kbps - claimed) > max(claimed * 0.1, 500):
        return f"<-- name says {m.group(1)} Mbps"
    return ""


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--org-id", required=True)
    p.add_argument("--macs", help="comma-separated client MACs")
    p.add_argument("--policies", action="store_true",
                   help="just list every group policy and its limits")
    args = p.parse_args()

    if not args.macs and not args.policies:
        sys.exit("Give --macs, or --policies to list them all.")

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

    print("=" * 78)
    print("CLIENT POLICY AND BANDWIDTH CAP")
    print("=" * 78)
    print(f"  key      read-only ({who})")
    print(f"  network  {net.get('name')}")

    pols = safe("group policies", dash.networks.getNetworkGroupPolicies, net_id) or []
    by_id = {str(g.get("groupPolicyId")): g for g in pols}

    print()
    print("-" * 78)
    print("GROUP POLICIES ON THIS NETWORK")
    print("-" * 78)
    print(f"  {'id':>6} {'name':30} {'setting':16} {'up':>12} {'down':>12}  note")
    for g in sorted(pols, key=lambda x: str(x.get("name") or "")):
        up, dn, setting = limits_of(g)
        print(f"  {str(g.get('groupPolicyId')):>6} {str(g.get('name'))[:30]:30} "
              f"{setting[:16]:16} {fmt_kbps(up):>12} {fmt_kbps(dn):>12}  "
              f"{name_mismatch(g.get('name'), dn)}")
    if not pols:
        print("  (none defined)")

    # The SSID's own per-client limit is the floor everyone sits under unless a
    # group policy overrides it, so print it for context.
    print()
    print("-" * 78)
    print("PER-SSID LIMITS (the default when no group policy applies)")
    print("-" * 78)
    # The bandwidth limits live on the SSID object itself, in kbps with 0 for
    # unlimited -- NOT on a traffic-shaping endpoint, which is where I looked
    # first and why this used to crash. The shaping endpoint carries only the
    # rules.
    ssids = safe("ssids", dash.wireless.getNetworkWirelessSsids, net_id) or []
    for s in ssids:
        if not s.get("enabled"):
            continue
        print(f"  {str(s.get('name'))[:24]:24} "
              f"per-client up {fmt_kbps(s.get('perClientBandwidthLimitUp')):>12} "
              f"down {fmt_kbps(s.get('perClientBandwidthLimitDown')):>12}")
        print(f"  {'':24} per-SSID   up {fmt_kbps(s.get('perSsidBandwidthLimitUp')):>12} "
              f"down {fmt_kbps(s.get('perSsidBandwidthLimitDown')):>12}")
        ts = safe(f"shaping rules {s['number']}",
                  dash.wireless.getNetworkWirelessSsidTrafficShapingRules,
                  net_id, s["number"]) or {}
        rules = ts.get("rules") or []
        if not ts.get("trafficShapingEnabled"):
            print(f"  {'':24} traffic shaping off")
            continue
        print(f"  {'':24} shaping ON, {len(rules)} rule(s), "
              f"default rules {'on' if ts.get('defaultRulesEnabled') else 'off'}")
        # A rule that sets dscpTagValue is the wireless side marking packets
        # before they ever reach a switch. Given that SFSW51 trusts DSCP on
        # its access ports and the core polices what it receives, any rule
        # tagging 46 here is worth tracing all the way through.
        for r in rules:
            dscp = r.get("dscpTagValue")
            pri = r.get("pcpTagValue")
            lim = (r.get("perClientBandwidthLimits") or {}).get("bandwidthLimits") or {}
            defs = ", ".join(defn_name(d) for d in (r.get("definitions") or []))[:34]
            flag = ""
            if dscp is not None:
                flag = "  <-- DSCP tag"
                # A packet's layer-2 priority is conventionally the class
                # selector of its DSCP, i.e. the top three bits: CoS = DSCP>>3.
                # EF (46) therefore belongs in CoS 5. CoS 6 and 7 are reserved
                # for network control -- spanning tree, routing protocols --
                # and putting user traffic there competes with the control
                # plane for the same egress queue.
                want = dscp >> 3
                if pri is not None and pri != want:
                    flag = f"  <-- DSCP {dscp} should pair with pcp {want}, not {pri}"
            print(f"  {'':26} {defs:34} dscp {str(dscp or '-'):>3} "
                  f"pcp {str(pri if pri is not None else '-'):>2} "
                  f"down {fmt_kbps(lim.get('limitDown')):>10}{flag}")

    if not args.macs:
        return

    print()
    print("-" * 78)
    print("CLIENTS")
    print("-" * 78)
    print(f"  {'mac':20} {'device policy':16} {'group policy':24} {'down cap':>12}")
    for mac in [m.strip() for m in args.macs.split(",") if m.strip()]:
        cp = safe(f"policy {mac}", dash.networks.getNetworkClientPolicy, net_id, mac)
        if cp is None:
            print(f"  {mac:20} (no policy record returned)")
            continue
        gid = str(cp.get("groupPolicyId") or "")
        g = by_id.get(gid)
        up, dn, _ = limits_of(g)
        print(f"  {mac:20} {str(cp.get('devicePolicy'))[:16]:16} "
              f"{(g.get('name') if g else '-')[:24]:24} {fmt_kbps(dn):>12}")

    print()
    print("  A client showing 'Normal' takes the per-SSID limit above. A client")
    print("  on a group policy takes that policy's limit instead. Two machines")
    print("  at the same desk with different caps is a policy assignment, not RF.")
    print()


if __name__ == "__main__":
    main()
