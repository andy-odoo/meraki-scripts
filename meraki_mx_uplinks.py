#!/usr/bin/env python3
"""
meraki_mx_uplinks.py - What the MX is actually doing with the two WAN circuits.

Written 30 October 2026, after SFISPSW01 (the AT&T-side Nexus 3064) reported
2.05 GB in and 1.82 GB out over 19 days 18 hours -- a flat 9.6 Kbps with no
business-hours peak at all. A 2 Gbps circuit carrying nine kilobits is either
a standby that has never been called on, or a circuit the MX has quietly
stopped using. The switch cannot tell those apart. The dashboard can.

Two questions the switches genuinely cannot answer, and one they raised:

  1. WHICH CIRCUIT CARRIES THE OFFICE, AND BY WHOSE DECISION.
     SFISPSW01 can count its own bytes but knows nothing about Zayo or about
     the MX's uplink policy. If load balancing is off and the default uplink
     is Zayo, AT&T's silence is correct and expected. If load balancing is ON,
     then traffic should be crossing both and AT&T's silence is a fault.
     Those two readings lead to opposite actions, so this is first.

  2. WHAT WRITES THE DSCP MARKINGS.
     This is the open question the whole wired investigation ran into. Floor 3
     has discarded 118,112,889 packets out of its access-point ports, two
     thirds of them from the starved scavenger queue that serves AF11. The
     core has dropped 59,559,422 packets from its priority queue, all of them
     EF, CS4, CS5 or CoS 5. No access switch sets DSCP; the core copies what
     arrives. So the marking is applied upstream, and the MX's traffic shaping
     rules are the only remaining candidate. Section 5 reads them and names
     every DSCP value they write.

  3. WHETHER THE ACTIVE CIRCUIT IS CLEAN.
     Staff report choppy voice and dropped calls. AT&T's handoff is flawless
     -- zero CRC, zero discards, no flaps in 19 days -- but that is the idle
     circuit. The one carrying the calls has never been measured.

CALIBRATION. getNetworkApplianceUplinksUsageHistory returns bytes, so section
4's AT&T total is directly comparable to the 2,048,770,737 bytes SFISPSW01
counted. If the two agree, every other number in that section is trustworthy.
If they disagree by orders of magnitude, stop and work out why before quoting
anything. The script prints that comparison rather than assuming it.

SAFETY: same three layers as the other scripts --
  1. PREFLIGHT  - aborts unless the key's admin account is read-only
  2. SIMULATE   - SDK constructed with simulate=True; writes become no-ops
  3. READ-ONLY  - only get* methods are called

Usage:
    export MERAKI_DASHBOARD_API_KEY='...'
    python3 meraki_mx_uplinks.py --org-id 1586134
    python3 meraki_mx_uplinks.py --org-id 1586134 --days 30 --csv uplinks.csv
    python3 meraki_mx_uplinks.py --org-id 1586134 --att-subnet 12.25.161.224/29
"""

import argparse
import csv
import ipaddress
import os
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

# Business hours, for separating "what the office does" from "what the office
# does at 3am". A 24-hour mean hides a circuit that is saturated at 11am.
BIZ_START, BIZ_END = 9, 17

# Ground truth from SFISPSW01, read 30 Oct 2026. Section 4 compares the
# dashboard's AT&T total against this to prove the units and the mapping.
NEXUS_RX_BYTES = 2_048_770_737
NEXUS_TX_BYTES = 1_816_520_389
NEXUS_SECONDS = (19 * 86400) + (18 * 3600) + (23 * 60)   # 19d 18h 23m uptime

MAX_RPS = 4.0
_last = [0.0]


def throttle():
    gap = 1.0 / MAX_RPS
    d = time.time() - _last[0]
    if d < gap:
        time.sleep(gap - d)
    _last[0] = time.time()


def safe(label, fn, *a, **kw):
    """Call an endpoint; on failure say so on stderr and return None.

    One missing metric should cost you that metric, not the run. Every caller
    below is written to cope with None.
    """
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
    """A bound SDK method, or None if this release does not have it."""
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


# --------------------------------------------------------------------------
# DSCP
# --------------------------------------------------------------------------
# Standard per-hop behaviour names, so a rule reading "dscpTagValue: 10" shows
# up as AF11 and lines up with what the switches are dropping.
DSCP_NAMES = {
    0: "CS0/default (best effort)",
    8: "CS1", 10: "AF11", 12: "AF12", 14: "AF13",
    16: "CS2", 18: "AF21", 20: "AF22", 22: "AF23",
    24: "CS3", 26: "AF31", 28: "AF32", 30: "AF33",
    32: "CS4", 34: "AF41", 36: "AF42", 38: "AF43",
    40: "CS5", 46: "EF (voice)",
    48: "CS6", 56: "CS7",
}

# What each marking runs into downstream, measured on the switches this week.
# The point of the cross-reference is that a shaping rule is harmless in
# isolation; it only becomes a problem because of where its traffic lands.
DSCP_CONSEQUENCE = {
    10: "floor 3 queue 4 (scavenger, 10% buffer / 60% threshold) "
        "- 17.4% loss, two thirds of 118.1M discards",
    8:  "floor 3 queue 4 (scavenger) - same starved queue as AF11",
    12: "floor 3 queue 4 (scavenger) - same starved queue as AF11",
    14: "floor 3 queue 4 (scavenger) - same starved queue as AF11",
    46: "core priority queue, 3 Gbps policer - 59.5M drops",
    32: "core priority queue, 3 Gbps policer - 59.5M drops "
        "(and shares floor 3's voice queue: 17.3M CS4 packets, 3.4% loss)",
    40: "core priority queue, 3 Gbps policer - 59.5M drops",
    24: "floor 5 queue 1 (signalling) - 3.1% lifetime loss",
    18: "floor 5 queue 1 (signalling) - 3.1% lifetime loss",
    48: "floor 5 queue 1 (signalling) - 3.1% lifetime loss",
}


def dscp_label(v):
    if v is None:
        return "(not set - rule does not mark)"
    return f"{v} = {DSCP_NAMES.get(v, 'unassigned code point')}"


def human_bytes(n):
    if n is None:
        return "-"
    for unit, div in (("TB", 1e12), ("GB", 1e9), ("MB", 1e6), ("KB", 1e3)):
        if abs(n) >= div:
            return f"{n / div:.2f} {unit}"
    return f"{n:.0f} B"


def human_bps(n):
    if n is None:
        return "-"
    for unit, div in (("Gbps", 1e9), ("Mbps", 1e6), ("Kbps", 1e3)):
        if abs(n) >= div:
            return f"{n / div:.2f} {unit}"
    return f"{n:.0f} bps"


def rule_subject(rule):
    """One readable line for what a shaping rule matches.

    Meraki expresses this as a list of definitions, each an application, an
    application category, a host, a port, an IP range or a URL pattern.
    """
    out = []
    for d in rule.get("definitions") or []:
        t = d.get("type", "?")
        v = d.get("value")
        if isinstance(v, dict):
            v = v.get("name") or v.get("id") or "?"
        out.append(f"{t}:{v}")
    return ", ".join(out) if out else "(no definitions)"


def in_subnet(ip, net):
    if not ip or not net:
        return False
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(net, strict=False)
    except ValueError:
        return False


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--org-id", required=True)
    p.add_argument("--network-id", help="pin to one appliance network")
    p.add_argument("--days", type=int, default=30,
                   help="usage history window; API maximum lookback is 30 days")
    p.add_argument("--resolution", type=int, default=3600,
                   choices=[60, 300, 600, 1800, 3600, 86400],
                   help="usage history bucket size in seconds")
    p.add_argument("--att-subnet", default="12.25.161.224/29",
                   help="public block on the AT&T path, so uplinks get carrier "
                        "labels instead of wan1/wan2")
    p.add_argument("--latency-days", type=int, default=7,
                   help="window for the loss/latency/jitter trend")
    p.add_argument("--csv", help="write the hourly per-uplink series here")
    args = p.parse_args()

    key = os.environ.get("MERAKI_DASHBOARD_API_KEY")
    if not key:
        sys.exit("Set MERAKI_DASHBOARD_API_KEY first.")

    dash = meraki.DashboardAPI(api_key=key, simulate=True, wait_on_rate_limit=True,
                               maximum_retries=5, suppress_logging=True,
                               print_console=False)

    print("Preflight: confirming the key is read-only ...", file=sys.stderr)
    who = preflight(dash)
    print(f"  ok, {who} is read-only everywhere\n", file=sys.stderr)

    now = datetime.now(timezone.utc)

    print("=" * 78)
    print("MX UPLINKS - CONFIGURATION, UTILISATION AND MARKING")
    print(f"org {args.org_id}   read {now.astimezone(LOCAL):%Y-%m-%d %H:%M %Z}")
    print("=" * 78)

    # ---------------------------------------------------------------- find
    nets = safe("getOrganizationNetworks",
                endpoint(dash, "organizations", "getOrganizationNetworks"),
                args.org_id, total_pages="all") or []
    appliance_nets = [n for n in nets if "appliance" in (n.get("productTypes") or [])]
    if args.network_id:
        appliance_nets = [n for n in appliance_nets if n["id"] == args.network_id]
    if not appliance_nets:
        sys.exit("No appliance networks found. Check --org-id, or pass --network-id.")

    # ---------------------------------------------------------------- 1
    print()
    print("-" * 78)
    print("1. WHICH UPLINK IS WHICH")
    print("-" * 78)
    print("  Every address the MX pair holds on the public side. The ARP table on")
    print("  SFISPSW01 showed three live hosts plus the switch in the /29; this")
    print("  section names them, and tells you whether .230 -- the entry that was")
    print("  INCOMPLETE and re-ARPing every twelve seconds -- belongs to anything.")
    print()

    statuses = safe("getOrganizationUplinksStatuses",
                    endpoint(dash, "organizations", "getOrganizationUplinksStatuses"),
                    args.org_id, total_pages="all")
    if statuses is None:
        statuses = safe("getOrganizationApplianceUplinkStatuses",
                        endpoint(dash, "appliance", "getOrganizationApplianceUplinkStatuses"),
                        args.org_id, total_pages="all") or []

    net_names = {n["id"]: n["name"] for n in nets}
    wanted = {n["id"] for n in appliance_nets}
    seen_public = []

    # Carrier labels are keyed by (serial, interface), NOT by interface alone.
    # Keying on the bare name labelled every wan1 in the org as the AT&T path
    # the moment one network's wan1 matched -- including a second site whose
    # wan1 is a different carrier entirely, and it then ran the SFISPSW01
    # calibration against that unrelated circuit.
    iface_label = {}        # (serial, iface) -> label
    att_by_net = {}         # networkId -> the iface on the AT&T path there

    def dev_tag(serial, iface):
        lab = iface_label.get((serial, iface))
        return f"  [{lab}]" if lab else ""

    def net_tag(nid, iface):
        # Per-network view, for the sections that aggregate across the pair.
        return "  [AT&T path]" if att_by_net.get(nid) == iface else ""

    for dev in statuses:
        if dev.get("networkId") not in wanted:
            continue
        print(f"  {dev.get('model', '?')}  serial {dev.get('serial', '?')}"
              f"   network {net_names.get(dev.get('networkId'), '?')}")
        print(f"    last reported {dev.get('lastReportedAt', '?')}")
        for u in dev.get("uplinks") or []:
            iface = u.get("interface", "?")
            ip = u.get("ip")
            pub = u.get("publicIp")
            att = in_subnet(ip, args.att_subnet) or in_subnet(pub, args.att_subnet)
            if att:
                iface_label[(dev.get("serial"), iface)] = "AT&T path"
                att_by_net[dev.get("networkId")] = iface
            print(f"    {iface:9} status={u.get('status', '?'):14} "
                  f"ip={ip or '-':17} gw={u.get('gateway') or '-':17}")
            print(f"    {'':9} public={pub or '-':15} assigned by "
                  f"{u.get('ipAssignedBy') or '-'}"
                  + ("   <-- inside --att-subnet" if att else ""))
            dns = [u.get("primaryDns"), u.get("secondaryDns")]
            dns = [d for d in dns if d]
            if dns:
                print(f"    {'':9} dns {', '.join(dns)}")
            for v in (ip, pub):
                if v and v not in seen_public:
                    seen_public.append(v)
        print()

    if not statuses:
        print("  (no uplink statuses returned)")
        print()

    # Warm spare settles whether a third address in the /29 is a virtual IP
    # rather than a third device.
    for n in appliance_nets:
        ws = safe("getNetworkApplianceWarmSpare",
                  endpoint(dash, "appliance", "getNetworkApplianceWarmSpare"), n["id"])
        if not ws:
            continue
        print(f"  warm spare, {n['name']}: enabled={ws.get('enabled')}  "
              f"uplinkMode={ws.get('uplinkMode', '-')}")
        print(f"    primary {ws.get('primarySerial', '-')}   "
              f"spare {ws.get('spareSerial', '-')}")
        for w in ("wan1", "wan2"):
            blk = ws.get(w) or {}
            if blk.get("ip") or blk.get("subnet"):
                print(f"    {w} virtual ip {blk.get('ip', '-')}  "
                      f"subnet {blk.get('subnet', '-')}  "
                      f"static={blk.get('usingStaticIp')}")
                if blk.get("ip") and blk["ip"] not in seen_public:
                    seen_public.append(blk["ip"])
        print()
        # Only worth explaining where a pair actually exists. Printing it for a
        # single-appliance network invited the reader to go looking for a third
        # address that was never there.
        if ws.get("enabled"):
            print("  A warm-spare pair holds one address per appliance plus a shared")
            print("  virtual IP, which is three addresses for two boxes -- so this")
            print("  pair alone accounts for three of the /29's six usable hosts.")
            print()

    if seen_public:
        print(f"  addresses accounted for: {', '.join(sorted(seen_public))}")
        print()

    # Per-device uplink settings: what is *configured*, as against what is up.
    # An uplink that is disabled here can never carry traffic, however healthy
    # the circuit looks from the Nexus side.
    for dev in statuses:
        if dev.get("networkId") not in wanted or not dev.get("serial"):
            continue
        st = safe("getDeviceApplianceUplinksSettings",
                  endpoint(dash, "appliance", "getDeviceApplianceUplinksSettings"),
                  dev["serial"])
        if not st:
            continue
        print(f"  configured interfaces on {dev['serial']}:")
        for iface, blk in (st.get("interfaces") or {}).items():
            svi = ((blk.get("svis") or {}).get("ipv4") or {})
            print(f"    {iface:9} enabled={blk.get('enabled')}  "
                  f"vlanTagging={(blk.get('vlanTagging') or {}).get('enabled')}  "
                  f"mode={svi.get('assignmentMode', '-')}  "
                  f"addr={svi.get('address', '-')}")
            if (blk.get("pppoe") or {}).get("enabled"):
                print(f"    {'':9} pppoe enabled")
        print()

    # ---------------------------------------------------------------- 2
    print("-" * 78)
    print("2. UPLINK SELECTION POLICY - IS AT&T IDLE BY DESIGN?")
    print("-" * 78)
    print("  This is the section that decides what AT&T's 9.6 Kbps means.")
    print()
    print("    loadBalancingEnabled false  ->  one circuit carries everything and")
    print("        the other waits. AT&T's silence is correct. The open question")
    print("        becomes whether failover has ever been tested, because an")
    print("        untested standby is a promise, not a capability.")
    print()
    print("    loadBalancingEnabled true   ->  the MX should be spreading flows")
    print("        across both. AT&T carrying nine kilobits is then a fault, and")
    print("        the whole office is on one circuit without anyone intending it.")
    print()

    for n in appliance_nets:
        sel = safe("getNetworkApplianceTrafficShapingUplinkSelection",
                   endpoint(dash, "appliance",
                            "getNetworkApplianceTrafficShapingUplinkSelection"),
                   n["id"])
        if not sel:
            continue
        print(f"  {n['name']}:")
        print(f"    loadBalancingEnabled    {sel.get('loadBalancingEnabled')}")
        print(f"    defaultUplink           {sel.get('defaultUplink', '-')}")
        print(f"    activeActiveAutoVpn     {sel.get('activeActiveAutoVpnEnabled')}")
        fof = (sel.get("failoverAndFailback") or {}).get("immediate") or {}
        print(f"    immediate failover      {fof.get('enabled', '-')}")

        wan_prefs = sel.get("wanTrafficUplinkPreferences") or []
        print(f"    wan traffic preferences {len(wan_prefs)}")
        for i, pref in enumerate(wan_prefs, 1):
            print(f"      [{i}] prefer {pref.get('preferredUplink', '-')}")
            for d in pref.get("trafficFilters") or []:
                v = d.get("value") or {}
                print(f"          {d.get('type', '?')}: proto={v.get('protocol', '-')} "
                      f"src={(v.get('source') or {}).get('cidr', '-')} "
                      f"dst={(v.get('destination') or {}).get('cidr', '-')}")
        vpn_prefs = sel.get("vpnTrafficUplinkPreferences") or []
        if vpn_prefs:
            print(f"    vpn traffic preferences {len(vpn_prefs)}")
            for i, pref in enumerate(vpn_prefs, 1):
                print(f"      [{i}] prefer {pref.get('preferredUplink', '-')}  "
                      f"class {(pref.get('performanceClass') or {}).get('type', '-')}")
        print()

    # ---------------------------------------------------------------- 3
    print("-" * 78)
    print("3. BANDWIDTH THE MX IS CONFIGURED TO ALLOW")
    print("-" * 78)
    print("  Both circuits are sold as 2 Gbps. The MX enforces whatever is set")
    print("  here regardless, and a limit left at a previous circuit's speed is a")
    print("  common and invisible way to lose most of what you pay for.")
    print()

    for n in appliance_nets:
        bw = safe("getNetworkApplianceTrafficShapingUplinkBandwidth",
                  endpoint(dash, "appliance",
                           "getNetworkApplianceTrafficShapingUplinkBandwidth"),
                  n["id"])
        if bw:
            print(f"  {n['name']} per-uplink limits:")
            limits = bw.get("bandwidthLimits") or {}
            if not limits:
                print("    (none returned)")
            for iface, lim in limits.items():
                lim = lim or {}
                up, dn = lim.get("limitUp"), lim.get("limitDown")
                tag = net_tag(n["id"], iface)
                print(f"    {iface:9} up={human_bps(up * 1000) if up else 'unlimited':>12}"
                      f"   down={human_bps(dn * 1000) if dn else 'unlimited':>12}{tag}")
            print()

        gl = safe("getNetworkApplianceTrafficShaping",
                  endpoint(dash, "appliance", "getNetworkApplianceTrafficShaping"), n["id"])
        if gl:
            g = gl.get("globalBandwidthLimits") or {}
            up, dn = g.get("limitUp"), g.get("limitDown")
            print(f"  {n['name']} global per-client limits: "
                  f"up={human_bps(up * 1000) if up else 'unlimited'}  "
                  f"down={human_bps(dn * 1000) if dn else 'unlimited'}")
            print()

    # ---------------------------------------------------------------- 4
    print("-" * 78)
    print(f"4. WHAT EACH UPLINK HAS ACTUALLY CARRIED ({args.days} days)")
    print("-" * 78)

    rows = []
    for n in appliance_nets:
        hist = safe("getNetworkApplianceUplinksUsageHistory",
                    endpoint(dash, "appliance", "getNetworkApplianceUplinksUsageHistory"),
                    n["id"], timespan=min(args.days, 30) * 86400,
                    resolution=args.resolution)
        if not hist:
            # A long window at a fine resolution is the usual cause. Retry
            # coarse before giving up on the network entirely.
            hist = safe("getNetworkApplianceUplinksUsageHistory (coarse retry)",
                        endpoint(dash, "appliance",
                                 "getNetworkApplianceUplinksUsageHistory"),
                        n["id"], timespan=min(args.days, 30) * 86400,
                        resolution=86400)
        if not hist:
            print(f"  {n['name']}: no usage history returned")
            continue

        per = defaultdict(lambda: {"sent": 0, "recv": 0, "rx_bps": [], "tx_bps": [],
                                   "biz_rx": [], "biz_tx": [], "buckets": 0})
        for b in hist:
            start = b.get("startTime")
            end = b.get("endTime")
            try:
                t0 = datetime.fromisoformat(start.replace("Z", "+00:00"))
                t1 = datetime.fromisoformat(end.replace("Z", "+00:00"))
                secs = max((t1 - t0).total_seconds(), 1)
            except Exception:
                t0, secs = None, args.resolution
            for i in b.get("byInterface") or []:
                iface = i.get("interface", "?")
                s = i.get("sent") or 0
                r = i.get("received") or 0
                d = per[iface]
                d["sent"] += s
                d["recv"] += r
                d["buckets"] += 1
                rx_bps, tx_bps = r * 8 / secs, s * 8 / secs
                d["rx_bps"].append(rx_bps)
                d["tx_bps"].append(tx_bps)
                if t0 is not None:
                    lt = t0.astimezone(LOCAL)
                    if lt.weekday() < 5 and BIZ_START <= lt.hour < BIZ_END:
                        d["biz_rx"].append(rx_bps)
                        d["biz_tx"].append(tx_bps)
                    rows.append({"network": n["name"], "interface": iface,
                                 "start_local": lt.isoformat(),
                                 "sent_bytes": s, "received_bytes": r,
                                 "tx_bps": round(tx_bps), "rx_bps": round(rx_bps)})

        print(f"  {n['name']}:")
        print(f"    {'iface':9} {'received':>11} {'sent':>11} {'mean rx':>11} "
              f"{'peak rx':>11} {'biz mean rx':>12}")
        for iface in sorted(per):
            d = per[iface]
            mean_rx = statistics.mean(d["rx_bps"]) if d["rx_bps"] else 0
            peak_rx = max(d["rx_bps"]) if d["rx_bps"] else 0
            biz_rx = statistics.mean(d["biz_rx"]) if d["biz_rx"] else None
            tag = net_tag(n["id"], iface)
            print(f"    {iface:9} {human_bytes(d['recv']):>11} "
                  f"{human_bytes(d['sent']):>11} {human_bps(mean_rx):>11} "
                  f"{human_bps(peak_rx):>11} "
                  f"{(human_bps(biz_rx) if biz_rx is not None else '-'):>12}{tag}")
        print()

        # The calibration. A circuit whose business-hours mean equals its
        # 24-hour mean has no users on it, whatever its headline total says --
        # that flatness is exactly what SFISPSW01 measured.
        print("    Read the last two columns together. A circuit carrying people")
        print("    has a business-hours mean well above its 24-hour mean. One where")
        print("    the two are equal is carrying keepalives, and its total is just")
        print("    uptime multiplied by a constant.")
        print()
        for iface in sorted(per):
            d = per[iface]
            if att_by_net.get(n["id"]) != iface:
                continue
            nexus_rate = NEXUS_RX_BYTES * 8 / NEXUS_SECONDS
            print(f"    calibration against SFISPSW01 ({iface}):")
            print(f"      switch counted  {human_bytes(NEXUS_RX_BYTES)} in / "
                  f"{human_bytes(NEXUS_TX_BYTES)} out over 19d 18h "
                  f"= {human_bps(nexus_rate)}")
            print(f"      dashboard says  {human_bytes(d['recv'])} in / "
                  f"{human_bytes(d['sent'])} out over {args.days}d")
            print("      These cover different windows, so expect a difference of")
            print("      degree. Orders of magnitude mean the units or the uplink")
            print("      mapping are wrong -- check before quoting either figure.")
            print()

    # ---------------------------------------------------------------- 5
    print("-" * 78)
    print("5. WHAT WRITES DSCP - THE MARKING THE SWITCHES ARE DROPPING")
    print("-" * 78)
    print("  Xterra's position is that the MX already does QoS, which is why they")
    print("  removed it from the switches. If that is right, the markings the")
    print("  switches were sorting on are set here. Every rule below that carries")
    print("  a dscpTagValue writes that value into the packet, and the switches")
    print("  downstream then queue on it.")
    print()

    for n in appliance_nets:
        tsr = safe("getNetworkApplianceTrafficShapingRules",
                   endpoint(dash, "appliance", "getNetworkApplianceTrafficShapingRules"),
                   n["id"])
        if not tsr:
            continue
        rules = tsr.get("rules") or []
        default_on = tsr.get("defaultRulesEnabled")
        print(f"  {n['name']}: {len(rules)} custom rule(s), "
              f"defaultRulesEnabled={default_on}")
        print()

        marks = {}
        for i, r in enumerate(rules, 1):
            dscp = r.get("dscpTagValue")
            prio = r.get("priority", "-")
            pcb = r.get("perClientBandwidthLimits") or {}
            lim = pcb.get("bandwidthLimits") or {}
            print(f"    [{i}] {rule_subject(r)[:88]}")
            print(f"        dscp     {dscp_label(dscp)}")
            print(f"        priority {prio}")
            if pcb.get("settings") and pcb["settings"] != "network default":
                up, dn = lim.get("limitUp"), lim.get("limitDown")
                print(f"        per-client up="
                      f"{human_bps(up * 1000) if up else 'unlimited'}  down="
                      f"{human_bps(dn * 1000) if dn else 'unlimited'}")
            if dscp is not None:
                marks.setdefault(dscp, []).append(rule_subject(r)[:60])
            print()

        if marks:
            print("    CROSS-REFERENCE WITH THE SWITCH COUNTERS")
            print("    Each marking written here, and what it runs into downstream:")
            print()
            for dscp in sorted(marks):
                print(f"      {dscp_label(dscp)}")
                hit = DSCP_CONSEQUENCE.get(dscp)
                if hit:
                    print(f"        -> {hit}")
                else:
                    print("        -> no drop counter attributed to this value "
                          "in what we have read so far")
                for s in marks[dscp][:4]:
                    print(f"           set by: {s}")
                print()
        else:
            print("    No custom rule writes a DSCP value.")
            print()
            print("    That is a result, not an absence. If nothing here marks")
            print("    AF11, and no access switch marks it, and the core only")
            print("    copies what arrives, then the marking is coming from the")
            print("    endpoints themselves -- the applications on the ThinkPads")
            print("    and the softphone -- and no amount of MX configuration")
            print("    will change it. Removing the switch QoS is then the right")
            print("    call for a different reason than the one given.")
            print()

        if default_on:
            print("    CAVEAT WORTH STATING TO XTERRA: defaultRulesEnabled is true.")
            print("    Meraki's built-in shaping rules then apply on top of the")
            print("    list above, and the API does not enumerate them. So this")
            print("    section proves what IS marked, not that nothing else is.")
            print("    The dashboard UI shows the default set; the API cannot.")
            print()

        cpc = safe("getNetworkApplianceTrafficShapingCustomPerformanceClasses",
                   endpoint(dash, "appliance",
                            "getNetworkApplianceTrafficShapingCustomPerformanceClasses"),
                   n["id"])
        if cpc:
            print(f"    custom performance classes ({len(cpc)}):")
            for c in cpc:
                print(f"      {c.get('name', '?')}: maxLatency={c.get('maxLatency', '-')}ms "
                      f"maxJitter={c.get('maxJitter', '-')}ms "
                      f"maxLossPercentage={c.get('maxLossPercentage', '-')}%")
            print()

    # ---------------------------------------------------------------- 6
    print("-" * 78)
    print("6. LOSS, LATENCY AND JITTER ON THE CIRCUIT THAT CARRIES THE CALLS")
    print("-" * 78)
    print("  AT&T's handoff is flawless and idle. This measures the other one.")
    print("  For voice, jitter above roughly 30 ms or loss above 1% is audible as")
    print("  the choppiness staff are reporting.")
    print()

    dests = {}
    for n in appliance_nets:
        cm = safe("getNetworkApplianceConnectivityMonitoringDestinations",
                  endpoint(dash, "appliance",
                           "getNetworkApplianceConnectivityMonitoringDestinations"),
                  n["id"])
        if cm:
            ds = cm.get("destinations") or []
            dests[n["id"]] = ds
            print(f"  {n['name']} monitors {len(ds)} destination(s) "
                  f"-- this is the 9.6 Kbps SFISPSW01 was counting:")
            for d in ds:
                print(f"    {d.get('ip', '?'):17} {d.get('description', '')}"
                      f"{'  [default]' if d.get('default') else ''}")
            print()

    # Snapshot: org-wide, every MX, every uplink. t1 can only be 5 minutes
    # after t0 on this endpoint, so it is a reading rather than a trend.
    snap = safe("getOrganizationDevicesUplinksLossAndLatency",
                endpoint(dash, "organizations",
                         "getOrganizationDevicesUplinksLossAndLatency"),
                args.org_id, timespan=300)
    if snap:
        print("  last 5 minutes:")
        print(f"    {'serial':16} {'uplink':8} {'dest':17} {'loss%':>7} "
              f"{'latency':>9} {'jitter':>8}")
        for e in snap:
            if e.get("networkId") not in wanted:
                continue
            ts = e.get("timeSeries") or []
            loss = [x["lossPercent"] for x in ts if x.get("lossPercent") is not None]
            lat = [x["latencyMs"] for x in ts if x.get("latencyMs") is not None]
            jit = [x["jitter"] for x in ts if x.get("jitter") is not None]
            iface = e.get("uplink", "?")
            tag = dev_tag(e.get("serial"), iface)
            print(f"    {str(e.get('serial'))[:16]:16} {iface:8} "
                  f"{str(e.get('ip'))[:17]:17} "
                  f"{(statistics.mean(loss) if loss else 0):>7.2f} "
                  f"{(f'{statistics.mean(lat):.1f} ms' if lat else '-'):>9} "
                  f"{(f'{statistics.mean(jit):.1f} ms' if jit else '-'):>8}{tag}")
        print()

    # Trend: per device, per uplink, needs an explicit destination IP.
    hist_fn = endpoint(dash, "devices", "getDeviceLossAndLatencyHistory")
    serials = [(d.get("serial"), d.get("networkId"))
               for d in statuses if d.get("networkId") in wanted and d.get("serial")]
    ifaces = sorted({u.get("interface") for d in statuses
                     for u in (d.get("uplinks") or [])
                     if d.get("networkId") in wanted and u.get("interface")})
    for serial, nid in serials:
        ip = None
        for d in dests.get(nid) or []:
            if d.get("ip"):
                ip = d["ip"]
                break
        if not ip:
            ip = "8.8.8.8"
        for iface in ifaces or ["wan1", "wan2"]:
            h = safe(f"loss/latency {serial} {iface}", hist_fn, serial, ip=ip,
                     uplink=iface, timespan=args.latency_days * 86400,
                     resolution=3600)
            if not h:
                continue
            loss = [x["lossPercent"] for x in h if x.get("lossPercent") is not None]
            lat = [x["latencyMs"] for x in h if x.get("latencyMs") is not None]
            jit = [x["jitter"] for x in h if x.get("jitter") is not None]
            good = [x["goodput"] for x in h if x.get("goodput") is not None]
            if not (loss or lat or jit):
                continue
            tag = dev_tag(serial, iface)
            print(f"  {serial} {iface} to {ip}, {args.latency_days}d hourly{tag}")
            if loss:
                bad = sum(1 for x in loss if x >= 1.0)
                print(f"    loss     mean {statistics.mean(loss):.2f}%  "
                      f"p95 {sorted(loss)[int(len(loss) * 0.95) - 1]:.2f}%  "
                      f"max {max(loss):.2f}%   "
                      f"hours at or above 1%: {bad}/{len(loss)}")
            if lat:
                print(f"    latency  mean {statistics.mean(lat):.1f} ms  "
                      f"p95 {sorted(lat)[int(len(lat) * 0.95) - 1]:.1f} ms  "
                      f"max {max(lat):.1f} ms")
            if jit:
                bad = sum(1 for x in jit if x >= 30.0)
                print(f"    jitter   mean {statistics.mean(jit):.1f} ms  "
                      f"p95 {sorted(jit)[int(len(jit) * 0.95) - 1]:.1f} ms  "
                      f"max {max(jit):.1f} ms   "
                      f"hours at or above 30 ms: {bad}/{len(jit)}")
            if good:
                print(f"    goodput  mean {statistics.mean(good):.0f} kbps  "
                      f"max {max(good):.0f} kbps")
            print()

    if args.csv and rows:
        with open(args.csv, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["network", "interface", "start_local",
                                              "sent_bytes", "received_bytes",
                                              "tx_bps", "rx_bps"])
            w.writeheader()
            w.writerows(rows)
        print(f"  {len(rows)} hourly samples written to {args.csv}")
        print()

    print("-" * 78)
    print("WHAT TO DO WITH THIS")
    print("-" * 78)
    print("  Section 2 first. It decides whether AT&T idling is a design or a")
    print("  fault, and nothing else in the file matters until that is settled.")
    print()
    print("  Section 5 second, and keep it. If a rule there writes DSCP 10, you")
    print("  have found the source of floor 3's 118 million discards and can say")
    print("  so with a configuration line rather than an inference. If nothing")
    print("  there writes DSCP at all, that is equally conclusive in the other")
    print("  direction: the marking is coming from the endpoints, and removing")
    print("  the switch QoS was right for a reason nobody has stated yet.")
    print()
    print("  Section 6 is the only direct evidence about the voice complaints")
    print("  that does not depend on a switch counter.")
    print()


if __name__ == "__main__":
    main()
