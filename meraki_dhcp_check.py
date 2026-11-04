#!/usr/bin/env python3
"""
meraki_dhcp_check.py - Why are clients failing DHCP?

The wireless deep dive tells you DHCP is failing. It does not tell you why.
There are only a few possible causes and each one has a different fix, so
this script checks them separately rather than reporting one number:

  1. CONFIG     - who serves DHCP for each VLAN, lease time, relay targets
  2. POOL        - used vs free addresses per subnet (exhaustion)
  3. ROGUE       - DHCP servers seen on the wire, and whether they're allowed
  4. FAILURES    - DHCP-step failed connections: by AP, by client, over time
  5. ORPHANS     - associated clients with no address, a 169.254 address,
                   or an address outside their VLAN's configured subnet
  6. EVENTS      - DHCP-related entries from the event log

A client with a 169.254 address or an address outside its own subnet is
evidence of a different kind of problem than a full pool, which is why
they are counted apart.

SAFETY: same three layers as the other scripts --
  1. PREFLIGHT  - aborts unless the key's admin account is read-only
  2. SIMULATE   - SDK constructed with simulate=True; writes become no-ops
  3. READ-ONLY  - only get* methods are called

Usage:
    export MERAKI_DASHBOARD_API_KEY='...'
    python3 meraki_dhcp_check.py --org-id 1586134
    python3 meraki_dhcp_check.py --org-id 1586134 --hours 2 --vlan 50
    python3 meraki_dhcp_check.py --org-id 1586134 --hours 24 --csv dhcp_fail.csv
"""

import argparse
import csv
import ipaddress
import os
import re
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

try:
    from zoneinfo import ZoneInfo
except ImportError:
    ZoneInfo = None

try:
    import meraki
except ImportError:
    sys.exit("Missing SDK. Install with: pip install meraki --break-system-packages")

# ---------------------------------------------------------------- thresholds

POOL_WARN = 80.0            # % of pool used
POOL_BAD = 90.0
AP_FAIL_WARN = 10           # DHCP failures on one AP in the window
AP_FAIL_BAD = 25
CLIENT_FAIL_WARN = 3        # one client failing this often is stuck in a loop

DHCP_PAT = re.compile(r"dhcp|lease|bootp", re.I)

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
        print("    ! %s: %s %s" % (label, type(e).__name__, str(e)[:90]),
              file=sys.stderr)
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
                bad.append("%s = %s" % (org["name"], a.get("orgAccess")))
    if bad:
        sys.exit("ABORT: API key has WRITE access to: " + ", ".join(bad))
    return email


# ---------------------------------------------------------------- helpers

def parse_ts(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except ValueError:
        return None


def fmt_ts(dt, tz):
    if dt is None:
        return "-"
    if tz is not None:
        dt = dt.astimezone(tz)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def events_list(res):
    if res is None:
        return []
    if isinstance(res, dict):
        return res.get("events") or []
    if isinstance(res, list):
        out = []
        for r in res:
            if isinstance(r, dict) and "events" in r:
                out.extend(r["events"] or [])
            elif isinstance(r, dict):
                out.append(r)
        return out
    return []


def flatten(obj, depth=0):
    if depth > 3:
        return ""
    if isinstance(obj, dict):
        return " ".join("%s=%s" % (k, flatten(v, depth + 1)) for k, v in obj.items())
    if isinstance(obj, (list, tuple)):
        return " ".join(flatten(v, depth + 1) for v in obj)
    return str(obj)


def step_of(row):
    """Failed-connection rows name the step in one of two fields depending on
    firmware. Check both rather than assuming."""
    for k in ("failureStep", "type", "step"):
        v = row.get(k)
        if v:
            return str(v).lower()
    return ""


def net_of(subnet):
    try:
        return ipaddress.ip_network(str(subnet), strict=False)
    except ValueError:
        return None


def bucket15(dt):
    if dt is None:
        return None
    return dt.replace(minute=(dt.minute // 15) * 15, second=0, microsecond=0)


def bar(n, scale):
    if scale <= 0:
        return ""
    return "#" * max(1, int(round(n * 40.0 / scale))) if n else ""


# ---------------------------------------------------------------- main

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--org-id", required=True)
    p.add_argument("--network", help="network name or ID substring")
    p.add_argument("--hours", type=float, default=2.0,
                   help="look back this many hours (default 2, max 168)")
    p.add_argument("--vlan", type=int, help="limit the failure views to one VLAN")
    p.add_argument("--floor", type=int, help="limit the AP views to one floor")
    p.add_argument("--csv", help="write DHCP-step failures here")
    p.add_argument("--tz", default="America/Los_Angeles")
    args = p.parse_args()

    key = os.environ.get("MERAKI_DASHBOARD_API_KEY")
    if not key:
        sys.exit("Set MERAKI_DASHBOARD_API_KEY first.")

    hours = min(args.hours, 168.0)
    timespan = int(hours * 3600)

    tz = None
    if ZoneInfo is not None:
        try:
            tz = ZoneInfo(args.tz)
        except Exception:
            pass

    dash = meraki.DashboardAPI(api_key=key, simulate=True,
                               wait_on_rate_limit=True, maximum_retries=5,
                               suppress_logging=True, print_console=False)
    who = preflight(dash)

    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    print("=" * 78)
    print("DHCP HEALTH CHECK")
    print("=" * 78)
    print("  key      read-only (%s)" % who)
    print("  window   %s -> now  (%.1f h)" % (fmt_ts(since, tz), hours))
    if args.vlan:
        print("  vlan     %d" % args.vlan)
    if args.floor:
        print("  floor    %d" % args.floor)

    nets = safe("networks", dash.organizations.getOrganizationNetworks,
                args.org_id, total_pages="all") or []
    if args.network:
        q = args.network.lower()
        nets = [n for n in nets
                if q in (n.get("name") or "").lower() or q in n["id"].lower()]
    if not nets:
        sys.exit("No networks matched.")

    devs = safe("devices", dash.organizations.getOrganizationDevices,
                args.org_id, total_pages="all") or []
    name_of = {d["serial"]: (d.get("name") or d["serial"]) for d in devs}
    mxs = [d for d in devs if (d.get("model") or "").upper().startswith("MX")]

    def floor_of(name):
        m = re.search(r"AP\s*(\d)\d\d", name or "", re.I)
        return int(m.group(1)) if m else None

    verdicts = []

    # ---------------------------------------------------------- 1. config
    print()
    print("=" * 78)
    print("1. WHO SERVES DHCP, AND HOW")
    print("=" * 78)
    vlan_cfg = {}
    for n in nets:
        if "appliance" not in (n.get("productTypes") or []):
            continue
        vlans = safe("vlans %s" % n["name"],
                     dash.appliance.getNetworkApplianceVlans, n["id"])
        if vlans is None:
            print("  %s: VLANs not readable (single-LAN mode, or no appliance)"
                  % n["name"])
            continue
        for v in vlans:
            vid = v.get("id")
            if args.vlan and str(vid) != str(args.vlan):
                continue
            vlan_cfg[str(vid)] = v
            handling = v.get("dhcpHandling") or "?"
            print("  VLAN %-5s %-22s %s" % (vid, (v.get("name") or "")[:22],
                                            handling))
            print("      subnet        %s   gateway %s" %
                  (v.get("subnet") or "?", v.get("applianceIp") or "?"))
            nw = net_of(v.get("subnet"))
            if nw is not None:
                print("      addresses     %d usable in the subnet" %
                      max(0, nw.num_addresses - 2))
            if v.get("dhcpLeaseTime"):
                print("      lease time    %s" % v["dhcpLeaseTime"])
            relays = v.get("dhcpRelayServerIps") or []
            if relays:
                print("      relay to      %s" % ", ".join(relays))
            res = v.get("reservedIpRanges") or []
            for r in res:
                print("      reserved      %s - %s  (%s)" %
                      (r.get("start"), r.get("end"), r.get("comment") or ""))
            fixed = v.get("fixedIpAssignments") or {}
            if fixed:
                print("      fixed         %d static assignment(s)" % len(fixed))
            if "relay" in handling.lower():
                print("      NOTE: the MX is not the server for this VLAN, so")
                print("            pool usage below will be blank. Check the")
                print("            relay target's own scope.")
            elif "not" in handling.lower() or "do not" in handling.lower():
                verdicts.append(("WARN", "VLAN %s: DHCP handling is %r -- "
                                         "something else must be answering"
                                 % (vid, handling)))
    if not vlan_cfg:
        print("  No appliance VLAN config readable. If DHCP is served by a")
        print("  Catalyst SVI or a Windows/Linux server, check it there:")
        print("    show run interface vlan <id> | include helper|dhcp")
        print("    show ip dhcp pool / show ip dhcp binding | count")

    # ---------------------------------------------------------- 2. pool
    print()
    print("=" * 78)
    print("2. POOL UTILIZATION  (is it exhausted?)")
    print("=" * 78)
    any_pool = False
    for mx in mxs:
        subs = safe("dhcp subnets %s" % mx["serial"],
                    dash.appliance.getDeviceApplianceDhcpSubnets, mx["serial"])
        if not subs:
            continue
        any_pool = True
        print("  %s (%s)" % (name_of.get(mx["serial"], mx["serial"]), mx["model"]))
        print("    %-6s %-20s %8s %8s %7s" %
              ("vlan", "subnet", "used", "free", "used%"))
        for s in subs:
            vid = s.get("vlanId")
            if args.vlan and str(vid) != str(args.vlan):
                continue
            used = s.get("usedCount")
            free = s.get("freeCount")
            tot = None
            pct = None
            if isinstance(used, int) and isinstance(free, int):
                tot = used + free
                pct = (100.0 * used / tot) if tot else None
            print("    %-6s %-20s %8s %8s %7s" %
                  (vid, s.get("subnet") or "?",
                   used if used is not None else "-",
                   free if free is not None else "-",
                   ("%.1f" % pct) if pct is not None else "-"))
            if pct is not None and pct >= POOL_BAD:
                verdicts.append(("HIGH", "VLAN %s pool is %.1f%% used (%d free) "
                                         "-- exhaustion will present as DHCP "
                                         "failures" % (vid, pct, free)))
            elif pct is not None and pct >= POOL_WARN:
                verdicts.append(("WARN", "VLAN %s pool is %.1f%% used (%d free)"
                                 % (vid, pct, free)))
    if not any_pool:
        print("  No MX-served DHCP pools readable. Either DHCP is relayed or")
        print("  served elsewhere -- see the note in section 1.")

    # ---------------------------------------------------------- 3. rogue
    print()
    print("=" * 78)
    print("3. DHCP SERVERS SEEN ON THE WIRE  (rogue detection)")
    print("=" * 78)
    saw_any = False
    for n in nets:
        if "switch" not in (n.get("productTypes") or []):
            continue
        seen = safe("dhcp servers %s" % n["name"],
                    dash.switch.getNetworkSwitchDhcpV4ServersSeen,
                    n["id"], timespan=timespan, total_pages="all")
        if not seen:
            continue
        saw_any = True
        print("  %-16s %-18s %-6s %-9s %s" %
              ("MAC", "IP", "vlan", "allowed", "last seen"))
        for s in seen:
            allowed = s.get("isAllowed")
            ipaddr = (s.get("ipv4") or {}).get("address") or "?"
            print("  %-16s %-18s %-6s %-9s %s" %
                  (s.get("mac") or "?", ipaddr, s.get("vlan") or "?",
                   "yes" if allowed else "NO",
                   fmt_ts(parse_ts(s.get("lastAck", {}).get("ts")
                                   if isinstance(s.get("lastAck"), dict)
                                   else s.get("lastSeenAt")), tz)))
            if allowed is False:
                verdicts.append(("HIGH", "Unapproved DHCP server %s at %s on "
                                         "VLAN %s" % (s.get("mac"), ipaddr,
                                                      s.get("vlan"))))
    if not saw_any:
        print("  This endpoint only reports what Meraki switches observe, and")
        print("  your access layer is Catalyst, so nothing is expected here.")
        print("  Section 5 (orphan addresses) is the substitute signal, and on")
        print("  the switch side:")
        print("    show ip dhcp snooping binding")
        print("    show ip dhcp conflict")
        print("    show ip device tracking all | include 10.50.")

    # ---------------------------------------------------------- 4. failures
    print()
    print("=" * 78)
    print("4. DHCP-STEP FAILED CONNECTIONS")
    print("=" * 78)
    rows = []
    step_tally = Counter()
    for n in nets:
        if "wireless" not in (n.get("productTypes") or []):
            continue
        kw = dict(timespan=timespan)
        if args.vlan:
            kw["vlan"] = args.vlan
        fails = safe("failed conns %s" % n["name"],
                     dash.wireless.getNetworkWirelessFailedConnections,
                     n["id"], **kw)
        if fails is None and args.vlan:
            kw.pop("vlan", None)
            fails = safe("failed conns %s (no vlan filter)" % n["name"],
                         dash.wireless.getNetworkWirelessFailedConnections,
                         n["id"], **kw)
        for f in (fails or []):
            st = step_of(f)
            step_tally[st or "?"] += 1
            if "dhcp" not in st:
                continue
            serial = f.get("serial") or ""
            ap = name_of.get(serial, serial or "-")
            fl = floor_of(ap)
            if args.floor and fl != args.floor:
                continue
            if args.vlan and f.get("vlan") is not None and \
                    str(f.get("vlan")) != str(args.vlan):
                continue
            dt = parse_ts(f.get("ts"))
            rows.append({
                "time": fmt_ts(dt, tz),
                "_dt": dt,
                "ap": ap,
                "ap_serial": serial,
                "floor": fl if fl is not None else "",
                "client_mac": f.get("clientMac") or "",
                "vlan": f.get("vlan") if f.get("vlan") is not None else "",
                "ssid": f.get("ssidNumber") if f.get("ssidNumber") is not None else "",
                "step": st,
            })

    print("  all failure steps in window: %s" %
          (dict(step_tally) if step_tally else "none"))
    print("  DHCP-step failures: %d" % len(rows))

    if rows:
        rows.sort(key=lambda r: (r["_dt"] or datetime.min.replace(tzinfo=timezone.utc)))

        by_ap = Counter(r["ap"] for r in rows)
        print()
        print("  by access point:")
        top = by_ap.most_common()
        scale = top[0][1] if top else 1
        for ap, c in top:
            flag = ""
            if c >= AP_FAIL_BAD:
                flag = "  !!"
            elif c >= AP_FAIL_WARN:
                flag = "  !"
            print("    %-14s %5d  %-40s%s" % (ap[:14], c, bar(c, scale), flag))
        for ap, c in top:
            if c >= AP_FAIL_BAD:
                verdicts.append(("HIGH", "%s: %d DHCP failures in %.1fh"
                                 % (ap, c, hours)))
                break

        by_client = Counter(r["client_mac"] for r in rows if r["client_mac"])
        repeat = [(m, c) for m, c in by_client.most_common()
                  if c >= CLIENT_FAIL_WARN]
        print()
        print("  distinct clients affected: %d" % len(by_client))
        if repeat:
            print("  clients failing %d+ times (stuck in a retry loop):"
                  % CLIENT_FAIL_WARN)
            for m, c in repeat[:15]:
                print("    %-18s %4d" % (m, c))
            if len(by_client) and len(repeat) * 1.0 / len(by_client) > 0.5:
                verdicts.append(("WARN", "%d of %d affected clients failed 3+ "
                                         "times -- retry loops, not one-offs"
                                 % (len(repeat), len(by_client))))
        else:
            print("  No client failed %d+ times -- failures are spread thin,"
                  % CLIENT_FAIL_WARN)
            print("  which points at transient load rather than a stuck scope.")

        buckets = Counter()
        for r in rows:
            b = bucket15(r["_dt"])
            if b is not None:
                buckets[b] += 1
        if buckets:
            print()
            print("  timeline (15-minute buckets):")
            mx = max(buckets.values())
            for b in sorted(buckets):
                print("    %-17s %4d  %s" %
                      (fmt_ts(b, tz)[11:16], buckets[b], bar(buckets[b], mx)))
            print()
            print("  A flat line is steady-state pressure. A spike is an event --")
            print("  compare it against the complaint time and the change log.")

    # ---------------------------------------------------------- 5. orphans
    print()
    print("=" * 78)
    print("5. CLIENTS WITH NO ADDRESS, OR THE WRONG ONE")
    print("=" * 78)
    no_ip = []
    link_local = []
    off_subnet = []
    total_clients = 0
    for n in nets:
        cl = safe("clients %s" % n["name"], dash.networks.getNetworkClients,
                  n["id"], timespan=timespan, perPage=1000, total_pages="all") or []
        for c in cl:
            total_clients += 1
            ip = c.get("ip") or ""
            vid = c.get("vlan")
            if args.vlan and str(vid) != str(args.vlan):
                continue
            label = "%s  %s  vlan=%s  ap=%s" % (
                (c.get("description") or c.get("mac") or "?")[:22],
                ip or "(none)", vid,
                name_of.get(c.get("recentDeviceSerial"), "") or
                c.get("recentDeviceName") or "-")
            if not ip:
                no_ip.append(label)
                continue
            if ip.startswith("169.254."):
                link_local.append(label)
                continue
            v = vlan_cfg.get(str(vid))
            if v is not None:
                nw = net_of(v.get("subnet"))
                try:
                    if nw is not None and ipaddress.ip_address(ip) not in nw:
                        off_subnet.append(label + "  (expected %s)"
                                          % v.get("subnet"))
                except ValueError:
                    pass

    print("  clients seen in window: %d" % total_clients)
    print("  no address:             %d" % len(no_ip))
    print("  169.254.x.x:            %d" % len(link_local))
    print("  outside their subnet:   %d" % len(off_subnet))

    for title, lst, sev, why in (
            ("169.254 (DHCP never answered)", link_local, "HIGH",
             "a self-assigned address means no server replied at all"),
            ("outside the configured subnet", off_subnet, "HIGH",
             "an address from the wrong scope is a second DHCP server"),
            ("no address recorded", no_ip, "WARN",
             "may be transient, or may be clients that never completed DHCP")):
        if lst:
            print()
            print("  --- %s ---" % title)
            for s in lst[:20]:
                print("    %s" % s)
            if len(lst) > 20:
                print("    ... and %d more" % (len(lst) - 20))
            verdicts.append((sev, "%d client(s) %s -- %s"
                             % (len(lst), title, why)))

    # ---------------------------------------------------------- 6. events
    print()
    print("=" * 78)
    print("6. DHCP-RELATED EVENTS")
    print("=" * 78)
    since_iso = since.strftime("%Y-%m-%dT%H:%M:%SZ")
    found = 0
    for n in nets:
        ptypes = n.get("productTypes") or []
        types = safe("event types %s" % n["name"],
                     dash.networks.getNetworkEventsEventTypes, n["id"]) or []
        want = sorted({t["type"] for t in types
                       if DHCP_PAT.search("%s %s" % (t.get("type", ""),
                                                     t.get("description", "")))})
        if want:
            print("  %s: matching event types -> %s" % (n["name"], ", ".join(want)))
        for pt in ("appliance", "wireless", "switch"):
            if pt not in ptypes:
                continue
            kw = dict(productType=pt, perPage=1000, startingAfter=since_iso,
                      total_pages=3)
            if want:
                kw["includedEventTypes"] = want
            res = safe("events %s/%s" % (n["name"], pt),
                       dash.networks.getNetworkEvents, n["id"], **kw)
            if res is None and want:
                kw.pop("includedEventTypes", None)
                res = safe("events %s/%s unfiltered" % (n["name"], pt),
                           dash.networks.getNetworkEvents, n["id"], **kw)
            for ev in events_list(res):
                blob = flatten(ev)
                if not DHCP_PAT.search(blob):
                    continue
                found += 1
                if found > 60:
                    continue
                print("  %-19s %-10s %-22s %s" %
                      (fmt_ts(parse_ts(ev.get("occurredAt")), tz), pt,
                       str(ev.get("type"))[:22],
                       (ev.get("description") or "")[:34]))
    if found == 0:
        print("  No DHCP-related events in the window.")
    elif found > 60:
        print("  ... and %d more (showing first 60)" % (found - 60))

    # ---------------------------------------------------------- verdict
    print()
    print("=" * 78)
    print("VERDICT")
    print("=" * 78)
    if not verdicts:
        print("  Nothing crossed a threshold. If users are still failing DHCP,")
        print("  the server is not the MX -- chase it on the Catalyst SVI or")
        print("  wherever ip helper-address points.")
    else:
        order = {"HIGH": 0, "WARN": 1}
        for sev, msg in sorted(verdicts, key=lambda x: order.get(x[0], 2)):
            print("  [%s] %s" % (sev, msg))

    if args.csv and rows:
        cols = ["time", "ap", "ap_serial", "floor", "client_mac", "vlan",
                "ssid", "step"]
        with open(args.csv, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
            w.writeheader()
            w.writerows(rows)
        print()
        print("  Wrote %s (%d rows)" % (args.csv, len(rows)))

    print()


if __name__ == "__main__":
    main()
