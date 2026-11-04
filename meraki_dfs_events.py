#!/usr/bin/env python3
"""
meraki_dfs_events.py - Did DFS actually happen, or did someone change the config?

A radar hit on a DFS channel is a logged, timestamped event. So is a
configuration change. This script pulls both for a time window and lays them
side by side, so "it was DFS" becomes a claim you can confirm or refute
instead of a claim you have to accept.

What it reports:
  1. The event types this network actually publishes that mention DFS, radar
     or channel changes -- discovered from the API, not guessed.
  2. Every matching event in the window: when, which AP, which channel.
  3. Per-AP summary with estimated non-occupancy time (30 min per radar hit).
  4. The current 5 GHz channel plan, flagging DFS and TDWR channels.
  5. Whether the RF profile even permits DFS channels. If it doesn't, DFS
     cannot have happened and the conversation is over.
  6. With --changes: the org configuration change log for the same window --
     who touched what, and when.

SAFETY: same three layers as the other scripts --
  1. PREFLIGHT  - aborts unless the key's admin account is read-only
  2. SIMULATE   - SDK constructed with simulate=True; writes become no-ops
  3. READ-ONLY  - only get* methods are called

Usage:
    export MERAKI_DASHBOARD_API_KEY='...'
    python3 meraki_dfs_events.py --org-id 1586134 --hours 12
    python3 meraki_dfs_events.py --org-id 1586134 --floor 5 --hours 12 --changes
    python3 meraki_dfs_events.py --org-id 1586134 --floor 5 --csv dfs.csv
"""

import argparse
import csv
import os
import re
import sys
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone

try:
    from zoneinfo import ZoneInfo
except ImportError:
    ZoneInfo = None

try:
    import meraki
except ImportError:
    sys.exit("Missing SDK. Install with: pip install meraki --break-system-packages")

# ---------------------------------------------------------------- constants

DFS_CHANNELS = {52, 56, 60, 64,
                100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144}
TDWR_CHANNELS = {120, 124, 128}          # 5600-5650 MHz, SFO has a TDWR
NON_OCCUPANCY_MIN = 30                   # FCC: stay off the channel this long

# Event types are matched against these, case-insensitively. Meraki's naming
# has changed across firmware, so match loosely rather than hard-coding.
EVENT_PAT = re.compile(r"dfs|radar", re.I)
CHANNEL_PAT = re.compile(r"chan", re.I)

# Pull a channel number out of free-text event descriptions.
CHAN_NUM_PAT = re.compile(r"channel\s*[:=]?\s*(\d{1,3})", re.I)

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
    """Refuse to run on a key that can write anything, anywhere."""
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

def floor_of(name):
    """SFAP502 -> 5. Returns None if the name doesn't follow the convention."""
    m = re.search(r"AP\s*(\d)\d\d", name or "", re.I)
    return int(m.group(1)) if m else None


def events_list(res):
    """getNetworkEvents returns a dict; with total_pages it may return a list
    of dicts. Flatten either shape into a plain list of events."""
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


def parse_ts(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def fmt_ts(dt, tz):
    if dt is None:
        return "-"
    if tz is not None:
        dt = dt.astimezone(tz)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def flatten(obj, depth=0):
    """Squash an event's nested dicts into one searchable string."""
    if depth > 3:
        return ""
    if isinstance(obj, dict):
        return " ".join("%s=%s" % (k, flatten(v, depth + 1))
                        for k, v in obj.items())
    if isinstance(obj, (list, tuple)):
        return " ".join(flatten(v, depth + 1) for v in obj)
    return str(obj)


def channel_of(ev):
    """Best-effort channel number from an event's payload or description."""
    ed = ev.get("eventData") or {}
    for k in ("channel", "newChannel", "new_channel", "radio_channel"):
        v = ed.get(k)
        if v is not None:
            try:
                return int(str(v).split(",")[0])
            except (ValueError, TypeError):
                pass
    m = CHAN_NUM_PAT.search(flatten(ev))
    if m:
        try:
            return int(m.group(1))
        except ValueError:
            pass
    return None


def band_note(ch):
    if ch is None:
        return ""
    if ch in TDWR_CHANNELS:
        return "DFS/TDWR"
    if ch in DFS_CHANNELS:
        return "DFS"
    if ch <= 14:
        return "2.4GHz"
    return "non-DFS"


# ---------------------------------------------------------------- main

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--org-id", required=True)
    p.add_argument("--network", help="network name or ID substring; default: "
                                     "every wireless network in the org")
    p.add_argument("--hours", type=float, default=24.0,
                   help="look back this many hours (default 24)")
    p.add_argument("--floor", type=int, help="limit the AP views to one floor")
    p.add_argument("--pages", type=int, default=5,
                   help="max event pages to pull per network (default 5)")
    p.add_argument("--changes", action="store_true",
                   help="also pull the org configuration change log")
    p.add_argument("--csv", help="write the matched events here")
    p.add_argument("--tz", default="America/Los_Angeles",
                   help="timezone for printed timestamps")
    p.add_argument("--all-types", action="store_true",
                   help="ignore type discovery and scan every wireless event "
                        "(slower, catches oddly-named types)")
    args = p.parse_args()

    key = os.environ.get("MERAKI_DASHBOARD_API_KEY")
    if not key:
        sys.exit("Set MERAKI_DASHBOARD_API_KEY first.")

    tz = None
    if ZoneInfo is not None:
        try:
            tz = ZoneInfo(args.tz)
        except Exception:
            print("  (unknown timezone %r, printing UTC)" % args.tz)

    dash = meraki.DashboardAPI(api_key=key, simulate=True,
                               wait_on_rate_limit=True, maximum_retries=5,
                               suppress_logging=True, print_console=False)
    who = preflight(dash)

    since = datetime.now(timezone.utc) - timedelta(hours=args.hours)
    since_iso = since.strftime("%Y-%m-%dT%H:%M:%SZ")

    print("=" * 78)
    print("DFS / CHANNEL-CHANGE AUDIT")
    print("=" * 78)
    print("  key           read-only (%s)" % who)
    print("  window        %s  ->  now  (%.1f h)" % (fmt_ts(since, tz), args.hours))
    print("  timestamps    %s" % (args.tz if tz else "UTC"))
    if args.floor:
        print("  floor filter  %d" % args.floor)

    # ---- networks
    nets = safe("networks", dash.organizations.getOrganizationNetworks,
                args.org_id, total_pages="all") or []
    wnets = [n for n in nets if "wireless" in (n.get("productTypes") or [])]
    if args.network:
        q = args.network.lower()
        wnets = [n for n in wnets
                 if q in (n.get("name") or "").lower() or q in n["id"].lower()]
    if not wnets:
        sys.exit("No wireless networks matched.")
    print("  networks      %s" % ", ".join(n["name"] for n in wnets))

    # ---- devices, for serial -> name
    devs = safe("devices", dash.organizations.getOrganizationDevices,
                args.org_id, total_pages="all") or []
    name_of = {}
    aps = []
    for d in devs:
        name_of[d["serial"]] = d.get("name") or d["serial"]
        if (d.get("model") or "").upper().startswith("MR"):
            aps.append(d)
    if args.floor:
        aps = [a for a in aps if floor_of(a.get("name")) == args.floor]
    print("  APs in scope  %d" % len(aps))

    # ---- what does this network actually call a DFS event?
    matched_types = []
    for n in wnets:
        types = safe("event types %s" % n["name"],
                     dash.networks.getNetworkEventsEventTypes, n["id"]) or []
        for t in types:
            blob = "%s %s %s" % (t.get("type", ""), t.get("description", ""),
                                 t.get("category", ""))
            if EVENT_PAT.search(blob) or CHANNEL_PAT.search(blob):
                matched_types.append(t)

    seen = set()
    uniq_types = []
    for t in matched_types:
        if t.get("type") not in seen:
            seen.add(t.get("type"))
            uniq_types.append(t)

    print()
    print("-" * 78)
    print("EVENT TYPES PUBLISHED BY THIS NETWORK THAT MENTION DFS/RADAR/CHANNEL")
    print("-" * 78)
    if uniq_types:
        for t in uniq_types:
            print("  %-34s %s" % (t.get("type", "?"),
                                  (t.get("description") or "")[:40]))
    else:
        print("  none -- the API lists no event type mentioning DFS, radar or")
        print("  channel for this network. Scanning all wireless events instead.")

    use_types = [t["type"] for t in uniq_types] if uniq_types else None
    if args.all_types:
        use_types = None

    # ---- pull the events
    rows = []
    for n in wnets:
        kw = dict(productType="wireless", perPage=1000,
                  startingAfter=since_iso, total_pages=args.pages)
        if use_types:
            kw["includedEventTypes"] = use_types
        res = safe("events %s" % n["name"], dash.networks.getNetworkEvents,
                   n["id"], **kw)
        if res is None and use_types:
            # A rejected type list is a 400. Retry unfiltered rather than
            # silently reporting zero events.
            print("    (type filter rejected; retrying unfiltered)",
                  file=sys.stderr)
            kw.pop("includedEventTypes", None)
            res = safe("events %s unfiltered" % n["name"],
                       dash.networks.getNetworkEvents, n["id"], **kw)

        for ev in events_list(res):
            blob = flatten(ev)
            if not (EVENT_PAT.search(blob) or CHANNEL_PAT.search(blob)):
                continue
            serial = ev.get("deviceSerial") or ""
            apname = ev.get("deviceName") or name_of.get(serial, serial or "-")
            fl = floor_of(apname)
            if args.floor and fl != args.floor:
                continue
            ts = parse_ts(ev.get("occurredAt"))
            ch = channel_of(ev)
            rows.append({
                "time": fmt_ts(ts, tz),
                "time_utc": ev.get("occurredAt") or "",
                "_dt": ts,
                "network": n["name"],
                "ap": apname,
                "ap_serial": serial,
                "floor": fl if fl is not None else "",
                "type": ev.get("type") or "",
                "channel": ch if ch is not None else "",
                "band": band_note(ch),
                "description": (ev.get("description") or "")[:70],
                "radar": "yes" if EVENT_PAT.search(blob) else "",
            })

    rows.sort(key=lambda r: (r["_dt"] or datetime.min.replace(tzinfo=timezone.utc)))

    print()
    print("=" * 78)
    print("MATCHED EVENTS IN WINDOW  (%d)" % len(rows))
    print("=" * 78)
    if not rows:
        print("  Nothing. No DFS, radar or channel-change event was logged for")
        print("  these APs in the last %.1f hours." % args.hours)
        print()
        print("  That is the answer to the question. If the APs were on DFS")
        print("  channels and an outage occurred, something other than radar")
        print("  caused it. Run with --changes to see who edited what.")
    else:
        print("  %-19s %-12s %-5s %-24s %-4s %-9s" %
              ("time", "AP", "floor", "type", "chan", "band"))
        print("  " + "-" * 76)
        for r in rows:
            print("  %-19s %-12s %-5s %-24s %-4s %-9s" %
                  (r["time"], str(r["ap"])[:12], r["floor"],
                   str(r["type"])[:24], r["channel"], r["band"]))
            if r["description"]:
                print("  %19s %s" % ("", r["description"]))

        # ---- per-AP summary
        per_ap = defaultdict(lambda: {"n": 0, "radar": 0, "chans": set()})
        for r in rows:
            s = per_ap[r["ap"]]
            s["n"] += 1
            if r["radar"]:
                s["radar"] += 1
            if r["channel"] != "":
                s["chans"].add(r["channel"])

        print()
        print("-" * 78)
        print("PER-AP SUMMARY")
        print("-" * 78)
        print("  %-14s %6s %6s %7s  channels" % ("AP", "events", "radar", "min off"))
        print("  " + "-" * 64)
        for ap in sorted(per_ap, key=lambda k: -per_ap[k]["radar"]):
            s = per_ap[ap]
            chans = ",".join(str(c) for c in sorted(s["chans"]))
            print("  %-14s %6d %6d %7d  %s" %
                  (ap[:14], s["n"], s["radar"],
                   s["radar"] * NON_OCCUPANCY_MIN, chans))
        print()
        print("  'min off' = radar hits x %d min FCC non-occupancy. It is the"
              % NON_OCCUPANCY_MIN)
        print("  floor on how long that AP was unavailable on that channel,")
        print("  not a measurement -- the AP moves elsewhere immediately.")

    # ---- current channel plan
    print()
    print("=" * 78)
    print("CURRENT 5 GHz CHANNEL PLAN")
    print("=" * 78)
    if not aps:
        print("  No APs in scope.")
    else:
        print("  %-14s %-8s %6s %7s %-9s %s" %
              ("AP", "status", "chan", "width", "band", "power"))
        print("  " + "-" * 66)
        statuses = {}
        st = safe("statuses", dash.organizations.getOrganizationDevicesStatuses,
                  args.org_id, total_pages="all") or []
        for s in st:
            statuses[s.get("serial")] = s.get("status")
        dfs_in_use = 0
        tdwr_in_use = 0
        for a in sorted(aps, key=lambda d: d.get("name") or ""):
            rs = safe("radio %s" % a["serial"],
                      dash.wireless.getDeviceWirelessRadioSettings, a["serial"])
            five = (rs or {}).get("fiveGhzSettings") or {}
            ch = five.get("channel")
            try:
                chi = int(ch)
            except (TypeError, ValueError):
                chi = None
            if chi in TDWR_CHANNELS:
                tdwr_in_use += 1
            elif chi in DFS_CHANNELS:
                dfs_in_use += 1
            print("  %-14s %-8s %6s %7s %-9s %s" %
                  ((a.get("name") or a["serial"])[:14],
                   statuses.get(a["serial"]) or "?",
                   ch if ch is not None else "auto",
                   five.get("channelWidth") or "-",
                   band_note(chi),
                   five.get("targetPower") if five.get("targetPower") is not None
                   else "auto"))
        print()
        print("  %d AP(s) currently on a DFS channel, %d on a TDWR channel "
              "(120/124/128)." % (dfs_in_use, tdwr_in_use))
        if dfs_in_use == 0 and tdwr_in_use == 0:
            print("  No AP in scope is on a DFS channel right now. A radar event")
            print("  cannot affect a channel nobody is using.")

    # ---- does the RF profile even allow DFS?
    print()
    print("=" * 78)
    print("RF PROFILES - IS DFS EVEN PERMITTED?")
    print("=" * 78)
    for n in wnets:
        profs = safe("rf profiles %s" % n["name"],
                     dash.wireless.getNetworkWirelessRfProfiles, n["id"]) or []
        for pr in profs:
            five = pr.get("fiveGhzSettings") or {}
            valid = five.get("validAutoChannels")
            if valid is None:
                continue
            vset = set()
            for c in valid:
                try:
                    vset.add(int(c))
                except (TypeError, ValueError):
                    pass
            dfs_allowed = sorted(vset & DFS_CHANNELS)
            tdwr_allowed = sorted(vset & TDWR_CHANNELS)
            print("  %s" % (pr.get("name") or pr.get("id")))
            print("      width         %s MHz" % (five.get("channelWidth") or "?"))
            print("      auto channels %s" % ",".join(str(c) for c in sorted(vset)))
            if dfs_allowed:
                print("      DFS allowed   yes: %s" %
                      ",".join(str(c) for c in dfs_allowed))
                if tdwr_allowed:
                    print("      TDWR allowed  YES: %s  <-- deselect these; SFO "
                          "has a TDWR" % ",".join(str(c) for c in tdwr_allowed))
                else:
                    print("      TDWR allowed  no (good)")
            else:
                print("      DFS allowed   NO -- radar cannot have moved these APs")

    # ---- who changed what
    if args.changes:
        print()
        print("=" * 78)
        print("CONFIGURATION CHANGES IN THE SAME WINDOW")
        print("=" * 78)
        ch = safe("change log",
                  dash.organizations.getOrganizationConfigurationChanges,
                  args.org_id, timespan=min(args.hours * 3600, 2678400),
                  total_pages="all") or []
        if not ch:
            print("  No configuration changes logged in this window.")
        else:
            wifi_pat = re.compile(r"rf|radio|channel|ssid|wireless|power|dfs", re.I)
            print("  %-19s %-26s %s" % ("time", "admin", "what"))
            print("  " + "-" * 74)
            for c in ch:
                ts = parse_ts(c.get("ts"))
                label = "%s / %s" % (c.get("page") or "?", c.get("label") or "?")
                line = "  %-19s %-26s %s" % (
                    fmt_ts(ts, tz), (c.get("adminName") or "?")[:26], label[:60])
                if wifi_pat.search(label):
                    line += "   <-- wireless"
                print(line)
                if c.get("oldValue") is not None or c.get("newValue") is not None:
                    print("  %19s   %s -> %s" %
                          ("", str(c.get("oldValue"))[:28],
                           str(c.get("newValue"))[:28]))
            print()
            print("  Any line marked '<-- wireless' is a change that could produce")
            print("  the same observable as a radar event: APs on new channels.")

    # ---- csv
    if args.csv and rows:
        cols = ["time", "time_utc", "network", "ap", "ap_serial", "floor",
                "type", "channel", "band", "radar", "description"]
        with open(args.csv, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
            w.writeheader()
            w.writerows(rows)
        print()
        print("  Wrote %s (%d rows)" % (args.csv, len(rows)))

    print()


if __name__ == "__main__":
    main()
