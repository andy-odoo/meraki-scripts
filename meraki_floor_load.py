#!/usr/bin/env python3
"""
meraki_floor_load.py - Is this floor starved of radios, or is it something else?

Written 2 November 2026, the first full-occupancy day since Beautiful Networks
disabled 25 of floor 3's 33 five-gigahertz radios on 28 October. The impact
analysis run that week found no effect and said so with a caveat: the office
was nearly empty, so it would catch a large effect and nothing subtle, and it
should be re-run once staff were back. Staff are back and floor 3 is in
trouble, which is exactly the case that measurement could not see.

The question is not "is it bad" -- that is already known. It is WHICH of three
things is bad, because they have opposite fixes:

                        clients per   802.11      non-WiFi
                        live radio    utilisation utilisation  RSSI   SNR
  capacity starvation       HIGH         HIGH         low      good   good
  coverage hole           normal          low         low      POOR   poor
  non-WiFi interference   normal          low        HIGH      good   POOR

  capacity starvation  -> turn radios back on; the cure caused the disease
  coverage hole        -> turn SPECIFIC radios back on, where the gaps are
  interference         -> radio count is irrelevant; find the emitter

Section 5 applies that table. It is a reading of the evidence, not a verdict,
and it says which way each piece of evidence points rather than only the
conclusion.

TWO THINGS THIS GETS RIGHT THAT ARE EASY TO GET WRONG.

Radio state is read from getDeviceWirelessRadioSettings, NOT from
getDeviceWirelessStatus. The status endpoint lists one basic service set per
SSID per band and its 'enabled' flag describes the SSID, not the radio -- a
disabled radio still shows its SSIDs as enabled there. A channel or target
power of -1 in the radio settings is what a disabled radio looks like, and
that is how those 25 radios were turned off.

Load is per LIVE radio, not per access point. A floor with 33 access points
and 8 working radios is a floor with 8 radios. Dividing by 33 is the error
that made the 28 October analysis report no effect.

SAFETY: same three layers as the other scripts --
  1. PREFLIGHT  - aborts unless the key's admin account is read-only
  2. SIMULATE   - SDK constructed with simulate=True; writes become no-ops
  3. READ-ONLY  - only get* methods are called

Usage:
    export MERAKI_DASHBOARD_API_KEY='...'
    python3 meraki_floor_load.py --org-id 1586134 --floor 3
    python3 meraki_floor_load.py --org-id 1586134 --floor 3 --csv floor3.csv
    python3 meraki_floor_load.py --org-id 1586134 --floor 3 --hours 4
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

# Where channel utilisation starts to hurt. These are the conventional marks:
# above 50% total, contention is measurable in latency; above 70% a floor
# behaves the way people describe as "the wifi is broken".
UTIL_BUSY, UTIL_SATURATED = 50.0, 70.0
# Clients per live radio. A 5 GHz radio serves perhaps 25-30 active clients
# before airtime becomes the constraint; the exact number depends on what they
# are doing, so treat these as bands rather than thresholds.
CPR_BUSY, CPR_OVERLOADED = 25.0, 40.0
# Signal. Below these, the problem is coverage rather than contention.
RSSI_POOR, SNR_POOR = -72.0, 20.0

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


def radio_live(block):
    """Is this band's radio actually serving?

    Meraki disables a radio by setting its channel or target power to -1.
    Read from getDeviceWirelessRadioSettings; getDeviceWirelessStatus will
    happily report SSIDs as enabled on a radio that is switched off.
    Returns (live, channel, width, power).
    """
    b = block or {}
    ch, pw = b.get("channel"), b.get("targetPower")
    width = b.get("channelWidth")
    if ch == -1 or pw == -1:
        return False, None, None, None
    # Both fields absent means NO PER-RADIO OVERRIDE -- the radio follows its
    # RF profile and is live with automatic settings. Reading that as
    # "disabled" counted 13 of floor 2's 16 radios as dark on 2 November,
    # which inflated its clients-per-radio to 82.7 and made floor 3 look
    # BETTER than its neighbours when it was carrying nearly three times
    # their load. Those radios were serving clients and reporting airtime
    # at the time. Only -1 means off.
    return True, (ch if ch is not None else "auto"), width, pw


def _band_matches(value, want):
    """'5 GHz', '5', '2.4 GHz' and '2.4' all have to compare equal."""
    s = str(value or "").strip().lower().replace("ghz", "").strip()
    return s == str(want)


def _chan_of(bss):
    """The operating channel from a basic service set, wherever it is kept.

    The bulk endpoint nests radio attributes under 'radio'; the per-device one
    puts them at the top level. Accept either rather than guess.
    """
    for src in ((bss.get("radio") or {}), bss):
        v = src.get("channel")
        if isinstance(v, bool):
            continue
        if isinstance(v, int):
            return v
        if isinstance(v, str) and v.strip().isdigit():
            return int(v.strip())
    return None


def operating_channels(dash, org_id, serials, band):
    """serial -> the channel each radio is ACTUALLY on.

    The radio settings say what was configured, and 'auto' there tells you
    nothing: eight radios set to auto collapse into one meaningless row and
    the cross-floor overlap check compares 'auto' against 'auto'. This reads
    the live basic service sets instead, so an auto radio reports the channel
    auto-RF chose for it.

    hideDisabled is forced off. Its default hides access points whose SSIDs
    are disabled, and an SSID's enabled flag says nothing about whether the
    radio is up -- the same trap that made getDeviceWirelessStatus the wrong
    source for radio state in the first place.
    """
    out = {}

    def absorb(entry):
        serial = entry.get("serial") or (entry.get("device") or {}).get("serial")
        if not serial:
            return
        for bss in entry.get("basicServiceSets") or []:
            if not _band_matches(
                    (bss.get("radio") or {}).get("band", bss.get("band")), band):
                continue
            ch = _chan_of(bss)
            if ch is not None:
                out.setdefault(serial, ch)

    bulk = endpoint(dash, "wireless", "getOrganizationWirelessSsidsStatusesByDevice")
    if bulk is not None and serials:
        for i in range(0, len(serials), 100):
            chunk = serials[i:i + 100]
            res = safe("operating channels", bulk, org_id, serials=chunk,
                       hideDisabled=False, total_pages="all", perPage=500)
            if res is None:
                continue
            items = res.get("items") if isinstance(res, dict) else res
            for entry in items or []:
                absorb(entry)

    # Anything the bulk call did not cover, ask for one at a time.
    missing = [s for s in serials if s not in out]
    if missing:
        per = endpoint(dash, "wireless", "getDeviceWirelessStatus")
        for s in missing:
            res = safe(f"status {s}", per, s)
            if res:
                absorb({"serial": s, **res})
    return out


def fmt(x, unit="", nd=1):
    return "-" if x is None else f"{x:.{nd}f}{unit}"


def mean_or_none(v):
    return statistics.mean(v) if v else None


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--org-id", required=True)
    p.add_argument("--floor", default="3", help="floor in trouble")
    p.add_argument("--band", default="5", choices=["2.4", "5", "6"])
    p.add_argument("--hours", type=float, default=2.0,
                   help="how far back to average; 2 captures the morning peak")
    p.add_argument("--csv", help="write the per-AP rows here")
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

    now = datetime.now(LOCAL)
    span = int(args.hours * 3600)

    print("=" * 78)
    print(f"FLOOR {args.floor} LOAD - IS IT SHORT OF RADIOS?")
    print(f"org {args.org_id}   {args.band} GHz   "
          f"last {args.hours:g}h to {now:%Y-%m-%d %H:%M %Z}")
    print("=" * 78)

    nets = safe("networks", endpoint(dash, "organizations", "getOrganizationNetworks"),
                args.org_id, total_pages="all") or []
    wnets = [n for n in nets if "wireless" in (n.get("productTypes") or [])]
    if not wnets:
        sys.exit("No wireless networks in this org.")
    net = max(wnets, key=lambda n: len(n.get("productTypes") or []))

    devs = safe("devices", endpoint(dash, "organizations", "getOrganizationDevices"),
                args.org_id, total_pages="all") or []
    aps = {}
    for d in devs:
        if not str(d.get("model", "")).upper().startswith(("MR", "CW")):
            continue
        nm = d.get("name") or d.get("serial")
        aps[d["serial"]] = {"name": nm, "floor": floor_of(nm),
                            "model": d.get("model", "?")}
    floors = sorted({a["floor"] for a in aps.values() if a["floor"] != "?"})
    if args.floor not in floors:
        sys.exit(f"No access points named SFAP{args.floor}xx. Found floors: "
                 f"{', '.join(floors)}")

    # ---------------------------------------------------------------- 1
    print()
    print("-" * 78)
    print("1. WHAT IS ACTUALLY SERVING")
    print("-" * 78)
    print("  Read from the per-radio settings, not from the SSID list. A radio")
    print("  switched off still shows its SSIDs as enabled everywhere else.")
    print()

    key_band = "fiveGhzSettings" if args.band == "5" else (
        "twoFourGhzSettings" if args.band == "2.4" else "sixGhzSettings")
    rs_fn = endpoint(dash, "wireless", "getDeviceWirelessRadioSettings")
    radio = {}
    for serial, a in aps.items():
        if a["floor"] == "?":
            continue
        st = safe(f"radio {a['name']}", rs_fn, serial)
        if st is None:
            radio[serial] = {"known": False}
            continue
        live, ch, width, pw = radio_live(st.get(key_band))
        radio[serial] = {"known": True, "live": live, "ch": ch,
                         "width": width, "power": pw}

    unknown = [s for s, r in radio.items() if not r.get("known")]
    if unknown:
        print(f"  WARNING: radio settings unreadable for {len(unknown)} access")
        print("  point(s). Those are counted as unknown, never as live, so the")
        print("  load figures below are if anything too optimistic.")
        print()

    live_serials = [s for s, r in radio.items() if r.get("live")]
    oper = operating_channels(dash, args.org_id, live_serials, args.band)

    def chan_of(serial):
        """Operating channel where known, otherwise whatever was configured."""
        c = oper.get(serial)
        return c if c is not None else radio.get(serial, {}).get("ch")

    auto_n = sum(1 for s in live_serials if radio.get(s, {}).get("ch") == "auto")
    known = sum(1 for s in live_serials if oper.get(s) is not None)
    if auto_n:
        print(f"  {auto_n} radio(s) are set to auto; operating channels read "
              f"live for {known} of {len(live_serials)}.")
        print()

    by_floor = defaultdict(lambda: {"total": 0, "live": 0, "chans": defaultdict(list)})
    for serial, a in aps.items():
        f = a["floor"]
        if f == "?":
            continue
        r = radio.get(serial, {})
        by_floor[f]["total"] += 1
        if r.get("live"):
            by_floor[f]["live"] += 1
            by_floor[f]["chans"][chan_of(serial)].append(a["name"])

    print(f"  {'floor':6} {'APs':>5} {'radios live':>12} {'dark':>6}   channels in use")
    for f in floors:
        v = by_floor[f]
        dark = v["total"] - v["live"]
        chans = ", ".join(str(c) for c in sorted(v["chans"], key=str))
        mark = "   <-- the floor in question" if f == args.floor else ""
        print(f"  {f:6} {v['total']:>5} {v['live']:>12} {dark:>6}   "
              f"{chans[:40] or '(none)'}{mark}")

    tgt = by_floor[args.floor]
    print()
    if tgt["total"] and tgt["live"] < tgt["total"]:
        pctdark = 100.0 * (tgt["total"] - tgt["live"]) / tgt["total"]
        print(f"  Floor {args.floor} is running {tgt['live']} radios out of "
              f"{tgt['total']} access points — {pctdark:.0f}% dark.")
    elif tgt["total"]:
        print(f"  All {tgt['total']} radios on floor {args.floor} are serving.")

    # ---------------------------------------------------------------- 2
    print()
    print("-" * 78)
    print("2. LOAD PER LIVE RADIO")
    print("-" * 78)
    print("  Clients divided by radios that are actually on. The other floors")
    print("  are the control: same building, same hour, same people, radios")
    print("  untouched. A floor carrying three times the clients per radio of")
    print("  its neighbours is not suffering from the weather.")
    print()

    cl_fn = endpoint(dash, "networks", "getNetworkClients")
    clients = safe("clients", cl_fn, net["id"], timespan=span,
                   total_pages="all", perPage=1000) or []
    per_ap = defaultdict(int)
    for c in clients:
        s = (c.get("recentDeviceSerial") or c.get("deviceSerial")
             or (c.get("recentDeviceConnection") or {}).get("serial"))
        if s:
            per_ap[s] += 1
    if not per_ap:
        # Fall back to per-AP history when the client list carries no serial.
        cch = endpoint(dash, "wireless", "getNetworkWirelessClientCountHistory")
        for serial, a in aps.items():
            if a["floor"] != args.floor:
                continue
            h = safe(f"clients {a['name']}", cch, net["id"], deviceSerial=serial,
                     timespan=span, resolution=300, band=args.band) or []
            vals = [e.get("clientCount") for e in h if e.get("clientCount") is not None]
            if vals:
                per_ap[serial] = int(statistics.mean(vals))

    load = {}
    for f in floors:
        n_clients = sum(v for s, v in per_ap.items()
                        if aps.get(s, {}).get("floor") == f)
        live = by_floor[f]["live"]
        load[f] = {"clients": n_clients, "live": live,
                   "cpr": (n_clients / live) if live else None}

    print(f"  {'floor':6} {'clients':>8} {'live radios':>12} "
          f"{'clients/radio':>14}")
    for f in floors:
        v = load[f]
        flag = ""
        if v["cpr"] is not None:
            if v["cpr"] >= CPR_OVERLOADED:
                flag = "   OVERLOADED"
            elif v["cpr"] >= CPR_BUSY:
                flag = "   busy"
        if v["live"] == 0 and v["clients"]:
            flag = "   clients with NO live radio on this band"
        print(f"  {f:6} {v['clients']:>8} {v['live']:>12} "
              f"{fmt(v['cpr']):>14}{flag}")

    # A floor with a handful of clients is not a control -- averaging it in
    # drags the comparison either way for no reason. Require real occupancy.
    MIN_CONTROL = 50
    ctrl = [f for f in floors if f != args.floor and load[f]["cpr"]
            and load[f]["clients"] >= MIN_CONTROL]
    mine = load[args.floor]["cpr"]
    if mine and ctrl:
        base = statistics.mean(load[f]["cpr"] for f in ctrl)
        print()
        print(f"  Floor {args.floor} carries {mine / base:.1f}x the clients per "
              f"radio of floor(s) {', '.join(ctrl)} "
              f"({base:.1f} per radio there).")
        skipped = [f for f in floors if f != args.floor and f not in ctrl]
        if skipped:
            print(f"  Floor(s) {', '.join(skipped)} left out as controls: "
                  f"under {MIN_CONTROL} clients.")

    # Co-channel radios share one medium rather than adding capacity, so the
    # number that bites is clients per CHANNEL, not per radio.
    chans = defaultdict(lambda: {"clients": 0, "aps": []})
    any_auto = False
    for serial, a in aps.items():
        if a["floor"] != args.floor:
            continue
        r = radio.get(serial, {})
        if not r.get("live"):
            continue
        k = str(chan_of(serial))
        # A star marks a radio auto-RF placed rather than one pinned by hand,
        # so a collision can be read as auto's doing or a person's.
        star = "*" if r.get("ch") == "auto" and oper.get(serial) is not None else ""
        any_auto = any_auto or bool(star)
        chans[k]["clients"] += per_ap.get(serial, 0)
        chans[k]["aps"].append(a["name"] + star)
    if chans:
        print()
        print("  Per channel — co-channel radios divide one medium, they do")
        print("  not add capacity:")
        print(f"    {'channel':9} {'clients':>8}   radios")
        for k, v in sorted(chans.items(), key=lambda i: -i[1]["clients"]):
            flag = "   <-- co-channel" if len(v["aps"]) > 1 else ""
            print(f"    {k:9} {v['clients']:>8}   {', '.join(v['aps'])}{flag}")
        tot = sum(v["clients"] for v in chans.values())
        print()
        print(f"  {tot} clients across {len(chans)} distinct channel(s) "
              f"= {tot / len(chans):.0f} per channel.")
        if any_auto:
            print("  * placed by auto-RF rather than pinned by hand.")

    # ---------------------------------------------------------------- 3
    print()
    print("-" * 78)
    print("3. IS THE AIR FULL?")
    print("-" * 78)
    print("  Channel utilisation is the share of airtime already spoken for.")
    print(f"  Above {UTIL_BUSY:.0f}% contention shows up in latency; above "
          f"{UTIL_SATURATED:.0f}% a floor behaves")
    print("  the way people describe as broken. The split matters: 802.11")
    print("  utilisation is other Wi-Fi, non-WiFi is everything else.")
    print()

    cu_fn = endpoint(dash, "wireless",
                     "getOrganizationWirelessDevicesChannelUtilizationByDevice")
    cu = safe("channel utilisation", cu_fn, args.org_id, timespan=span,
              interval=min(span, 3600), total_pages="all") or []
    util = defaultdict(lambda: {"total": [], "wifi": [], "non": []})
    rows = []
    for ent in cu:
        serial = ent.get("serial") or (ent.get("device") or {}).get("serial")
        a = aps.get(serial)
        if not a or a["floor"] == "?":
            continue
        for b in ent.get("byBand") or []:
            if str(b.get("band")) != args.band:
                continue
            # Tolerate both shapes the dashboard has used: a nested
            # {"percentage": n} and a bare number. Getting this wrong would
            # empty section 3 silently and quietly remove half the evidence
            # section 5 reasons from.
            def pc(v):
                if isinstance(v, dict):
                    for k in ("percentage", "percent", "value"):
                        if isinstance(v.get(k), (int, float)):
                            return float(v[k])
                    return None
                return float(v) if isinstance(v, (int, float)) else None
            vals = {"total": pc(b.get("total")), "wifi": pc(b.get("wifi")),
                    "non": pc(b.get("nonWifi"))}
            for k, v in vals.items():
                if v is not None:
                    util[a["floor"]][k].append(v)
            rows.append({"floor": a["floor"], "ap": a["name"], "serial": serial,
                         "clients": per_ap.get(serial, 0),
                         "radio_live": radio.get(serial, {}).get("live"),
                         "channel": radio.get(serial, {}).get("ch"),
                         "oper_channel": oper.get(serial),
                         "power_dbm": radio.get(serial, {}).get("power"),
                         "util_total": vals["total"], "util_wifi": vals["wifi"],
                         "util_nonwifi": vals["non"]})

    print(f"  {'floor':6} {'total':>8} {'802.11':>8} {'non-WiFi':>10}   radios sampled")
    uf = {}
    for f in floors:
        u = util.get(f, {})
        t, w, n = (mean_or_none(u.get("total")), mean_or_none(u.get("wifi")),
                   mean_or_none(u.get("non")))
        uf[f] = {"total": t, "wifi": w, "non": n}
        flag = ""
        if t is not None:
            if t >= UTIL_SATURATED:
                flag = "   SATURATED"
            elif t >= UTIL_BUSY:
                flag = "   busy"
        print(f"  {f:6} {fmt(t, '%'):>8} {fmt(w, '%'):>8} {fmt(n, '%'):>10}   "
              f"{len(u.get('total') or [])}{flag}")
    if not any(uf[f]["total"] is not None for f in floors):
        print("  (no channel utilisation returned)")

    # ---------------------------------------------------------------- 4
    print()
    print("-" * 78)
    print("4. COVERAGE, OR CONTENTION?")
    print("-" * 78)
    print("  Turning radios off removes capacity AND coverage. If the clients")
    print("  that remain are hearing their access point well, the problem is")
    print("  airtime. If they are hearing it badly, the gaps are the problem")
    print("  and the fix is specific radios rather than all of them.")
    print()

    sq_fn = endpoint(dash, "wireless", "getNetworkWirelessSignalQualityHistory")
    sig = {}
    for f in floors:
        serials = [s for s, a in aps.items()
                   if a["floor"] == f and radio.get(s, {}).get("live")]
        rssis, snrs = [], []
        for s in serials[:12]:    # a sample is enough; this is one call each
            h = safe(f"signal {aps[s]['name']}", sq_fn, net["id"],
                     deviceSerial=s, timespan=span, resolution=300,
                     band=args.band) or []
            for e in h:
                if e.get("rssi") is not None:
                    rssis.append(e["rssi"])
                if e.get("snr") is not None:
                    snrs.append(e["snr"])
        sig[f] = {"rssi": mean_or_none(rssis), "snr": mean_or_none(snrs),
                  "n": len(rssis)}

    print(f"  {'floor':6} {'mean RSSI':>11} {'mean SNR':>10}   samples")
    for f in floors:
        v = sig[f]
        flag = ""
        if v["rssi"] is not None and v["rssi"] <= RSSI_POOR:
            flag = "   POOR SIGNAL"
        elif v["snr"] is not None and v["snr"] <= SNR_POOR:
            flag = "   POOR SNR"
        print(f"  {f:6} {fmt(v['rssi'], ' dBm'):>11} {fmt(v['snr'], ' dB'):>10}   "
              f"{v['n']}{flag}")

    # ---------------------------------------------------------------- 5
    print()
    print("-" * 78)
    print("5. WHICH OF THE THREE IS IT?")
    print("-" * 78)

    t = uf.get(args.floor, {})
    s = sig.get(args.floor, {})
    ev = []
    if mine is not None:
        if mine >= CPR_OVERLOADED:
            ev.append(("capacity", f"{mine:.1f} clients per live radio "
                                   f"(over {CPR_OVERLOADED:.0f} is overloaded)"))
        elif mine >= CPR_BUSY:
            ev.append(("capacity", f"{mine:.1f} clients per live radio (busy)"))
        else:
            ev.append(("not capacity", f"{mine:.1f} clients per live radio "
                                       f"is not high on its own"))
    if t.get("total") is not None:
        # Judge on TOTAL airtime, the same figure section 3 flags on. Testing
        # the 802.11 share against a threshold meant for the total gave two
        # different answers to one question in the same run.
        w = t.get("wifi")
        share = f" ({w:.1f}% of it Wi-Fi)" if w is not None else ""
        if t["total"] >= UTIL_BUSY:
            ev.append(("capacity", f"airtime {t['total']:.1f}%{share} — "
                                   f"over the {UTIL_BUSY:.0f}% contention mark"))
        else:
            ev.append(("not capacity", f"airtime {t['total']:.1f}%{share}, "
                                       f"under the {UTIL_BUSY:.0f}% mark"))
    if t.get("non") is not None:
        if t["non"] >= 20.0:
            ev.append(("interference", f"non-WiFi airtime {t['non']:.1f}% — "
                                       f"something not Wi-Fi is using the band"))
        else:
            ev.append(("not interference", f"non-WiFi airtime {t['non']:.1f}%, low"))
    if s.get("rssi") is not None:
        if s["rssi"] <= RSSI_POOR:
            ev.append(("coverage", f"mean RSSI {s['rssi']:.1f} dBm — clients are "
                                   f"far from a radio"))
        else:
            ev.append(("not coverage", f"mean RSSI {s['rssi']:.1f} dBm is healthy"))

    for kind, why in ev:
        print(f"  {kind:18} {why}")
    print()
    votes = defaultdict(int)
    for kind, _ in ev:
        if not kind.startswith("not "):
            votes[kind] += 1
    if votes:
        lead = max(votes, key=votes.get)
        print(f"  The evidence points at {lead.upper()}.")
        if lead == "capacity":
            dark = tgt["total"] - tgt["live"]
            print()
            print(f"  If that holds, the fix is to re-enable radios on floor "
                  f"{args.floor}.")
            print(f"  {dark} are dark. Turning them all back on returns the floor to")
            print("  its pre-28-October state, which was also unhappy — so bring")
            print("  them back in groups, not all at once, and measure between")
            print("  each group. Half of them is a reasonable first step.")
    else:
        print("  Not enough evidence returned to point anywhere. Check the")
        print("  warnings above before concluding anything.")
    print()
    print("  One thing this cannot see: the switch. Floor 3's access-point")
    print("  ports were discarding 2.5% of everything before QoS came off.")
    print("  Read `show interfaces | include output drops` on SFSW31 tonight")
    print("  before deciding the radios are the whole story.")

    # ---------------------------------------------------------------- 6
    print()
    print("-" * 78)
    print("6. IS THIS FLOOR REACHING THE OTHERS?")
    print("-" * 78)
    print("  5 GHz passes between floors attenuated, not blocked. A crowded")
    print("  floor sharing a channel with the floor above raises that floor's")
    print("  noise, which is how one floor's problem arrives in someone else's")
    print("  office.")
    print()

    mychans = set(by_floor[args.floor]["chans"])
    clash = []
    for f in floors:
        if f == args.floor:
            continue
        shared = mychans & set(by_floor[f]["chans"])
        if shared:
            clash.append((f, sorted(shared, key=str)))
    if not mychans:
        print(f"  Floor {args.floor} has no live radios on this band to clash with.")
    elif clash:
        for f, sh in clash:
            names = ", ".join(str(c) for c in sh)
            print(f"  floor {f} shares channel(s) {names} with floor {args.floor}")
        print()
        print("  Worth checking the transmit power on the floor's remaining")
        print("  radios. If any were turned up to cover for the ones switched")
        print("  off, they are now louder on a shared channel than they were.")
        powers = [(aps[s]["name"], radio[s].get("power"))
                  for s in aps
                  if aps[s]["floor"] == args.floor and radio.get(s, {}).get("live")
                  and isinstance(radio[s].get("power"), (int, float))]
        if powers:
            vals = [p for _, p in powers]
            print()
            print(f"  floor {args.floor} transmit power: min {min(vals)} dBm, "
                  f"max {max(vals)} dBm, mean {statistics.mean(vals):.1f} dBm")
            loud = [f"{n} {p} dBm" for n, p in sorted(powers, key=lambda x: -x[1])[:5]]
            print(f"  loudest: {', '.join(loud)}")
    else:
        print(f"  No channel overlap between floor {args.floor} and the others.")
        print("  So whatever is reaching your office is not co-channel from here.")

    if args.csv and rows:
        with open(args.csv, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=[
                "floor", "ap", "serial", "clients", "radio_live", "channel",
                "oper_channel", "power_dbm", "util_total", "util_wifi",
                "util_nonwifi"])
            w.writeheader()
            w.writerows(rows)
        print()
        print(f"  {len(rows)} per-AP rows written to {args.csv}")
    print()


if __name__ == "__main__":
    main()
