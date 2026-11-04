#!/usr/bin/env python3
"""
meraki_change_impact.py - Did the 28 October radio changes on floor 3 help?

Beautiful Networks disabled 25 of floor 3's 33 5 GHz radios at 16:04 local on
28 October, pinned nine channels and cut two access points to 4 dBm. Nobody
measured anything before or after. Meraki, however, has been recording the
whole time, so the baseline exists even though no one captured one.

Two comparisons, because neither is sound on its own:

  A. SAME TIME, TWO FLOORS. Floor 3 is running 8 radios, floor 5 is running
     29, in the same building, the same hour, the same partly-empty office.
     If thinning density is the cure, floor 3 should look better than floor 5
     RIGHT NOW. No temporal confound at all -- but the floors differ in layout
     and headcount, so a gap is suggestive rather than decisive.

  B. BEFORE AND AFTER, FLOOR 5 AS CONTROL. The office emptied on 27 October,
     so floor 3 looking better today proves nothing by itself: most of the
     people left. Floor 5 emptied too and its radios were NOT touched, so
     whatever floor 5 did is what an empty office does on its own. The part of
     floor 3's change that EXCEEDS floor 5's is the part the radio work can
     claim. That subtraction is the whole point of this script.

The weakness no amount of code fixes: there are only a few business hours of
"after" data and the office is unusually empty, so this run will catch a large
effect and nothing subtle. Run it again once staff are back for a number
anyone should act on.

SAFETY: same three layers as the other scripts --
  1. PREFLIGHT  - aborts unless the key's admin account is read-only
  2. SIMULATE   - SDK constructed with simulate=True; writes become no-ops
  3. READ-ONLY  - only get* methods are called

Usage:
    export MERAKI_DASHBOARD_API_KEY='...'
    python3 meraki_change_impact.py --org-id 1586134
    python3 meraki_change_impact.py --org-id 1586134 --treated 3 --control 5
    python3 meraki_change_impact.py --org-id 1586134 --days-before 14 --csv out.csv
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

# Beautiful Networks' change window, 28 Oct 2026 16:04-16:17 local. Everything
# before 16:04 is "before", everything after 16:17 is "after"; the thirteen
# minutes between are discarded rather than assigned to either side.
CHANGE_START = datetime(2026, 10, 28, 16, 4, tzinfo=LOCAL)
CHANGE_END = datetime(2026, 10, 28, 16, 17, tzinfo=LOCAL)

# Only business hours count. Comparing a Thursday lunchtime against a Sunday
# night would show a huge "improvement" that is entirely the clock.
BIZ_START, BIZ_END = 9, 17
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


def endpoint(dash, group, name):
    """Return a bound SDK method, or None if this SDK release does not have it.

    The dashboard SDK gains, renames and retires endpoints between releases. A
    missing one should cost you that single metric, not the whole run.
    """
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


def parse_ts(s):
    """Meraki hands back ISO 8601 with a Z. Python wants the offset spelled out."""
    if not s:
        return None
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except ValueError:
        return None


def in_business_hours(dt):
    """Weekday, 09:00-17:00, in the office's own timezone -- not UTC, and not
    the switch's clock, which is an hour out on Belgian DST rules."""
    local = dt.astimezone(LOCAL)
    return local.weekday() < 5 and BIZ_START <= local.hour < BIZ_END


def side_of(dt, span=timedelta(hours=1)):
    """Which side of the change an hourly bucket falls on, or None to discard.

    The bucket is an hour wide, so the one starting at 16:00 on the 28th holds
    both states and belongs to neither. Assigning it to 'before' would quietly
    mix post-change data into the baseline.
    """
    if dt + span <= CHANGE_START:
        return "before"
    if dt >= CHANGE_END:
        return "after"
    return None


def med(xs):
    xs = [x for x in xs if x is not None]
    return statistics.median(xs) if xs else None


def fmt(v, suffix="", places=1):
    return "-" if v is None else f"{v:.{places}f}{suffix}"


def delta(before, after):
    if before is None or after is None:
        return None
    return after - before


# --------------------------------------------------------------------------
# collection
# --------------------------------------------------------------------------

def radio_state(dash, devices):
    """Which radios are actually enabled, read from the per-device radio settings.

    NOT from getDeviceWirelessStatus. That endpoint lists one basic service set
    per SSID per band and its 'enabled' flag describes the SSID, not the radio,
    so every access point comes back fully lit whatever its radios are doing --
    which is exactly the wrong answer, delivered confidently.

    The radio settings carry the truth: a disabled radio reports channel -1 and
    targetPower -1, the same -1 the change log records when one is switched off.
    A channel of None means automatic, which is a radio that is ON.
    """
    out = {}
    get = endpoint(dash, "wireless", "getDeviceWirelessRadioSettings")
    if not get:
        return out

    def chan(block):
        ch, pw = (block or {}).get("channel"), (block or {}).get("targetPower")
        if ch == -1 or pw == -1:
            return None
        return ch if ch is not None else "auto"

    for d in devices:
        rs = safe(f"radio {d['name']}", get, d["serial"])
        if not rs:
            continue
        c5, c24 = chan(rs.get("fiveGhzSettings")), chan(rs.get("twoFourGhzSettings"))
        out[d["serial"]] = {"ch5": [c5] if c5 is not None else [],
                            "ch24": [c24] if c24 is not None else [],
                            "rf": rs.get("rfProfileId")}
    return out


def series(dash, net_id, devices, t0, t1):
    """Hourly channel utilisation and client count per access point.

    Pulled per device so the samples can be grouped by floor afterwards. One
    call each way per AP; at four requests a second roughly thirty seconds for
    a two-floor run.
    """
    util_fn = endpoint(dash, "wireless", "getNetworkWirelessChannelUtilizationHistory")
    cnt_fn = endpoint(dash, "wireless", "getNetworkWirelessClientCountHistory")
    sig_fn = endpoint(dash, "wireless", "getNetworkWirelessSignalQualityHistory")
    rows = []
    for i, d in enumerate(devices, 1):
        util = {}
        if util_fn:
            r = safe(f"util {d['name']}", util_fn, net_id, deviceSerial=d["serial"],
                     t0=t0, t1=t1, resolution=3600, band="5") or []
            for s in r:
                ts = parse_ts(s.get("startTs"))
                if ts:
                    # Keep the split, not just the total. Airtime lost to other
                    # Wi-Fi radios and airtime lost to a microwave or a camera
                    # are different faults with different fixes, and the total
                    # alone cannot tell you which one you have.
                    util[ts] = (s.get("utilizationTotal"),
                                s.get("utilization80211"),
                                s.get("utilizationNonWifi"))
        counts = {}
        if cnt_fn:
            # Band-matched to the utilisation above. Counting 2.4 GHz clients
            # against 5 GHz airtime understates the cost per client wherever
            # 2.4 GHz is widely enabled -- which is floor 5 (21 radios) but
            # not floor 3 (2), so leaving it out tilts exactly the comparison
            # this script exists to make.
            r = safe(f"clients {d['name']}", cnt_fn, net_id, deviceSerial=d["serial"],
                     t0=t0, t1=t1, resolution=3600, band="5") or []
            for s in r:
                ts = parse_ts(s.get("startTs"))
                if ts:
                    counts[ts] = s.get("clientCount")
        # How strong the clients are, as the access point hears them. If
        # switching radios off left people further from whatever is still
        # serving them, this is where it shows: the same clients, further
        # down the rate ladder, each byte occupying the channel for longer.
        sig = {}
        if sig_fn:
            r = safe(f"signal {d['name']}", sig_fn, net_id, deviceSerial=d["serial"],
                     t0=t0, t1=t1, resolution=3600, band="5") or []
            for s in r:
                ts = parse_ts(s.get("startTs"))
                if ts:
                    sig[ts] = (s.get("rssi"), s.get("snr"))

        for ts in sorted(set(util) | set(counts) | set(sig)):
            if not in_business_hours(ts):
                continue
            side = side_of(ts)
            if side is None:
                continue
            tot, wifi, nonwifi = util.get(ts) or (None, None, None)
            rssi, snr = sig.get(ts) or (None, None)
            rows.append({"serial": d["serial"], "ap": d["name"],
                         "floor": floor_of(d["name"]), "ts": ts, "side": side,
                         "util": tot, "util_wifi": wifi, "util_nonwifi": nonwifi,
                         "rssi": rssi, "snr": snr, "clients": counts.get(ts)})
        if i % 20 == 0:
            print(f"    {i}/{len(devices)} access points")
    return rows


def window_stats(dash, net_id, t0, t1):
    """Per-device connection success and latency over one window.

    Both of these are single network-wide calls that return a row per access
    point, which is far cheaper than asking each device in turn.
    """
    conn, lat = {}, {}
    cf = endpoint(dash, "wireless", "getNetworkWirelessDevicesConnectionStats")
    lf = endpoint(dash, "wireless", "getNetworkWirelessDevicesLatencyStats")
    if cf:
        for r in safe("connection stats", cf, net_id, t0=t0, t1=t1) or []:
            conn[r.get("serial")] = r.get("connectionStats") or {}
    if lf:
        for r in safe("latency stats", lf, net_id, t0=t0, t1=t1) or []:
            lat[r.get("serial")] = r.get("latencyStats") or {}
    return conn, lat


def success_rate(stats):
    """Meraki counts failures by the step they died at, plus successes. The
    rate that matters to a user is successes over every attempt."""
    if not stats:
        return None
    succ = stats.get("success") or 0
    fail = sum(stats.get(k) or 0 for k in ("assoc", "auth", "dhcp", "dns"))
    total = succ + fail
    return 100.0 * succ / total if total else None


def voice_latency(stats):
    v = (stats or {}).get("voiceTraffic") or {}
    return v.get("avg")


# --------------------------------------------------------------------------
# reporting
# --------------------------------------------------------------------------

def floor_rows(rows, floor, side=None):
    return [r for r in rows if r["floor"] == floor and (side is None or r["side"] == side)]


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--org-id", required=True)
    p.add_argument("--treated", default="3", help="floor that was changed")
    p.add_argument("--control", default="5", help="untouched floor to compare against")
    p.add_argument("--days-before", type=int, default=7)
    p.add_argument("--csv", help="write the hourly samples here")
    args = p.parse_args()

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

    now = datetime.now(timezone.utc)
    start = CHANGE_START - timedelta(days=args.days_before)
    iso = lambda d: d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    devs = safe("devices", dash.organizations.getOrganizationDevices, args.org_id,
                total_pages="all", productTypes=["wireless"]) or []
    devs = [d for d in devs if d.get("serial")]
    for d in devs:
        d["name"] = d.get("name") or d["serial"]
        d["floor"] = floor_of(d["name"])
    wanted = [d for d in devs if d["floor"] in (args.treated, args.control)]
    wanted.sort(key=lambda d: d["name"])

    print("=" * 78)
    print("DID THE 28 OCTOBER RADIO CHANGES HELP?")
    print("=" * 78)
    print(f"  key        read-only ({who})")
    print(f"  network    {net.get('name')}")
    print(f"  change     {CHANGE_START.strftime('%Y-%m-%d %H:%M %Z')}"
          f" to {CHANGE_END.strftime('%H:%M %Z')}")
    print(f"  before     {start.strftime('%Y-%m-%d')} to the change")
    print(f"  after      the change to {now.astimezone(LOCAL).strftime('%Y-%m-%d %H:%M %Z')}")
    print(f"  counted    weekdays {BIZ_START:02d}:00-{BIZ_END:02d}:00 local only")
    print(f"  floors     {args.treated} (changed) vs {args.control} (control)")
    print(f"  APs        {len(wanted)}")
    print()

    # ------------------------------------------------------------------ 1
    print("-" * 78)
    print("1. RADIO STATE RIGHT NOW")
    print("-" * 78)
    st = radio_state(dash, wanted)
    print(f"  {'floor':6} {'APs':>4} {'5GHz on':>8} {'2.4GHz on':>10}  channels in use (5 GHz)")
    for fl in (args.treated, args.control):
        fd = [d for d in wanted if d["floor"] == fl]
        on5 = [d for d in fd if st.get(d["serial"], {}).get("ch5")]
        on24 = [d for d in fd if st.get(d["serial"], {}).get("ch24")]
        # A pinned channel is a number, an automatic one is the word 'auto',
        # and the two cannot be sorted together: numbers first, auto last.
        raw = {c for d in fd for c in st.get(d["serial"], {}).get("ch5", [])}
        chans = [str(c) for c in sorted(c for c in raw if isinstance(c, int))]
        if "auto" in raw:
            chans.append("auto")
        print(f"  {fl:6} {len(fd):>4} {len(on5):>8} {len(on24):>10}  "
              f"{', '.join(chans)[:40]}")
    print()
    print("  Read from each access point's radio settings, where a disabled radio")
    print("  reports channel -1 and power -1 -- the same -1 the change log records.")
    print("  'auto' means the radio is on and choosing its own channel.")

    # ------------------------------------------------------------------ data
    print()
    print("  collecting hourly history...")
    rows = series(dash, net_id, wanted, iso(start), iso(now))
    conn_b, lat_b = window_stats(dash, net_id, iso(start), iso(CHANGE_START))
    conn_a, lat_a = window_stats(dash, net_id, iso(CHANGE_END), iso(now))

    live = {s for s, v in st.items() if v.get("ch5")}
    if not st:
        # Without the radio settings there is no way to tell a switched-off
        # radio from a live one. Say so loudly and carry on counting every
        # access point as live -- a blank column with no explanation is the
        # worst of the available outcomes.
        print()
        print("  ! RADIO SETTINGS UNAVAILABLE on this SDK or key. This run cannot")
        print("    tell a disabled radio from a live one, so every access point is")
        print("    counted as live. That understates utilisation on a floor with")
        print("    radios switched off. Sections 2 and 3 are provisional.")
        live = {d["serial"] for d in wanted}

    def pool(floor, side):
        """The access points whose 5 GHz radio was on during that window.

        Before the change every one was on. After it, floor 3 has eight. Every
        per-floor figure has to use the right denominator or the 25 switched-off
        radios turn into a fake improvement.
        """
        return [d for d in wanted if d["floor"] == floor
                and (side == "before" or d["serial"] in live)]

    def agg_util(floor, side, field="util"):
        """Median channel utilisation across the radios that were actually on.

        A radio that is off cannot measure its channel. Including it as a zero
        would drag floor 3's median toward nothing the moment the radios were
        disabled, which looks exactly like success and means nothing.
        """
        keep = {d["serial"] for d in pool(floor, side)}
        return med([r[field] for r in floor_rows(rows, floor, side)
                    if r["serial"] in keep])

    def util_per_client(floor, side):
        """Airtime one client costs on the radio that serves it.

        Per-RADIO utilisation divided by clients-per-RADIO. Both halves have to
        be per radio. Dividing per-radio utilisation by the floor's TOTAL client
        count -- which this did until it was caught on 29 October -- is
        dimensionally wrong, and wrong in a way that lies loudly: switch radios
        off and the figure rockets, switch them on and it collapses, with
        nothing real having changed. It made a null result look like a
        fivefold regression.
        """
        u, n = agg_util(floor, side), clients_per_live_ap(floor, side)
        return u / n if (u is not None and n) else None

    def floor_clients(floor, side):
        """Clients on the whole floor, hour by hour, then the median hour.

        Summed across access points rather than averaged over them: an average
        per AP collapses when radios are switched off, and the question here is
        how many PEOPLE were on the floor, which switching radios off does not
        change.
        """
        by_hour = defaultdict(float)
        for r in floor_rows(rows, floor, side):
            if r["clients"] is not None:
                by_hour[r["ts"]] += r["clients"]
        return med(list(by_hour.values()))

    def clients_per_live_ap(floor, side):
        """How much each surviving radio is carrying."""
        tot, n = floor_clients(floor, side), len(pool(floor, side))
        return tot / n if tot is not None and n else None

    def per_floor_conn(floor, table):
        vals = [success_rate(table.get(d["serial"]))
                for d in wanted if d["floor"] == floor]
        return med(vals)

    def per_floor_voice(floor, table):
        vals = [voice_latency(table.get(d["serial"]))
                for d in wanted if d["floor"] == floor]
        return med(vals)

    # ------------------------------------------------------------------ 2
    print()
    print("-" * 78)
    print(f"2. SAME TIME, TWO FLOORS  (floor {args.treated} vs floor {args.control}, since the change)")
    print("-" * 78)
    t, c = args.treated, args.control
    print(f"  {'metric':34} {'floor ' + t:>12} {'floor ' + c:>12}")
    print(f"  {'live 5 GHz radios':34} "
          f"{len(pool(t, 'after')):>12} {len(pool(c, 'after')):>12}")
    print(f"  {'5 GHz channel utilisation':34} "
          f"{fmt(agg_util(t, 'after'), '%'):>12} {fmt(agg_util(c, 'after'), '%'):>12}")
    print(f"  {'  of which other Wi-Fi':34} "
          f"{fmt(agg_util(t, 'after', 'util_wifi'), '%'):>12} "
          f"{fmt(agg_util(c, 'after', 'util_wifi'), '%'):>12}")
    print(f"  {'  of which non-Wi-Fi':34} "
          f"{fmt(agg_util(t, 'after', 'util_nonwifi'), '%'):>12} "
          f"{fmt(agg_util(c, 'after', 'util_nonwifi'), '%'):>12}")
    print(f"  {'airtime per client':34} "
          f"{fmt(util_per_client(t, 'after'), '%', 3):>12} "
          f"{fmt(util_per_client(c, 'after'), '%', 3):>12}")
    print(f"  {'client signal as the AP hears it':34} "
          f"{fmt(agg_util(t, 'after', 'rssi'), ' dBm'):>12} "
          f"{fmt(agg_util(c, 'after', 'rssi'), ' dBm'):>12}")
    print(f"  {'client SNR':34} "
          f"{fmt(agg_util(t, 'after', 'snr'), ' dB'):>12} "
          f"{fmt(agg_util(c, 'after', 'snr'), ' dB'):>12}")
    print(f"  {'clients on the floor':34} "
          f"{fmt(floor_clients(t, 'after'), '', 0):>12} "
          f"{fmt(floor_clients(c, 'after'), '', 0):>12}")
    print(f"  {'clients per live radio':34} "
          f"{fmt(clients_per_live_ap(t, 'after')):>12} "
          f"{fmt(clients_per_live_ap(c, 'after')):>12}")
    print(f"  {'association success':34} "
          f"{fmt(per_floor_conn(t, conn_a), '%'):>12} {fmt(per_floor_conn(c, conn_a), '%'):>12}")
    print(f"  {'voice latency':34} "
          f"{fmt(per_floor_voice(t, lat_a), ' ms', 0):>12} "
          f"{fmt(per_floor_voice(c, lat_a), ' ms', 0):>12}")
    print()
    print(f"  Same building, same hours, same partly-empty office, so nothing here")
    print(f"  is explained by the clock. Floor {t} is the thinned one. If thinning")
    print(f"  density is the cure it should be winning this table -- but the two")
    print(f"  floors differ in layout and headcount, so read it as a hint.")

    # ------------------------------------------------------------------ 3
    print()
    print("-" * 78)
    print("3. BEFORE AND AFTER, WITH THE CONTROL FLOOR SUBTRACTED")
    print("-" * 78)
    print(f"  {'metric':26} {'f' + t + ' before':>10} {'f' + t + ' after':>10} "
          f"{'delta':>8} {'f' + c + ' delta':>10} {'NET':>8}")
    for label, fn_b, fn_a in (
        ("5 GHz utilisation %", lambda f: agg_util(f, "before"),
         lambda f: agg_util(f, "after")),
        ("  non-Wi-Fi share %", lambda f: agg_util(f, "before", "util_nonwifi"),
         lambda f: agg_util(f, "after", "util_nonwifi")),
        ("airtime per client %", lambda f: util_per_client(f, "before"),
         lambda f: util_per_client(f, "after")),
        ("client RSSI dBm", lambda f: agg_util(f, "before", "rssi"),
         lambda f: agg_util(f, "after", "rssi")),
        ("client SNR dB", lambda f: agg_util(f, "before", "snr"),
         lambda f: agg_util(f, "after", "snr")),
        ("clients per live radio", lambda f: clients_per_live_ap(f, "before"),
         lambda f: clients_per_live_ap(f, "after")),
        ("association success %", lambda f: per_floor_conn(f, conn_b),
         lambda f: per_floor_conn(f, conn_a)),
        ("voice latency ms", lambda f: per_floor_voice(f, lat_b),
         lambda f: per_floor_voice(f, lat_a)),
    ):
        tb, ta = fn_b(t), fn_a(t)
        cb, ca = fn_b(c), fn_a(c)
        dt_, dc = delta(tb, ta), delta(cb, ca)
        net_eff = delta(dc, dt_) if (dt_ is not None and dc is not None) else None
        print(f"  {label:26} {fmt(tb):>10} {fmt(ta):>10} {fmt(dt_):>8} "
              f"{fmt(dc):>10} {fmt(net_eff):>8}")

    print()
    print(f"  NET = floor {t}'s change minus floor {c}'s change. Floor {c} emptied out")
    print(f"  too and nobody touched its radios, so its column is what an empty")
    print(f"  office does on its own. Only the NET column can be credited to the")
    print(f"  radio work. A NET near zero means the change did nothing measurable.")

    # ------------------------------------------------------------------ 4
    print()
    print("-" * 78)
    print("4. HOW MUCH OF THIS IS JUST FEWER PEOPLE")
    print("-" * 78)
    for fl in (t, c):
        b, a = floor_clients(fl, "before"), floor_clients(fl, "after")
        pct = f"{100 * (a - b) / b:+.0f}%" if (b and a is not None) else "-"
        print(f"  floor {fl}: {fmt(b, '', 0)} clients before -> "
              f"{fmt(a, '', 0)} after  ({pct})")
    print()
    print("  If both floors fell by about the same proportion, the office")
    print("  emptying explains it and the radio change is not in these numbers.")
    nb = len([r for r in rows if r["side"] == "before"])
    na = len([r for r in rows if r["side"] == "after"])
    print()
    print(f"  Sample sizes: {nb} business-hour readings before, {na} after.")
    if na < 40:
        print()
        print("  THAT 'AFTER' NUMBER IS TOO SMALL TO CONCLUDE ANYTHING SUBTLE.")
        print("  A few business hours against a week, in an office that is barely")
        print("  occupied. This run will catch a large effect and miss everything")
        print("  else. Run it again once staff are back and the after-window has")
        print("  a couple of full days in it.")

    if args.csv:
        with open(args.csv, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["ts", "side", "floor", "ap", "serial",
                                              "util", "clients"])
            w.writeheader()
            for r in sorted(rows, key=lambda x: (x["ts"], x["ap"])):
                w.writerow({"ts": r["ts"].astimezone(LOCAL).isoformat(),
                            "side": r["side"], "floor": r["floor"], "ap": r["ap"],
                            "serial": r["serial"], "util": r["util"],
                            "clients": r["clients"]})
        print()
        print(f"  Hourly samples written to {args.csv}")
    print()


if __name__ == "__main__":
    main()
