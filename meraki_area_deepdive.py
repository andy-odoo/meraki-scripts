#!/usr/bin/env python3
"""
meraki_area_deepdive.py - Area / access-point deep dive for localized problems.

Use when a PLACE has trouble rather than a person: dropped calls in one corner,
a room that is slow, a floor that feels worse than the others. The per-client
check looks at association events, which stay clean while calls drop. This tool
looks at the things that actually break a call: packet loss, latency by traffic
class, non-Wi-Fi interference, and spectral overlap between neighbouring APs.

SAFETY: same three layers as the other scripts --
  1. PREFLIGHT  - aborts unless the key's admin account is read-only
  2. SIMULATE   - SDK constructed with simulate=True; writes become no-ops
  3. READ-ONLY  - only get* methods are called

Usage:
    export MERAKI_DASHBOARD_API_KEY='...'
    python3 meraki_area_deepdive.py --org-id 1586134 --floor 2
    python3 meraki_area_deepdive.py --org-id 1586134 --aps SFAP201,SFAP208,SFAP211
    python3 meraki_area_deepdive.py --org-id 1586134 --floor 2 --band 5 --csv area.csv

FIXES 2026-10-22:
  - short windows now work. The utilization and history endpoints reject or
    silently drop a timespan smaller than their bucket size; the bucket is
    chosen to fit the window instead of being hard-coded to an hour.
  - the window is printed in minutes below an hour rather than rounded to "0h".
  - the verdict flags an access point that is bad on its own, not only one
    that is worse than its neighbours. A uniformly bad area used to come back
    as "no problem found".
  - Air Marshal SNR sentinels (252-255 mean "no reading") are discarded.
  - the failed-connection step is read from whichever field the firmware
    populates, instead of assuming failureStep.
  - a loss percentage drawn from fewer than MIN_LOSS_PKTS packets is marked
    '?', kept out of the median, and kept out of the verdict. One lost packet
    in nine was reading as 11% and sorting above an access point losing 9%
    of 1.4 million.
"""

import argparse
import csv
import os
import re
import sys
import time
from collections import Counter, defaultdict

try:
    import meraki
except ImportError:
    sys.exit("Missing SDK. Install with: pip install meraki --break-system-packages")

MAX_RPS = 4.0
_last = [0.0]

# Thresholds. Voice is the strict one: ITU G.114 puts 150 ms one-way as the
# edge of acceptable, and 1% loss is already audible on a call.
LOSS_WARN, LOSS_BAD = 1.0, 3.0
# A loss percentage computed over a handful of frames is arithmetic, not a
# measurement: one lost packet in nine reads as 11% and sorts above an access
# point losing 9% of 1.4 million. Rows thinner than this are shown but kept
# out of the median and out of the verdict.
MIN_LOSS_PKTS = 10000
VOICE_SLOW_MS = 128           # the Meraki latency bucket nearest the voice limit
VOICE_SLOW_WARN = 2.0         # % of voice samples at or above that bucket
VOICE_SLOW_BAD = 5.0
NONWIFI_WARN, NONWIFI_BAD = 10.0, 20.0
UTIL_WARN, UTIL_BAD = 40.0, 50.0

# 5 GHz bonding. Meraki reports the PRIMARY channel; a 40 or 80 MHz radio
# occupies its whole bonded group, so two APs can overlap while showing
# different channel numbers.
PAIRS40 = [(36, 40), (44, 48), (52, 56), (60, 64), (100, 104), (108, 112),
           (116, 120), (124, 128), (132, 136), (140, 144), (149, 153),
           (157, 161), (165, 169)]
QUADS80 = [(36, 40, 44, 48), (52, 56, 60, 64), (100, 104, 108, 112),
           (116, 120, 124, 128), (132, 136, 140, 144), (149, 153, 157, 161)]
# 2.4 GHz: channel centres are 5 MHz apart and each channel is 20 MHz wide,
# so a channel reaches +/-10 MHz = +/-2 channel numbers. That makes 1, 6 and 11
# the non-overlapping set, and anything closer than 5 apart an overlap.
def occupied(ch, width, band):
    try:
        ch = int(ch)
    except (TypeError, ValueError):
        return set()
    if band == "2.4":
        return set(range(max(1, ch - 2), ch + 3))
    try:
        w = int(str(width).replace("MHz", "").strip())
    except (TypeError, ValueError):
        w = 20
    if w >= 80:
        for q in QUADS80:
            if ch in q:
                return set(q)
    if w >= 40:
        for p in PAIRS40:
            if ch in p:
                return set(p)
    return {ch}


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
        print(f"    ! {label}: {type(e).__name__} {str(e)[:80]}")
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


def hr(t):
    print("\n" + "=" * 78)
    print(t)
    print("=" * 78)


def flag(v, warn, bad, higher_is_worse=True):
    if v is None:
        return "   "
    if higher_is_worse:
        return "!! " if v >= bad else ("!  " if v >= warn else "   ")
    return "!! " if v <= bad else ("!  " if v <= warn else "   ")


# Several endpoints take a fixed set of legal bucket widths and reject - or
# silently return nothing for - a timespan shorter than the bucket. Pick the
# largest bucket that fits inside the window rather than clamping the window:
# a thirty-minute question deserves a thirty-minute answer.
# NOTE the two lists differ, and guessing at them costs a 400. Verified against
# the published parameter docs: the org-wide utilization endpoint accepts
# 300/600/3600/7200/14400/21600 and nothing else -- 1200 and 86400 are rejected,
# though both are legal resolutions on the per-network history endpoint.
UTIL_INTERVALS = (300, 600, 3600, 7200, 14400, 21600)
HIST_RESOLUTIONS = (600, 1200, 3600, 14400, 86400)


def fit_bucket(timespan, allowed):
    ok = [i for i in allowed if i <= timespan]
    return max(ok) if ok else min(allowed)


def window_label(secs):
    if secs < 3600:
        return f"{secs/60:.0f} min"
    return f"{secs/3600:.1f}h".replace(".0h", "h")


def snr_of(v):
    """Air Marshal reports SNR in dB, higher being stronger -- not dBm.

    Values at or above 100 are discarded: real SNR tops out around 70, and the
    endpoint emits 252-255 as sentinels, an unsigned byte holding a small
    negative number, meaning 'no reading'. Taken at face value they invent
    interferers that do not exist."""
    if not isinstance(v, (int, float)) or isinstance(v, bool):
        return None
    v = int(v)
    v = -v if v < 0 else v
    return None if v >= 100 else v


def step_of(row):
    """Failed-connection rows name the step in one of several fields depending
    on firmware. Check each rather than assuming, or the whole histogram
    collapses into {None: n}."""
    for k in ("failureStep", "type", "step"):
        v = row.get(k)
        if v:
            return str(v).lower()
    return "unknown"


def worst_of(r):
    """The worst of a row's three loss figures, with the direction it came from
    and the packet count behind it, so the sample size travels with the number
    instead of being looked up separately and forgotten."""
    cands = []
    if r.get("up_loss") is not None:
        cands.append((r["up_loss"], "upstream", r.get("up_pkts") or 0))
    if r.get("down_loss") is not None:
        cands.append((r["down_loss"], "downstream", r.get("down_pkts") or 0))
    if r.get("tot_loss") is not None:
        cands.append((r["tot_loss"], "total",
                      (r.get("up_pkts") or 0) + (r.get("down_pkts") or 0)))
    if not cands:
        return 0.0, "-", 0
    return max(cands, key=lambda c: c[0])


def thin(r):
    """True when the worst figure rests on too few packets to mean anything."""
    return worst_of(r)[2] < MIN_LOSS_PKTS


def malformed(bssid):
    """A BSSID is always a unicast address. The multicast bit set in the first
    octet, or an all-zero prefix, means the detection is a firmware artifact
    and not a neighbouring network.

    This matters more than it sounds. The 55:b8:21:c6:* family appears across
    this fleet at high SNR; counted as real it produces a phantom neighbour at
    -36 dBm and sends you looking for a rogue that does not exist."""
    parts = (bssid or "").split(":")
    if len(parts) != 6:
        return True
    try:
        o = [int(p, 16) for p in parts]
    except ValueError:
        return True
    return bool(o[0] & 0x01) or all(x == 0 for x in o[:5])


def pct_at_or_above(raw, floor_ms):
    """Share of latency samples in buckets >= floor_ms."""
    if not raw:
        return None, 0
    tot = sum(raw.values())
    if not tot:
        return None, 0
    slow = sum(n for b, n in raw.items() if int(b) >= floor_ms)
    return 100.0 * slow / tot, tot


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--org-id", required=True)
    p.add_argument("--network-id")
    p.add_argument("--floor", help="floor digit, matched against SFAP<floor><nn>")
    p.add_argument("--aps", help="comma-separated AP names")
    p.add_argument("--name-match", help="regex against AP name")
    p.add_argument("--band", choices=["2.4", "5", "6"],
                   help="restrict loss/latency queries to one band")
    p.add_argument("--timespan", type=int, default=86400)
    p.add_argument("--csv")
    args = p.parse_args()

    if not (args.floor or args.aps or args.name_match):
        sys.exit("Specify --floor, --aps, or --name-match.")

    key = os.environ.get("MERAKI_DASHBOARD_API_KEY")
    if not key:
        sys.exit("Set MERAKI_DASHBOARD_API_KEY first.")

    dash = meraki.DashboardAPI(api_key=key, simulate=True, wait_on_rate_limit=True,
                               maximum_retries=5, suppress_logging=True,
                               print_console=False)
    preflight(dash)

    net_id = args.network_id
    if not net_id:
        nets = safe("networks", dash.organizations.getOrganizationNetworks,
                    args.org_id, total_pages="all") or []
        wn = [n for n in nets if "wireless" in n.get("productTypes", [])]
        if not wn:
            sys.exit("No wireless networks found.")
        net_id = wn[0]["id"]

    devs = safe("devices", dash.organizations.getOrganizationDevices,
                args.org_id, total_pages="all", productTypes=["wireless"]) or []
    stats = safe("statuses", dash.organizations.getOrganizationDevicesStatuses,
                 args.org_id, total_pages="all", productTypes=["wireless"]) or []
    smap = {s["serial"]: s.get("status") for s in stats}

    # ---- scope selection
    if args.aps:
        want = {n.strip().lower() for n in args.aps.split(",")}
        sel = [d for d in devs if (d.get("name") or "").lower() in want]
        scope = f"APs {args.aps}"
    elif args.name_match:
        rx = re.compile(args.name_match, re.I)
        sel = [d for d in devs if rx.search(d.get("name") or "")]
        scope = f"name matching /{args.name_match}/"
    else:
        rx = re.compile(rf"SFAP{args.floor}\d{{2}}$", re.I)
        sel = [d for d in devs if rx.match((d.get("name") or "").strip())]
        scope = f"floor {args.floor}"

    sel.sort(key=lambda d: (d.get("name") or "zzz"))
    if not sel:
        sys.exit("Nothing matched. Check names with meraki_ap_inventory.py --all.")
    serials = [d["serial"] for d in sel]
    names = {d["serial"]: d.get("name") or d["serial"] for d in sel}

    hr(f"AREA DEEP DIVE  -  {scope}  ({len(sel)} access points, "
       f"{window_label(args.timespan)} window)")
    print("  Built for localized faults: dropped calls, a slow corner, a bad room.")
    print("  Association-level checks stay clean while calls drop; these do not.")

    bandkw = {"band": args.band} if args.band else {}

    # ================= 1. radio state and spectral overlap
    hr("1. RADIO STATE AND SPECTRAL OVERLAP")
    radio = {}
    print(f"  reading live radio state ({len(sel)} calls)")
    for d in sel:
        st = safe(f"status {d['serial']}", dash.wireless.getDeviceWirelessStatus,
                  d["serial"]) or {}
        live = {}
        for b in st.get("basicServiceSets") or []:
            if not b.get("enabled"):
                continue
            bd = str(b.get("band", "")).replace(" GHz", "").strip()
            live.setdefault(bd, b)
        radio[d["serial"]] = live

    for band in (["2.4", "5"] if not args.band else [args.band]):
        occ = {}
        for s in serials:
            b = radio.get(s, {}).get(band)
            if not b or b.get("channel") is None:
                continue
            occ[s] = (occupied(b.get("channel"), b.get("channelWidth"), band),
                      b.get("channel"), b.get("channelWidth"), b.get("power"))
        if not occ:
            continue
        print(f"\n  --- {band} GHz ---")
        print(f"  {'AP':10} {'status':9} {'primary':>8} {'width':>8} {'power':>8}  occupies")
        for s in sorted(occ, key=lambda x: names[x]):
            o, ch, w, pw = occ[s]
            print(f"  {names[s][:10]:10} {str(smap.get(s,'?'))[:9]:9} {str(ch):>8} "
                  f"{str(w):>8} {str(pw or 'OFF'):>8}  {sorted(o)}")

        # A radio with no transmit power is not on the air. Counting it as an
        # overlapping neighbour invents contention that cannot exist, which is
        # what a disabled 2.4 GHz band used to look like here.
        ks = [s for s in sorted(occ, key=lambda x: names[x]) if occ[s][3]]
        n_off = len(occ) - len(ks)
        if n_off:
            print(f"\n  {n_off} radio(s) in this band have transmit power off "
                  f"and are excluded\n  from the overlap analysis.")
        pairs = []
        for i in range(len(ks)):
            for j in range(i + 1, len(ks)):
                sh = occ[ks[i]][0] & occ[ks[j]][0]
                if sh:
                    pairs.append((names[ks[i]], names[ks[j]], sorted(sh)))
        print(f"\n  overlapping pairs: {len(pairs)}")
        for a, b, sh in pairs:
            print(f"    {a} <-> {b}   shared channels {sh}")
        groups = {}
        for s2 in ks:
            groups.setdefault(tuple(sorted(occ[s2][0])), []).append(names[s2])
        multi = {k: v for k, v in groups.items() if len(v) > 1}
        if multi:
            print("\n  shared blocks (co-channel APs divide one medium, they do not add"
                  "\n  capacity; each reports the whole block's occupancy, so read the"
                  "\n  highest figure rather than the sum):")
            for k, v in sorted(multi.items()):
                print(f"    channels {list(k)}: {', '.join(sorted(v))}")
        if pairs:
            print("  Width-aware: two APs can overlap while showing different primary")
            print("  channel numbers. A 40 MHz radio occupies its whole bonded pair.")

    # ================= 2. packet loss  (the dropped-call metric)
    hr("2. PACKET LOSS BY ACCESS POINT")
    print("  Loss, not signal, is what drops a call. Above ~1% is audible;")
    print("  above ~3% a voice call becomes unusable.")
    loss = safe("packet loss", dash.wireless.getOrganizationWirelessDevicesPacketLossByDevice,
                args.org_id, total_pages="all", serials=serials,
                timespan=args.timespan, **bandkw) or []
    lmap = {}
    if loss:
        print(f"\n  {'AP':10} {'down loss%':>11} {'up loss%':>10} {'total%':>8} "
              f"{'down pkts':>12} {'up pkts':>11}")
        rowsl = []
        for e in loss:
            ser = (e.get("device") or {}).get("serial") or e.get("serial")
            dn = e.get("downstream") or {}
            up = e.get("upstream") or {}
            tot = e.get("total") or {}
            r = {"serial": ser, "name": names.get(ser, ser),
                 "down_loss": dn.get("lossPercentage"), "up_loss": up.get("lossPercentage"),
                 "tot_loss": tot.get("lossPercentage"),
                 "down_pkts": dn.get("total"), "up_pkts": up.get("total")}
            rowsl.append(r)
            lmap[ser] = r
        solid = [r for r in rowsl if not thin(r)]
        for r in sorted(rowsl, key=lambda x: -worst_of(x)[0]):
            f = "?  " if thin(r) else flag(worst_of(r)[0], LOSS_WARN, LOSS_BAD)
            print(f"{f}{r['name'][:10]:10} {str(r['down_loss']):>11} {str(r['up_loss']):>10} "
                  f"{str(r['tot_loss']):>8} {str(r['down_pkts']):>12} {str(r['up_pkts']):>11}")
        if len(solid) < len(rowsl):
            print(f"\n  ? = fewer than {MIN_LOSS_PKTS:,} packets behind the figure. One lost")
            print("      packet in nine reads as 11%. These rows are shown but excluded")
            print("      from the median and from the verdict.")
        if not solid:
            print("\n  No access point here carried enough traffic to measure loss against.")
            print("  Re-run during the complaint, or over a longer window.")
        else:
            vals = sorted(worst_of(r)[0] for r in solid)
            med = vals[len(vals)//2]
            spread = vals[-1] - vals[0]
            print(f"\n  median {med:.1f}%   range {vals[0]:.1f}-{vals[-1]:.1f}%   "
                  f"spread {spread:.1f} pts   (over {len(solid)} of {len(rowsl)} APs)")
            print("  (total% is usually null; the worse of upstream/downstream is used)")
            if spread < 3.0 and med >= LOSS_WARN:
                print("  NOTE: every AP here sits in a narrow band around the median, so this")
                print("  looks like a fleet-wide baseline rather than a local fault. Compare")
                print("  against a known-good area before treating it as the cause.")
            outl = [r for r in solid
                    if worst_of(r)[0] >= med * 2 and worst_of(r)[0] >= LOSS_WARN]
            if outl:
                print("  outliers (2x the median):",
                      ", ".join(f"{r['name']} {worst_of(r)[0]:.1f}%" for r in outl))
    else:
        print("  No packet-loss data returned for these APs in this window.")

    # ================= 3. latency by traffic class
    hr("3. LATENCY BY TRAFFIC CLASS, PER ACCESS POINT")
    print("  voiceTraffic is the class that matters for calls. The figure is the")
    print(f"  share of samples at or above the {VOICE_SLOW_MS} ms bucket.")
    print(f"\n  {'AP':10} {'voice avg':>10} {'voice slow%':>12} {'besteff avg':>12} "
          f"{'video avg':>10} {'samples':>10}")
    latrows = []
    for d in sel:
        ls = safe(f"latency {d['serial']}", dash.wireless.getDeviceWirelessLatencyStats,
                  d["serial"], timespan=args.timespan, **bandkw)
        if not ls:
            continue
        v = ls.get("voiceTraffic") or {}
        be = ls.get("bestEffortTraffic") or {}
        vi = ls.get("videoTraffic") or {}
        slow, n = pct_at_or_above(v.get("rawDistribution"), VOICE_SLOW_MS)
        r = {"serial": d["serial"], "name": names[d["serial"]],
             "voice_avg": v.get("avg"), "voice_slow": slow,
             "besteffort_avg": be.get("avg"), "video_avg": vi.get("avg"),
             "voice_samples": n}
        latrows.append(r)
        f = flag(slow, VOICE_SLOW_WARN, VOICE_SLOW_BAD)
        print(f"{f}{r['name'][:10]:10} {str(r['voice_avg']):>10} "
              f"{(('%.2f' % slow) if slow is not None else '-'):>12} "
              f"{str(r['besteffort_avg']):>12} {str(r['video_avg']):>10} {n:>10,}")
    if latrows and not any(r["voice_samples"] for r in latrows):
        print("\n  No latency samples in this window. This endpoint needs a longer")
        print("  timespan - re-run with --timespan 86400 for the voice figures.")
    if latrows:
        bad = [r for r in latrows if (r["voice_slow"] or 0) >= VOICE_SLOW_WARN]
        print(f"\n  {len(bad)} of {len(latrows)} access points above "
              f"{VOICE_SLOW_WARN}% slow voice samples")

    # ================= 4. interference: wifi vs non-wifi
    hr("4. CHANNEL UTILIZATION  -  WI-FI vs NON-WI-FI")
    print("  Non-Wi-Fi energy is interference no access point setting can reduce:")
    print("  Bluetooth, wireless peripherals, microwaves, video senders.")
    u_interval = fit_bucket(args.timespan, UTIL_INTERVALS)
    print(f"  bucket {u_interval}s over a {window_label(args.timespan)} window")
    util = safe("utilization",
                dash.wireless.getOrganizationWirelessDevicesChannelUtilizationByDevice,
                args.org_id, total_pages="all", serials=serials,
                timespan=args.timespan, interval=u_interval) or []
    umap = {}
    if util:
        print(f"\n  {'AP':10} {'band':>5} {'total%':>8} {'wifi%':>8} {'nonWifi%':>10}")
        urows = []
        for e in util:
            ser = e.get("serial")
            for b in e.get("byBand") or []:
                r = {"serial": ser, "name": names.get(ser, ser), "band": b.get("band"),
                     "total": (b.get("total") or {}).get("percentage"),
                     "wifi": (b.get("wifi") or {}).get("percentage"),
                     "nonwifi": (b.get("nonWifi") or {}).get("percentage")}
                urows.append(r)
                umap[(ser, r["band"])] = r
        for r in sorted(urows, key=lambda x: (-(x["nonwifi"] or 0), x["name"])):
            if args.band and r["band"] != args.band:
                continue
            f = flag(r["nonwifi"], NONWIFI_WARN, NONWIFI_BAD)
            fmt = lambda x: ("%.1f" % x) if x is not None else "-"
            print(f"{f}{r['name'][:10]:10} {str(r['band']):>5} "
                  f"{fmt(r['total']):>8} {fmt(r['wifi']):>8} {fmt(r['nonwifi']):>10}")

    # ================= 5. hourly curve for the area
    hr("5. HOURLY UTILIZATION FOR THIS AREA")
    print("  Finds the hour the area degrades. Compare against the reported")
    print("  complaint window.")
    series = defaultdict(lambda: defaultdict(list))
    print(f"  pulling hourly series ({len(sel)*2} calls)")
    for d in sel:
        for band in (["2.4", "5"] if not args.band else [args.band]):
            rows = safe(f"hist {d['serial']} {band}",
                        dash.wireless.getNetworkWirelessChannelUtilizationHistory,
                        net_id, deviceSerial=d["serial"], band=band,
                        timespan=args.timespan,
                        resolution=fit_bucket(args.timespan, HIST_RESOLUTIONS))
            for r in rows or []:
                t = r.get("startTs") or r.get("startTime")
                tot = r.get("utilizationTotal")
                nw = r.get("utilizationNon80211")
                if t and tot is not None:
                    series[t][band].append((tot, nw))
    if series:
        print(f"\n  {'timestamp (UTC)':22} {'2.4 tot':>8} {'2.4 nonW':>9} "
              f"{'5 tot':>7} {'5 nonW':>8}")
        for t in sorted(series):
            out = [f"  {t:22}"]
            for band in ("2.4", "5"):
                v = series[t].get(band) or []
                if v:
                    tm = sum(x[0] for x in v) / len(v)
                    nws = [x[1] for x in v if x[1] is not None]
                    nm = sum(nws) / len(nws) if nws else None
                    out.append(f"{tm:>8.1f}" if band == "2.4" else f"{tm:>7.1f}")
                    out.append(f"{nm:>9.1f}" if band == "2.4" and nm is not None
                               else (f"{nm:>8.1f}" if nm is not None else f"{'-':>8}"))
                else:
                    out += [f"{'-':>8}", f"{'-':>9}"] if band == "2.4" else [f"{'-':>7}", f"{'-':>8}"]
            print(" ".join(out))

    # ================= 6. what these APs hear
    hr("6. FOREIGN NETWORKS HEARD BY THESE ACCESS POINTS")
    am = safe("air marshal", dash.wireless.getNetworkWirelessAirMarshal,
              net_id, timespan=min(args.timespan, 2678400)) or []
    here = defaultdict(list)
    bogus = Counter()
    chan_seen = Counter()
    for e in am:
        for b in e.get("bssids") or []:
            bad = malformed(b.get("bssid"))
            for det in b.get("detectedBy") or []:
                if det.get("device") in set(serials):
                    if bad:
                        bogus[det["device"]] += 1
                        continue
                    ch = b.get("channel") or det.get("channel") or e.get("channel")
                    here[det["device"]].append((b.get("bssid"), ch,
                                                snr_of(det.get("rssi")),
                                                e.get("ssid")))
                    if ch:
                        chan_seen[ch] += 1
    if here:
        print(f"  {'AP':10} {'foreign BSSIDs':>15} {'strongest SNR':>15} {'~dBm':>7} "
              f"{'discarded':>10}")
        for s in sorted(set(here) | set(bogus), key=lambda x: names.get(x, x)):
            v = here.get(s, [])
            snrs = [d[2] for d in v if d[2] is not None]
            best = max(snrs) if snrs else None
            print(f"  {names.get(s,s)[:10]:10} {len(v):>15} "
                  f"{(str(best) if best is not None else '-'):>15} "
                  f"{(str(best - 95) if best is not None else '-'):>7} "
                  f"{(bogus.get(s) or '-'):>10}")
        print("\n  SNR is the figure this endpoint returns: higher is stronger.")
        print("  The dBm column assumes a -95 dBm noise floor and is indicative.")
        if sum(bogus.values()):
            print("  'discarded' = detections whose BSSID is not a valid unicast")
            print("  address. Firmware artifacts, not neighbours. Counting them")
            print("  invents loud interferers that are not there.")
        if not chan_seen:
            print("\n  (channel not reported on these detections)")
        else:
            print("\n  foreign BSSIDs by channel (top 12):")
        for ch, n in chan_seen.most_common(12):
            band = "2.4" if int(ch) <= 14 else "5/6"
            print(f"    ch {ch:>4} ({band}): {n}")
    else:
        print("  No foreign detections attributed to these access points.")

    # ================= 7. failed connections
    hr("7. FAILED CONNECTIONS ON THESE ACCESS POINTS")
    fc = safe("failed", dash.wireless.getNetworkWirelessFailedConnections,
              net_id, timespan=args.timespan) or []
    mine = [f for f in fc if f.get("serial") in set(serials)]
    if mine:
        print("  by step: ", dict(Counter(step_of(f) for f in mine)))
        print("  by AP:")
        for s, n in Counter(f["serial"] for f in mine).most_common(10):
            print(f"    {names.get(s, s)[:12]:12} {n}")
    else:
        print("  None recorded for these access points.")

    # ================= 8. verdict
    hr("VERDICT")
    issues = []
    solid_l = [r for r in lmap.values() if not thin(r)]
    too_thin = sorted(r["name"] for r in lmap.values() if thin(r))
    _lv = sorted(worst_of(r)[0] for r in solid_l)
    loss_median = _lv[len(_lv)//2] if _lv else 0
    if _lv and loss_median >= LOSS_BAD:
        print(f"  Packet loss is elevated across the WHOLE area: median "
              f"{loss_median:.1f}%, range {_lv[0]:.1f}-{_lv[-1]:.1f}%.")
        print(f"  Every access point at or above {LOSS_BAD}% is listed below on its own")
        print("  merit, not relative to its neighbours. A uniformly bad area is still a")
        print("  bad area - compare against a known-good one before concluding the cause")
        print("  is local to these radios.\n")
    elif _lv and _lv[-1] - _lv[0] < 3.0 and loss_median >= LOSS_WARN:
        print(f"  Packet loss sits at {_lv[0]:.1f}-{_lv[-1]:.1f}% across every AP here,")
        print(f"  median {loss_median:.1f}%. A uniform figure below the {LOSS_BAD}% mark is")
        print("  a baseline rather than a local fault. Check it against a healthy area.\n")
    for s in serials:
        nm = names[s]
        l = lmap.get(s)
        if l and not thin(l):
            worst, which, _ = worst_of(l)
            # Two independent gates. The relative one catches an AP that stands
            # apart from its neighbours. The absolute one catches an AP that is
            # bad on its own terms -- without it, an area where EVERY radio is
            # failing reports no problem at all, because nothing exceeds twice
            # a median that is itself terrible.
            stands_apart = worst >= LOSS_WARN and worst >= loss_median * 2
            bad_outright = worst >= LOSS_BAD
            if stands_apart or bad_outright:
                sev = "HIGH" if worst >= LOSS_BAD else "MED"
                why = (f"{worst/max(loss_median,0.1):.1f}x the local median"
                       if stands_apart else
                       f"over the {LOSS_BAD}% threshold outright")
                issues.append((sev, nm, f"{worst}% {which} packet loss - {why}"))
    for r in latrows:
        if (r["voice_slow"] or 0) >= VOICE_SLOW_BAD:
            issues.append(("HIGH", r["name"],
                           f"{r['voice_slow']:.1f}% of voice samples over {VOICE_SLOW_MS} ms"))
        elif (r["voice_slow"] or 0) >= VOICE_SLOW_WARN:
            issues.append(("MED", r["name"],
                           f"{r['voice_slow']:.1f}% of voice samples over {VOICE_SLOW_MS} ms"))
    for (s, band), r in umap.items():
        if (r["total"] or 0) >= UTIL_BAD:
            issues.append(("HIGH", r["name"],
                           f"{r['total']:.1f}% total airtime on {band} GHz - at this "
                           f"level throughput collapses regardless of signal"))
        elif (r["total"] or 0) >= UTIL_WARN:
            issues.append(("MED", r["name"],
                           f"{r['total']:.1f}% total airtime on {band} GHz - approaching "
                           f"the level where throughput degrades"))
        if (r["nonwifi"] or 0) >= NONWIFI_BAD:
            issues.append(("HIGH", r["name"],
                           f"{r['nonwifi']:.1f}% non-Wi-Fi interference on {band} GHz "
                           f"- not fixable by configuration"))
        elif (r["nonwifi"] or 0) >= NONWIFI_WARN:
            issues.append(("MED", r["name"],
                           f"{r['nonwifi']:.1f}% non-Wi-Fi interference on {band} GHz"))
    if not issues:
        print("  No packet loss, voice latency or interference problem found on these")
        print("  access points over this window.")
        print("\n  A localized complaint with clean AP metrics points to:")
        print("    - a coverage hole between APs rather than at one (walk it with a survey)")
        if args.timespan > 1800:
            print(f"    - an intermittent source this {window_label(args.timespan)} average "
                  f"hides (re-run at --timespan {max(1800, args.timespan // 4)})")
        print("    - the wired path, the softphone client, or the VPN")
    else:
        order = {"HIGH": 0, "MED": 1}
        for sev, nm, txt in sorted(issues, key=lambda x: order[x[0]]):
            print(f"  [{sev}] {nm}: {txt}")

    if too_thin:
        print(f"\n  Not judged on loss, under {MIN_LOSS_PKTS:,} packets in this window:")
        print(f"    {', '.join(too_thin)}")
        print("  Few clients, or none. Absence of traffic is not absence of a fault.")

    if args.csv:
        cols = ["name", "serial", "down_loss", "up_loss", "tot_loss",
                "voice_avg", "voice_slow", "besteffort_avg",
                "util_2.4_total", "util_2.4_nonwifi", "util_5_total", "util_5_nonwifi"]
        with open(args.csv, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
            w.writeheader()
            lat = {r["serial"]: r for r in latrows}
            for s in serials:
                row = {"name": names[s], "serial": s}
                row.update({k: v for k, v in (lmap.get(s) or {}).items() if k in cols})
                row.update({k: v for k, v in (lat.get(s) or {}).items() if k in cols})
                for band in ("2.4", "5"):
                    u = umap.get((s, band)) or {}
                    row[f"util_{band}_total"] = u.get("total")
                    row[f"util_{band}_nonwifi"] = u.get("nonwifi")
                w.writerow(row)
        print(f"\n  Wrote {args.csv}")
    print()


if __name__ == "__main__":
    main()
