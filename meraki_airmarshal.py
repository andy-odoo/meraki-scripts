#!/usr/bin/env python3
"""
meraki_airmarshal.py - What do specific access points actually hear?

Air Marshal in the dashboard lists every SSID the estate detects, which on a
large deployment is hundreds of rows with no easy way to ask the only question
that matters during a complaint: what is THIS access point hearing, how loud,
and on which channel.

A NOTE ON THE SIGNAL FIELD. The Air Marshal endpoint returns a non-negative
number in its 'rssi' field. It is not dBm -- a received signal at -2 dBm is
not physically possible. It behaves as signal-to-noise ratio in dB, where
HIGHER IS STRONGER, and converting with a nominal -95 dBm noise floor
reproduces the figures the dashboard's RF Spectrum view shows. This script
therefore reports SNR as the primary figure and an estimated dBm alongside it,
clearly marked as an estimate. Sorting is strongest-first.

SAFETY: same three layers as the other scripts --
  1. PREFLIGHT  - aborts unless the key's admin account is read-only
  2. SIMULATE   - SDK constructed with simulate=True; writes become no-ops
  3. READ-ONLY  - only get* methods are called

Usage:
    export MERAKI_DASHBOARD_API_KEY='...'
    python3 meraki_airmarshal.py --org-id 1586134 --ap SFAP511
    python3 meraki_airmarshal.py --org-id 1586134 --ap SFAP511,SFAP512 --min-snr 30
    python3 meraki_airmarshal.py --org-id 1586134 --ap SFAP511 --channel 44 --csv heard.csv
"""

import argparse
import csv
import os
import sys
import time
from collections import defaultdict

try:
    import meraki
except ImportError:
    sys.exit("Missing SDK. Install with: pip install meraki --break-system-packages")

NOISE_FLOOR = -95          # nominal, for the dBm estimate only
STRONG_SNR = 35            # ~ -60 dBm; the threshold for "loud enough to matter"

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


def as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def snr_of(d):
    """Return the signal figure as SNR in dB, higher being stronger.

    Values at or above 100 are discarded. Real SNR tops out around 70, and
    the endpoint emits 252-255 as sentinels -- an unsigned byte holding a
    small negative number, meaning 'no reading'. Taken at face value those
    sort to the top of the list and invent interferers that do not exist."""
    for k in ("rssi", "signal", "snr", "rssi0"):
        v = d.get(k)
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            v = int(v)
            v = -v if v < 0 else v         # tolerate either sign convention
            if v >= 100:
                return None
            return v
    return None


def device_of(d):
    for k in ("device", "serial", "name", "deviceSerial", "deviceName"):
        v = d.get(k)
        if isinstance(v, str) and v:
            return v
        if isinstance(v, dict):
            return v.get("serial") or v.get("name") or ""
    return ""


def bssid_flag(bssid):
    """Reasons a BSSID cannot be a real neighbouring network."""
    parts = bssid.split(":")
    if len(parts) != 6:
        return "BADFORM"
    try:
        octets = [int(p, 16) for p in parts]
    except ValueError:
        return "BADFORM"
    if all(o == 0 for o in octets[:5]):
        return "NULLMAC"          # 00:00:00:00:00:xx is not an address
    if octets[0] & 0x01:
        return "MULTICAST"        # a BSSID is always unicast
    return ""


def locally_administered(bssid):
    """Set on randomised MACs -- phone hotspots and privacy-mode clients."""
    try:
        return bool(int(bssid.split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--org-id", required=True)
    p.add_argument("--network", help="network name or ID substring")
    p.add_argument("--ap", help="comma-separated AP names; omit for all")
    p.add_argument("--hours", type=float, default=1.0,
                   help="look back this many hours (default 1, max 744)")
    p.add_argument("--min-snr", type=int, default=20,
                   help="ignore detections below this SNR in dB (default 20, "
                        "roughly -75 dBm)")
    p.add_argument("--channel", type=int, help="only this channel")
    p.add_argument("--csv", help="write the detections here")
    args = p.parse_args()

    key = os.environ.get("MERAKI_DASHBOARD_API_KEY")
    if not key:
        sys.exit("Set MERAKI_DASHBOARD_API_KEY first.")

    timespan = int(min(args.hours, 744.0) * 3600)
    want_aps = set()
    if args.ap:
        want_aps = {a.strip().upper() for a in args.ap.split(",") if a.strip()}

    dash = meraki.DashboardAPI(api_key=key, simulate=True,
                               wait_on_rate_limit=True, maximum_retries=5,
                               suppress_logging=True, print_console=False)
    who = preflight(dash)

    print("=" * 78)
    print("AIR MARSHAL - WHAT THESE ACCESS POINTS HEAR")
    print("=" * 78)
    print("  key        read-only (%s)" % who)
    print("  window     last %.1f h" % args.hours)
    print("  threshold  SNR %d dB and above (approx %d dBm)"
          % (args.min_snr, NOISE_FLOOR + args.min_snr))
    if want_aps:
        print("  APs        %s" % ", ".join(sorted(want_aps)))
    if args.channel:
        print("  channel    %d only" % args.channel)
    print()
    print("  SNR is the signal figure this endpoint returns: HIGHER IS")
    print("  STRONGER. The dBm column is an estimate using a %d dBm noise"
          % NOISE_FLOOR)
    print("  floor and should be treated as indicative, not measured.")

    nets = safe("networks", dash.organizations.getOrganizationNetworks,
                args.org_id, total_pages="all") or []
    nets = [n for n in nets if "wireless" in (n.get("productTypes") or [])]
    if args.network:
        q = args.network.lower()
        nets = [n for n in nets
                if q in (n.get("name") or "").lower() or q in n["id"].lower()]
    if not nets:
        sys.exit("No wireless networks matched.")

    devs = safe("devices", dash.organizations.getOrganizationDevices,
                args.org_id, total_pages="all") or []
    name_of = {d["serial"]: (d.get("name") or d["serial"]) for d in devs}

    rows = []
    for n in nets:
        res = safe("air marshal %s" % n["name"],
                   dash.wireless.getNetworkWirelessAirMarshal,
                   n["id"], timespan=timespan)
        for entry in (res or []):
            ssid = entry.get("ssid") or "(hidden)"
            wired = entry.get("wiredMacs") or []
            chans = []
            for c in as_list(entry.get("channels")):
                try:
                    chans.append(int(c))
                except (TypeError, ValueError):
                    pass
            if args.channel and args.channel not in chans:
                continue
            for b in as_list(entry.get("bssids")):
                bssid = (b.get("bssid") or "").lower()
                flag = bssid_flag(bssid)
                for det in as_list(b.get("detectedBy")):
                    dev = device_of(det)
                    ap = name_of.get(dev, dev)
                    if want_aps and ap.upper() not in want_aps:
                        continue
                    s = snr_of(det)
                    if s is None or s < args.min_snr:
                        continue
                    rows.append({
                        "ap": ap,
                        "snr": s,
                        "est_dbm": NOISE_FLOOR + s,
                        "channel": ",".join(str(c) for c in chans[:6])
                                   + ("+" if len(chans) > 6 else ""),
                        "n_chan": len(chans),
                        "bssid": bssid,
                        "ssid": ssid,
                        "random": "yes" if locally_administered(bssid) else "",
                        "on_lan": "YES" if wired else "",
                        "flags": flag,
                        "network": n["name"],
                    })

    if not rows:
        print()
        print("  No detections at SNR %d or above in the last %.1f h."
              % (args.min_snr, args.hours))
        print("  Loosen with --min-snr 10 or widen with --hours 24.")
        return

    by_ap = defaultdict(list)
    for r in rows:
        by_ap[r["ap"]].append(r)

    for ap in sorted(by_ap):
        rs = sorted(by_ap[ap], key=lambda r: -r["snr"])
        print()
        print("-" * 78)
        print("%s  -  %d detection(s), strongest first" % (ap, len(rs)))
        print("-" * 78)
        print("  %-4s %-7s %-19s %-7s %-6s %-10s %s"
              % ("SNR", "~dBm", "bssid", "random", "LAN", "flags", "ssid"))
        print("  " + "-" * 80)
        for r in rs[:40]:
            print("  %-4d %-7d %-19s %-7s %-6s %-10s %s"
                  % (r["snr"], r["est_dbm"], r["bssid"], r["random"],
                     r["on_lan"], r["flags"], r["ssid"][:22]))
        if len(rs) > 40:
            print("  ... and %d weaker" % (len(rs) - 40))

        bad = [r for r in rs if r["flags"]]
        real = [r for r in rs if not r["flags"]]
        strong = [r for r in real if r["snr"] >= STRONG_SNR]
        print()
        print("  %d detections: %d plausible, %d malformed."
              % (len(rs), len(real), len(bad)))
        print("  %d at SNR %d or above (approx %d dBm or stronger)."
              % (len(strong), STRONG_SNR, NOISE_FLOOR + STRONG_SNR))
        if bad:
            print()
            print("  MALFORMED entries are not valid BSSIDs -- a null address,")
            print("  or the multicast bit set in the first octet. They are")
            print("  artifacts, not neighbouring networks. Discount them.")
        if strong:
            print()
            print("  Loud enough to matter:")
            for r in strong:
                tag = "randomised MAC" if r["random"] else ""
                print("    SNR %-3d  ch %-10s  %-22s %s"
                      % (r["snr"], r["channel"], r["ssid"][:22], tag))
            print()
            print("  Check the channel column against the band your affected")
            print("  clients are actually using. A loud neighbour on a band")
            print("  your users are not on cannot be their problem.")
        else:
            print()
            print("  Nothing foreign is loud enough to degrade this access")
            print("  point. Interference is not the explanation here.")

    anylan = [r for r in rows if r["on_lan"]]
    if anylan:
        print()
        print("=" * 78)
        print("DETECTED ON THE WIRED LAN  (%d)" % len(anylan))
        print("=" * 78)
        for r in anylan:
            print("  %-19s SNR %-4d %s" % (r["bssid"], r["snr"], r["ssid"]))

    if args.csv:
        cols = ["ap", "snr", "est_dbm", "channel", "n_chan", "bssid", "ssid",
                "random", "on_lan", "flags", "network"]
        with open(args.csv, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
            w.writeheader()
            w.writerows(sorted(rows, key=lambda r: (r["ap"], -r["snr"])))
        print()
        print("  Wrote %s (%d rows)" % (args.csv, len(rows)))

    print()


if __name__ == "__main__":
    main()
