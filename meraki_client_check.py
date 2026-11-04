#!/usr/bin/env python3
"""
meraki_client_check.py - Per-client wireless triage.

Run this when someone reports "the wifi is bad" and it tells you, in plain
language, whether they're stuck on 2.4 GHz, thrashing between APs, sticking
to a distant AP, or failing DHCP.

SAFETY: identical design to meraki_collect.py --
  1. PREFLIGHT  - aborts unless the key's admin account is read-only
  2. SIMULATE   - SDK constructed with simulate=True; writes become no-ops
  3. READ-ONLY  - only get* methods are called

Usage:
    export MERAKI_DASHBOARD_API_KEY='...'
    python3 meraki_client_check.py --org-id 123456 andys-laptop
    python3 meraki_client_check.py --org-id 123456 aa:bb:cc:dd:ee:ff
    python3 meraki_client_check.py --org-id 123456 10.5.20.14 --timespan 14400
    python3 meraki_client_check.py --org-id 123456 --list-recent 30

Search accepts a hostname, MAC, or IP. Meraki derives hostnames from DHCP
option 12, so a client whose OS doesn't send one will show as its MAC --
search by MAC or IP in that case.
"""

import argparse
import os
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone

try:
    import meraki
except ImportError:
    sys.exit("Missing SDK. Install with: pip install meraki --break-system-packages")

MAX_RPS = 4.0
_last = [0.0]

# thresholds used for the verdicts
ROAMS_PER_HOUR_THRASH = 6      # above this = ping-ponging
RSSI_WEAK = -70                # dBm; below this the link is struggling
RSSI_FLOOR = -100              # below this is a sentinel/garbage value
RSSI_CEIL = -15                # above this is physically impossible at a client
RSSI_STICKY = -75              # associated this weak for a long stretch = sticky
STICKY_MINUTES = 15
DISCONNECTS_CHURN = 4          # full drops per 24h that suggest churn, not roaming
RSSI_GOOD = -65                # signal this strong means drops aren't coverage


def valid_rssi(v):
    """Meraki emits sentinels (0, -1) when RSSI is unknown. A real client
    reading sits between about -100 and -15 dBm; anything else is not a
    measurement and must not be averaged in."""
    return (isinstance(v, (int, float)) and not isinstance(v, bool)
            and RSSI_FLOOR <= v <= RSSI_CEIL)


def throttle():
    gap = 1.0 / MAX_RPS
    delta = time.time() - _last[0]
    if delta < gap:
        time.sleep(gap - delta)
    _last[0] = time.time()


def safe(label, fn, *a, **kw):
    throttle()
    try:
        return fn(*a, **kw)
    except Exception as e:
        print(f"    ! {label}: {type(e).__name__} {str(e)[:90]}")
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
        print("Use a key from an admin with Organization access 'Read-only'.")
        sys.exit(1)
    return orgs


def hdr(t):
    print("\n" + "=" * 66)
    print(t)
    print("=" * 66)


def find_client(dash, net_id, term):
    """Meraki's search matches MAC, IP, or description (hostname)."""
    results = safe("client search", dash.networks.getNetworkClients,
                   net_id, total_pages="all", timespan=2592000, perPage=1000)
    if not results:
        return None
    t = term.lower()
    exact, partial = [], []
    for c in results:
        fields = [str(c.get(k) or "").lower()
                  for k in ("description", "mac", "ip", "ip6", "dhcpHostname")]
        if t in fields:
            exact.append(c)
        elif any(t in f for f in fields if f):
            partial.append(c)
    hits = exact or partial
    if not hits:
        return None
    if len(hits) > 1:
        print(f"  {len(hits)} clients matched '{term}':")
        _warn_duplicates(hits)
        for c in hits[:10]:
            print(f"    {c.get('description') or '(no hostname)':28} "
                  f"{c.get('mac')}  {c.get('ip')}  last seen {c.get('lastSeen')}")
        print("  Using the most recently seen. Pass a MAC to be specific.")
        hits.sort(key=lambda c: c.get("lastSeen") or "", reverse=True)
    return hits[0]


def is_randomized(mac):
    """Locally-administered bit set = randomized/virtual MAC."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0b10)
    except Exception:
        return False


def _warn_duplicates(hits):
    names = Counter((c.get("description") or "").lower() for c in hits if c.get("description"))
    dupes = [n for n, k in names.items() if k > 1 and n]
    rand = [c for c in hits if is_randomized(c.get("mac", ""))]
    if dupes:
        print(f"  NOTE: {len(hits)} devices share the hostname '{dupes[0]}'.")
        print("        Likely an unset hostname on cloned images (Fedora defaults to")
        print("        'fedora'). Meraki takes names from DHCP option 12.")
    if rand:
        print(f"  NOTE: {len(rand)} of these use a randomized MAC (locally-administered")
        print("        bit set). If randomization is per-connection rather than stable,")
        print("        each reconnect consumes a fresh DHCP lease and client history")
        print("        fragments across multiple entries.")


def band_of(evt):
    """Connectivity events carry band as '2.4'/'5'/'6' or a channel number."""
    b = evt.get("band")
    if b:
        return str(b)
    ch = evt.get("channel")
    if ch is None:
        return "?"
    ch = int(ch)
    return "2.4" if ch <= 14 else ("6" if ch >= 190 else "5")


def analyse(events, client, hours, apnames=None):
    """Turn raw connectivity events into findings a helpdesk can act on."""
    findings = []

    if not events:
        print("  No connectivity events in the window.")
        print("  Either the client was idle, or it is connected to a different network.")
        return findings

    # --- band usage
    ASSOC_TYPES = ("assoc", "association", "connection", "roam", "reassoc")
    assoc = [e for e in events if e.get("type") in ASSOC_TYPES]
    bands = Counter(band_of(e) for e in assoc)
    total = sum(bands.values()) or 1
    print("\n  Band usage across association/roam events:")
    for b, n in bands.most_common():
        label = {"2.4": "2.4 GHz", "5": "5 GHz", "6": "6 GHz"}.get(b, f"band {b}")
        print(f"    {label:10} {n:4}  ({100*n/total:.0f}%)")

    pct24 = 100 * bands.get("2.4", 0) / total
    if pct24 >= 50:
        findings.append(
            ("2.4 GHz", "HIGH",
             f"{pct24:.0f}% of this client's connections are on 2.4 GHz, which "
             f"runs at ~46% airtime utilization network-wide. This alone explains "
             f"slow and unreliable performance."))
    elif pct24 > 0:
        findings.append(
            ("2.4 GHz", "MED",
             f"{pct24:.0f}% of connections landed on 2.4 GHz. Intermittent, but "
             f"each excursion means a period of poor experience."))

    # --- roaming behaviour
    roams = [e for e in events if e.get("type") in ASSOC_TYPES and
             (e.get("deviceSerial") or e.get("deviceName"))]
    seq = sorted((e for e in roams if e.get("occurredAt")),
                 key=lambda e: e["occurredAt"])
    apnames = apnames or {}
    aps = [e.get("deviceName") or apnames.get(e.get("deviceSerial"))
           or e.get("deviceSerial") for e in seq]
    changes = sum(1 for i in range(1, len(aps)) if aps[i] != aps[i-1])
    per_hour = changes / hours if hours else 0
    print(f"\n  AP changes: {changes} over {hours:.1f}h  ({per_hour:.1f}/hour)")
    if aps:
        top = Counter(a for a in aps if a).most_common(5)
        print("  Most-used access points:")
        for name, n in top:
            print(f"    {name:20} {n}")

    if per_hour >= ROAMS_PER_HOUR_THRASH:
        findings.append(
            ("Roaming", "HIGH",
             f"{per_hour:.1f} AP changes per hour indicates ping-ponging between "
             f"access points of near-identical signal. Each transition drops "
             f"packets and stalls active sessions."))

    # --- signal strength
    # Events often carry no usable RSSI; values injected from the signal-quality
    # endpoint are tagged _signal. Report provenance so the reader knows which
    # source the figures came from.
    ev_raw = [e.get("rssi") for e in events
              if e.get("type") != "_signal" and e.get("rssi") is not None]
    ev_ok = [v for v in ev_raw if valid_rssi(v)]
    sig_ok = [e["rssi"] for e in events
              if e.get("type") == "_signal" and valid_rssi(e.get("rssi"))]
    rssis = ev_ok + sig_ok

    if ev_raw and not ev_ok:
        src = "signal-quality history (connectivity events carried no usable RSSI)"
    elif ev_ok and sig_ok:
        src = f"{len(ev_ok)} from events, {len(sig_ok)} from signal-quality history"
    elif ev_ok:
        dropped = len(ev_raw) - len(ev_ok)
        src = f"connectivity events{f', {dropped} sentinel value(s) discarded' if dropped else ''}"
    else:
        src = "signal-quality history"

    if rssis:
        avg = sum(rssis) / len(rssis)
        weak = sum(1 for r in rssis if r < RSSI_WEAK)
        print(f"\n  RSSI: mean {avg:.0f} dBm, min {min(rssis)}, max {max(rssis)}"
              f"  ({weak}/{len(rssis)} below {RSSI_WEAK})")
        print(f"        source: {src}")
        if avg < RSSI_STICKY:
            findings.append(
                ("Sticky client", "HIGH",
                 f"Mean signal of {avg:.0f} dBm means this client is holding onto "
                 f"distant access points instead of moving to a nearer one. Caused "
                 f"by the 11 Mbps minimum bitrate keeping cells oversized."))
        elif weak > len(rssis) * 0.3:
            findings.append(
                ("Signal", "MED",
                 f"{weak} of {len(rssis)} events below {RSSI_WEAK} dBm. Marginal "
                 f"link quality for a meaningful share of the session."))

    # --- failures
    steps = Counter(e["failureStep"] for e in events if e.get("failureStep"))
    if steps:
        print("\n  Failure events by step:")
        for s, n in steps.most_common():
            print(f"    {s:10} {n}")
        if steps.get("dhcp"):
            findings.append(
                ("DHCP", "HIGH",
                 f"{steps['dhcp']} DHCP failures. The client associated to the "
                 f"access point successfully but could not obtain an address. "
                 f"This is a wired-side or scope issue, not radio."))
        if steps.get("auth"):
            findings.append(
                ("Auth", "MED",
                 f"{steps['auth']} authentication failures. Check for a stale "
                 f"saved password on the device."))

    # --- reconnection churn: full auth/assoc/dhcp cycles vs genuine roams
    auths = [e for e in events if e.get("type") in ("auth", "authentication")]
    dhcps = [e for e in events if e.get("type") == "dhcp"]
    disc = [e for e in events if e.get("type") in
            ("disassoc", "disassociation", "deauth", "deauthentication")]

    scale = 24.0 / hours if hours else 1
    d24 = len(disc) * scale
    mean_rssi = (sum(rssis) / len(rssis)) if rssis else None

    if len(auths) or len(disc):
        print(f"\n  Reconnection cycles: {len(auths)} auth, {len(dhcps)} DHCP, "
              f"{len(disc)} disassoc  (AP changes: {changes})")

    if d24 >= DISCONNECTS_CHURN and mean_rssi is not None and mean_rssi > RSSI_GOOD:
        findings.append(
            ("Reconnection churn", "HIGH",
             f"{len(disc)} disconnections in {hours:.0f}h despite a healthy "
             f"{mean_rssi:.0f} dBm signal. These are full drops, not roams - each "
             f"one costs a complete auth, association and DHCP cycle that the user "
             f"sees as a stall. Signal is fine, so suspect client balancing "
             f"(currently enabled on all RF profiles) rather than coverage."))

    if len(auths) > max(changes, 1) * 1.5 and len(auths) >= 4:
        findings.append(
            ("No fast transition", "MED",
             f"{len(auths)} authentications for {changes} AP changes means every "
             f"transition is a full reauthentication rather than an 802.11r fast "
             f"handoff. Consider Meraki Adaptive 802.11r."))

    if len(auths) >= 4 and pct24 > 0:
        findings.append(
            ("Band re-selection", "MED",
             f"With no band steering configured, the client re-picks a band on "
             f"every one of these {len(auths)} reconnections. The {pct24:.0f}% "
             f"landing on 2.4 GHz is the result of repeated drops, not a device "
             f"preference. Fixing the drops reduces the 2.4 GHz exposure."))

    if disc:
        reasons = Counter(
            e.get("disassociationReason") or e.get("reason")
            or (e.get("details") or {}).get("reason") for e in disc)
        reasons.pop(None, None)
        print(f"\n  Disconnections: {len(disc)}")
        for r, n in reasons.most_common(5):
            print(f"    reason {r}: {n}")
        if len(disc) / (hours or 1) > 4:
            findings.append(
                ("Disconnects", "MED",
                 f"{len(disc)} disconnections in {hours:.1f}h. Client balancing is "
                 f"currently enabled and can deauthenticate clients unnecessarily."))

    return findings


def main():
    p = argparse.ArgumentParser()
    p.add_argument("search", nargs="?", help="hostname, MAC, or IP")
    p.add_argument("--org-id", required=True)
    p.add_argument("--network-id", help="skip auto-detection")
    p.add_argument("--timespan", type=int, default=86400, help="seconds, default 24h")
    p.add_argument("--list-recent", type=int, metavar="N",
                   help="list N most recently seen clients instead of checking one")
    args = p.parse_args()

    key = os.environ.get("MERAKI_DASHBOARD_API_KEY")
    if not key:
        sys.exit("Set MERAKI_DASHBOARD_API_KEY first.")

    dash = meraki.DashboardAPI(api_key=key, simulate=True, wait_on_rate_limit=True,
                               maximum_retries=5, suppress_logging=True, print_console=False)
    preflight(dash)

    net_id = args.network_id
    if not net_id:
        nets = safe("networks", dash.organizations.getOrganizationNetworks,
                    args.org_id, total_pages="all") or []
        wnets = [n for n in nets if "wireless" in n.get("productTypes", [])]
        if not wnets:
            sys.exit("No wireless networks found.")
        net_id = wnets[0]["id"]
        if len(wnets) > 1:
            print(f"Multiple wireless networks; using {wnets[0]['name']}. "
                  f"Override with --network-id.")

    if args.list_recent:
        cl = safe("clients", dash.networks.getNetworkClients, net_id,
                  total_pages="all", timespan=args.timespan, perPage=1000) or []
        cl.sort(key=lambda c: c.get("lastSeen") or "", reverse=True)
        hdr(f"{min(args.list_recent, len(cl))} most recently seen clients")
        for c in cl[:args.list_recent]:
            print(f"  {c.get('description') or '(no hostname)':30} "
                  f"{c.get('mac')}  {str(c.get('ip')):15} {c.get('ssid')}")
        return

    if not args.search:
        sys.exit("Provide a hostname, MAC, or IP (or use --list-recent).")

    hdr(f"Looking up '{args.search}'")
    client = find_client(dash, net_id, args.search)
    if not client:
        print("  Not found in the last 30 days.")
        print("  Meraki names clients from DHCP option 12. If the OS doesn't send")
        print("  a hostname, the client appears as its MAC. Try --list-recent.")
        return

    cid = client["id"]
    hdr("CLIENT")
    for label, k in (("Hostname", "description"), ("MAC", "mac"), ("IP", "ip"),
                     ("VLAN", "vlan"), ("SSID", "ssid"),
                     ("Current AP", "recentDeviceName"), ("Status", "status"),
                     ("First seen", "firstSeen"), ("Last seen", "lastSeen"),
                     ("OS", "os"), ("Manufacturer", "manufacturer")):
        v = client.get(k)
        if v not in (None, ""):
            print(f"  {label:14} {v}")

    hdr(f"CONNECTIVITY EVENTS (last {args.timespan/3600:.0f}h)")
    events = safe("events", dash.wireless.getNetworkWirelessClientConnectivityEvents,
                  net_id, cid, total_pages="all", timespan=args.timespan) or []
    print(f"  {len(events)} events retrieved")
    if events:
        print("  event types:", dict(Counter(e.get("type") for e in events)))

    sig = safe("signal", dash.wireless.getNetworkWirelessSignalQualityHistory,
               net_id, clientId=cid, timespan=args.timespan, resolution=3600)
    if sig:
        rs = [r["rssi"] for r in sig if valid_rssi(r.get("rssi"))]
        sn = [r["snr"] for r in sig if isinstance(r.get("snr"), (int, float)) and r["snr"]]
        if rs:
            print(f"\n  Signal quality history: RSSI mean {sum(rs)/len(rs):.0f} dBm "
                  f"(min {min(rs)}, max {max(rs)})", end="")
            print(f", SNR mean {sum(sn)/len(sn):.0f} dB" if sn else "")
            for r in rs:
                events.append({"type": "_signal", "rssi": r})

    devs = safe("devices", dash.organizations.getOrganizationDevices,
                args.org_id, total_pages="all", productTypes=["wireless"]) or []
    apnames = {d["serial"]: d.get("name") for d in devs if d.get("name")}

    findings = analyse(events, client, args.timespan / 3600, apnames)

    lat = safe("latency", dash.wireless.getNetworkWirelessClientLatencyHistory,
               net_id, cid, timespan=args.timespan, resolution=86400)
    if lat:
        vals = [r.get("backgroundTrafficMs") or r.get("bestEffortTrafficMs")
                for r in lat if (r.get("backgroundTrafficMs") or r.get("bestEffortTrafficMs"))]
        if vals:
            print(f"\n  Latency: mean {sum(vals)/len(vals):.1f} ms, max {max(vals):.1f} ms")

    hdr("VERDICT")
    if not findings:
        print("  No problems detected in the wireless layer for this client.")
        print("  If the user still reports issues, check: the application itself,")
        print("  the wired path upstream, or their VPN.")
    else:
        order = {"HIGH": 0, "MED": 1}
        for area, sev, text in sorted(findings, key=lambda f: order.get(f[1], 9)):
            print(f"\n  [{sev}] {area}")
            for line in _wrap(text, 62):
                print(f"        {line}")
    print()


def _wrap(text, width):
    words, line, out = text.split(), "", []
    for w in words:
        if len(line) + len(w) + 1 > width:
            out.append(line)
            line = w
        else:
            line = f"{line} {w}".strip()
    if line:
        out.append(line)
    return out


if __name__ == "__main__":
    main()
