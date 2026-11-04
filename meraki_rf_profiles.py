#!/usr/bin/env python3
"""
meraki_rf_profiles.py - Which RF profile is each access point actually on?

An RF profile binds to an access point, not to a floor. Floorplans in Meraki
carry no configuration and nothing is inherited from them, so "the floor 5
profile" holds only as long as every AP on floor 5 was individually assigned
it. An AP added later falls to the network default profile and diverges in
silence -- same floor, same map pin, different radio settings.

A per-radio channel or power override beats the profile outright. So an AP can
be on the correct profile, with the correct channel list, and still be parked
on a channel that profile does not permit, because someone pinned it by hand
during an earlier troubleshooting pass and never put it back.

This prints every profile, every AP's assignment, and both kinds of divergence.

SAFETY: same three layers as the other scripts --
  1. PREFLIGHT  - aborts unless the key's admin account is read-only
  2. SIMULATE   - SDK constructed with simulate=True; writes become no-ops
  3. READ-ONLY  - only get* methods are called

Runtime note: the per-radio override is only exposed per device, so this makes
one call per AP. At 4 requests/second that is roughly N/4 seconds for N APs.

Usage:
    export MERAKI_DASHBOARD_API_KEY='...'
    python3 meraki_rf_profiles.py --org-id 1586134
    python3 meraki_rf_profiles.py --org-id 1586134 --floor 5
    python3 meraki_rf_profiles.py --org-id 1586134 --full
"""

import argparse
import json
import os
import re
import sys
import time
from collections import defaultdict

try:
    import meraki
except ImportError:
    sys.exit("Missing SDK. Install with: pip install meraki --break-system-packages")

MAX_RPS = 4.0
_last = [0.0]

# US 5 GHz channels that require dynamic frequency selection. A radar detection
# on one of these moves the AP off channel and imposes a mandatory 60-second
# quiet period on the radio, which every associated client experiences as a
# drop. Their presence in a profile's channel list is therefore a design
# decision worth surfacing, not a detail.
DFS_5GHZ = {52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128,
            132, 136, 140, 144}

# A 5 GHz floor below this leaves clients clinging at rates that cost far more
# airtime than the data they carry. 12 Mbps is the usual starting point in a
# dense office; 6 and below is effectively no floor at all.
MINBITRATE_LOW_5G = 12


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
    """AP naming here is SFAP<floor><nn>, so the first digit is the floor."""
    m = re.match(r"\s*sfap\s*[-_]?(\d)", str(name or ""), re.I)
    return m.group(1) if m else "?"


def yn(v):
    if v is None:
        return "-"
    return "yes" if v else "NO"


def bitrate_of(prof, band):
    """minBitrateType decides where the floor actually lives. With 'band' it is
    in the band settings; with 'ssid' the band value is ignored entirely and
    each SSID carries its own, so printing the band figure would be a lie."""
    if (prof.get("minBitrateType") or "band") == "ssid":
        per = prof.get("perSsidSettings") or {}
        vals = sorted({s.get("minBitrate") for s in per.values()
                       if isinstance(s, dict) and s.get("minBitrate")})
        if not vals:
            return "per-SSID(none)"
        return "per-SSID " + "/".join(str(v) for v in vals)
    key = "twoFourGhzSettings" if band == "2.4" else "fiveGhzSettings"
    v = (prof.get(key) or {}).get("minBitrate")
    return f"{v} Mbps" if v else "-"


def chan_split(chans):
    """Returns (non-DFS, DFS) from a profile's permitted 5 GHz channel list."""
    s = set(chans or [])
    return sorted(s - DFS_5GHZ), sorted(s & DFS_5GHZ)


def steer_of(prof):
    ab = prof.get("apBandSettings") or {}
    return ab.get("bandSteeringEnabled")


def width_of(prof):
    w = (prof.get("fiveGhzSettings") or {}).get("channelWidth")
    return str(w) if w else "-"


def is_default(prof):
    tags = []
    if prof.get("isIndoorDefault"):
        tags.append("indoor")
    if prof.get("isOutdoorDefault"):
        tags.append("outdoor")
    return ",".join(tags) or ""


def override_of(radio):
    """A non-null channel or targetPower on the device itself is a manual pin
    that overrides whatever the profile permits. Null means auto, which is the
    profile doing its job."""
    out = []
    for band, key in (("2.4", "twoFourGhzSettings"), ("5", "fiveGhzSettings")):
        s = (radio or {}).get(key) or {}
        ch, pw = s.get("channel"), s.get("targetPower")
        if ch is not None:
            out.append(f"{band}GHz ch{ch}")
        if pw is not None:
            out.append(f"{band}GHz {pw}dBm")
    return out


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--org-id", required=True)
    p.add_argument("--floor", help="limit the AP table to one floor digit, e.g. 5")
    p.add_argument("--full", action="store_true",
                   help="dump each profile's raw JSON as well")
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

    profs = safe("rf profiles", dash.wireless.getNetworkWirelessRfProfiles,
                 net_id) or []
    by_id = {str(x.get("id")): x for x in profs}

    devs = safe("devices", dash.organizations.getOrganizationDevices,
                args.org_id, total_pages="all", productTypes=["wireless"]) or []
    aps = [d for d in devs if d.get("name")]
    aps.sort(key=lambda d: str(d.get("name")))

    stat = {}
    for s in (safe("statuses", dash.organizations.getOrganizationDevicesStatuses,
                   args.org_id, total_pages="all") or []):
        stat[s.get("serial")] = s.get("status")

    print("=" * 78)
    print("RF PROFILES AND PER-AP ASSIGNMENT")
    print("=" * 78)
    print(f"  key       read-only ({who})")
    print(f"  network   {net.get('name')}")
    print(f"  profiles  {len(profs)}")
    print(f"  APs       {len(aps)}")

    # ---------------------------------------------------------------- 1
    print()
    print("-" * 78)
    print("1. PROFILES")
    print("-" * 78)
    print(f"  {'id':>6}  {'name':24} {'bal':>4} {'steer':>6} "
          f"{'5G minbr':>14} {'width':>6}  default")
    for pr in sorted(profs, key=lambda x: str(x.get("name") or "")):
        print(f"  {str(pr.get('id')):>6}  {str(pr.get('name'))[:24]:24} "
              f"{yn(pr.get('clientBalancingEnabled')):>4} "
              f"{yn(steer_of(pr)):>6} {bitrate_of(pr,'5'):>14} "
              f"{width_of(pr):>6}  {is_default(pr)}")
    if not profs:
        print("  (none defined - every AP is on Meraki's built-in default)")

    print()
    print("  Permitted 5 GHz channels, and the 2.4 GHz floor:")
    for pr in sorted(profs, key=lambda x: str(x.get("name") or "")):
        non, dfs = chan_split((pr.get("fiveGhzSettings") or {}).get("validAutoChannels"))
        print(f"    {str(pr.get('name'))[:24]:24} "
              f"non-DFS {','.join(map(str,non)) or '-'}")
        print(f"    {'':24} DFS     {','.join(map(str,dfs)) or 'none'}"
              f"{'   <-- radar can drop clients' if dfs else ''}")
        print(f"    {'':24} 2.4 GHz {bitrate_of(pr,'2.4')}, "
              f"min bitrate type '{pr.get('minBitrateType') or 'band'}'")

    if args.full:
        print()
        for pr in profs:
            print(f"  --- raw: {pr.get('name')} ---")
            print("  " + json.dumps(pr, indent=2).replace("\n", "\n  "))

    # ---------------------------------------------------------------- 2
    print()
    print("-" * 78)
    print("2. ASSIGNMENT BY AP")
    print("-" * 78)
    print(f"  {'ap':12} {'fl':>2} {'status':>8} {'profile':24} manual override")

    rows = []
    for d in aps:
        fl = floor_of(d.get("name"))
        if args.floor and fl != str(args.floor):
            continue
        radio = safe(f"radio {d.get('name')}",
                     dash.wireless.getDeviceWirelessRadioSettings, d["serial"])
        pid = str((radio or {}).get("rfProfileId") or "")
        pr = by_id.get(pid)
        ov = override_of(radio)
        rows.append({"name": d.get("name"), "serial": d["serial"], "floor": fl,
                     "status": stat.get(d["serial"], "?"), "pid": pid,
                     "pname": (pr.get("name") if pr else
                               ("(network default)" if not pid else f"id {pid}?")),
                     "prof": pr, "ov": ov})
        print(f"  {str(d.get('name'))[:12]:12} {fl:>2} "
              f"{rows[-1]['status'][:8]:>8} {rows[-1]['pname'][:24]:24} "
              f"{', '.join(ov) if ov else '-'}")

    if not rows:
        print("  (no APs matched)")
        return

    # ---------------------------------------------------------------- 3
    print()
    print("-" * 78)
    print("3. DIVERGENCE")
    print("-" * 78)

    byfloor = defaultdict(lambda: defaultdict(list))
    for r in rows:
        byfloor[r["floor"]][r["pname"]].append(r["name"])

    found = False
    for fl in sorted(byfloor):
        groups = byfloor[fl]
        if len(groups) <= 1:
            continue
        found = True
        ranked = sorted(groups.items(), key=lambda kv: -len(kv[1]))
        major = ranked[0]
        print(f"  Floor {fl}: {len(major[1])} AP(s) on '{major[0]}', but --")
        for pname, names in ranked[1:]:
            print(f"      {len(names)} on '{pname}': {', '.join(sorted(names))}")
    if not found:
        print("  Every floor is internally consistent - one profile per floor.")

    orphans = [r["name"] for r in rows if not r["prof"]]
    if orphans:
        print()
        print(f"  On no named profile ({len(orphans)}): {', '.join(sorted(orphans))}")
        print("    These take Meraki's built-in default. A profile edit will")
        print("    not reach them, however many times you apply it.")

    pinned = [r for r in rows if r["ov"]]
    if pinned:
        print()
        print(f"  Manual per-radio overrides ({len(pinned)}) - these beat the profile:")
        for r in pinned:
            print(f"    {r['name']:12} {', '.join(r['ov'])}")
            dfs_pin = [c for c in re.findall(r"5GHz ch(\d+)", " ".join(r["ov"]))
                       if int(c) in DFS_5GHZ]
            if dfs_pin:
                print(f"    {'':12} channel {dfs_pin[0]} is DFS - pinned onto a "
                      f"radar-subject channel")
            if r["prof"]:
                permitted = set((r["prof"].get("fiveGhzSettings") or {})
                                .get("validAutoChannels") or [])
                for c in re.findall(r"5GHz ch(\d+)", " ".join(r["ov"])):
                    if permitted and int(c) not in permitted:
                        print(f"    {'':12} channel {c} is NOT in "
                              f"'{r['prof'].get('name')}' permitted list")
    else:
        print()
        print("  No manual per-radio overrides. Every radio is following its profile.")

    # ---------------------------------------------------------------- 4
    print()
    print("-" * 78)
    print("4. SETTINGS THAT BEAR ON THE CURRENT FAULTS")
    print("-" * 78)

    inuse = {}
    for r in rows:
        if r["prof"]:
            inuse.setdefault(str(r["prof"].get("id")), r["prof"])

    bal = [p.get("name") for p in inuse.values() if p.get("clientBalancingEnabled")]
    if bal:
        print(f"  Client balancing ENABLED on {len(bal)} profile(s) in use:")
        print(f"    {', '.join(sorted(map(str, bal)))}")
        print("    Each steering decision deauthenticates the client, which costs")
        print("    a full auth and DHCP cycle. Turning it off is a per-profile")
        print(f"    edit - all {len(bal)} of these, or the fix is partial.")
    else:
        print("  Client balancing is off on every profile in use.")

    dfs_profs = [p.get("name") for p in inuse.values()
                 if chan_split((p.get("fiveGhzSettings") or {}).get("validAutoChannels"))[1]]
    print()
    if dfs_profs:
        print(f"  DFS channels permitted on {len(dfs_profs)} profile(s) in use:")
        print(f"    {', '.join(sorted(map(str, dfs_profs)))}")
        print("    Any radar hit moves the AP and silences the radio for 60s.")
    else:
        print("  No profile in use permits DFS channels.")

    print()
    low = []
    for p in inuse.values():
        if (p.get("minBitrateType") or "band") != "band":
            continue
        v = (p.get("fiveGhzSettings") or {}).get("minBitrate")
        if v is not None and v < MINBITRATE_LOW_5G:
            low.append(f"{p.get('name')} ({v} Mbps)")
    if low:
        print(f"  5 GHz minimum bitrate below {MINBITRATE_LOW_5G} Mbps on:")
        print(f"    {', '.join(sorted(low))}")
        print("    Distant clients cling at low rates and spend airtime the")
        print("    whole cell pays for.")
    else:
        print(f"  No profile in use sits below {MINBITRATE_LOW_5G} Mbps on 5 GHz.")

    nosteer = [p.get("name") for p in inuse.values() if steer_of(p) is False]
    if nosteer:
        print()
        print(f"  Band steering OFF on: {', '.join(sorted(map(str, nosteer)))}")

    print()
    print(f"  {len(inuse)} profile(s) are actually carrying APs, out of "
          f"{len(profs)} defined.")
    unused = [str(p.get("name")) for p in profs if str(p.get("id")) not in inuse]
    if unused:
        print(f"  Defined but unused: {', '.join(sorted(unused))}")
    print()


if __name__ == "__main__":
    main()
