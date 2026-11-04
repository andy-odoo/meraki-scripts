#!/usr/bin/env python3
"""
meraki_group_policy_audit.py - Inventory every group policy and find conflicts.

"Conflict" is not one thing, so this checks several distinct classes:

  SETTINGS THAT DO NOTHING   rules or bandwidth limits configured while the
                             section is set to 'network default', so Meraki
                             ignores them. The single most common cause of
                             "I set a limit and it isn't applying."
  COMPETING ASSIGNMENTS      a client reachable by more than one assignment
                             path (manual, iPSK, RADIUS, SSID default). Only
                             one wins and the loser is invisible.
  DEAD FIREWALL RULES        an L3 rule fully shadowed by an earlier rule, so
                             it can never match.
  VLAN TAG ERRORS            a policy tagging a VLAN that no appliance in the
                             org defines.
  INACTIVE SCHEDULES         a policy whose schedule means it is not in force
                             right now, which reads as "the policy is broken."
  CROSS-POLICY DRIFT         policies tagging the same VLAN but treating it
                             differently; near-duplicate policies; policies
                             with nothing assigned to them.

SAFETY: identical design to the other scripts in this set --
  1. PREFLIGHT  - aborts unless the key's admin account is read-only
  2. SIMULATE   - SDK constructed with simulate=True; writes become no-ops
  3. READ-ONLY  - only get* methods are called

SECRETS: the identity-PSK and SSID endpoints return passphrases and RADIUS
shared secrets in cleartext. Nothing from those fields is ever printed. See
scrub() -- it is deliberately an allowlist of what may be shown, not a
denylist of what may not.

Usage:
    export MERAKI_DASHBOARD_API_KEY='...'
    python3 meraki_group_policy_audit.py --org-id 123456
    python3 meraki_group_policy_audit.py --org-id 123456 --network-id N_123
    python3 meraki_group_policy_audit.py --org-id 123456 --timespan 7d
"""

import argparse
import ipaddress
import os
import re
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime

try:
    from zoneinfo import ZoneInfo
except ImportError:
    ZoneInfo = None

try:
    import meraki
except ImportError:
    sys.exit("Missing SDK. Install with: pip install meraki --break-system-packages")

MAX_RPS = 4.0
_last = [0.0]

NEAR_DUPLICATE_FIELDS = ("bandwidth", "firewallAndTrafficShaping",
                         "contentFiltering", "vlanTagging", "splashAuthSettings")

# Per-client states Meraki exposes through the same field as a group policy
# assignment, but which are not group policies and carry no id.
SPECIAL_POLICIES = {"normal", "blocked", "allowed", "whitelisted"}

_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}

# Fields that may be printed from an SSID or identity-PSK record. Anything not
# listed is dropped, so a future SDK version that adds a new secret-bearing
# field cannot leak it by default.
SSID_SHOW = ("number", "name", "enabled", "authMode", "encryptionMode",
             "ipAssignmentMode", "useVlanTagging", "defaultVlanId",
             "perClientBandwidthLimitUp", "perClientBandwidthLimitDown",
             "perSsidBandwidthLimitUp", "perSsidBandwidthLimitDown",
             "splashPage", "visible", "availableOnAllAps",
             "minBitrate", "bandSelection", "lanIsolationEnabled")
IPSK_SHOW = ("id", "name", "groupPolicyId", "expiresAt")


def duration(text):
    """Parse '7d', '2h', '90m' or a bare number of seconds."""
    raw = str(text).strip().lower().replace(" ", "")
    if raw.isdigit():
        total = int(raw)
    else:
        parts = re.findall(r"(\d+)([smhd])", raw)
        if not parts or "".join(n + u for n, u in parts) != raw:
            raise argparse.ArgumentTypeError(
                f"'{text}' is not a timespan. Use 7d, 2h, 90m, or seconds.")
        total = sum(int(n) * _UNITS[u] for n, u in parts)
    if total <= 0:
        raise argparse.ArgumentTypeError("timespan must be greater than zero")
    return total


def scrub(record, allowed):
    """Return only the allowlisted keys. Used on every SSID and iPSK object."""
    return {k: record.get(k) for k in allowed if record.get(k) is not None}


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
    print("\n" + "=" * 74)
    print(t)
    print("=" * 74)


def sub(t):
    print(f"\n  --- {t} ---")


def plural(n, word, suffix="s"):
    return f"{n} {word}" + ("" if n == 1 else suffix)


def ssid_list(v):
    """Render the ssid field of an assignment as plain numbers."""
    if not v:
        return "-"
    nums = []
    for s in v:
        if isinstance(s, dict):
            n = s.get("ssidNumber", s.get("number"))
            if n is not None:
                nums.append(str(n))
        else:
            nums.append(str(s))
    return ",".join(nums) if nums else "-"


def kbps(v):
    """Meraki bandwidth limits are stored in Kbps; None or 0 means no limit.

    The raw figure is always shown. Meraki's dashboard fields do not all use
    the same Kbps-per-Mbps multiplier -- a limit entered as 100 Mbps can be
    stored as 102400 -- so a rendered "102 Mbps" cannot be compared against
    what the dashboard displays unless the stored number is beside it.
    """
    if v in (None, 0):
        return "unlimited"
    # Meraki's dashboard stores these fields as Mbps x 1024, so an exact
    # multiple of 1024 can be reported as the number someone actually typed.
    # Anything else was entered as a raw Kbps figure and is marked with ~,
    # which is itself a useful signal that the value was hand-edited.
    if v % 1024 == 0:
        return f"{v // 1024} Mbps [{v} Kbps]"
    return f"~{v/1024:.1f} Mbps [{v} Kbps]"


# --------------------------------------------------------------- rule coverage

def parse_ports(spec):
    """'any' -> None (matches everything). '80,443,8000-8100' -> set of ranges."""
    if spec is None:
        return None
    s = str(spec).strip().lower()
    if s in ("any", "", "*"):
        return None
    out = []
    for part in s.split(","):
        part = part.strip()
        if "-" in part:
            a, _, b = part.partition("-")
            try:
                out.append((int(a), int(b)))
            except ValueError:
                return "unparsed"
        else:
            try:
                out.append((int(part), int(part)))
            except ValueError:
                return "unparsed"
    return out


def ports_cover(a, b):
    """Does port spec a match everything port spec b matches?"""
    if a is None:
        return True
    if b is None or a == "unparsed" or b == "unparsed":
        return False
    return all(any(lo_a <= lo_b and hi_b <= hi_a for lo_a, hi_a in a)
               for lo_b, hi_b in b)


def parse_cidrs(spec):
    """'any' -> None. Returns (networks, had_non_ip) so FQDN entries are not
    silently treated as covered."""
    if spec is None:
        return None, False
    s = str(spec).strip().lower()
    if s in ("any", "", "*", "0.0.0.0/0"):
        return None, False
    nets, other = [], False
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            other = True          # an FQDN or a name, not comparable by subnet
    return nets, other


def cidrs_cover(a_spec, b_spec):
    a, a_other = parse_cidrs(a_spec)
    b, b_other = parse_cidrs(b_spec)
    if a is None and not a_other:
        return True               # 'any' covers everything
    if a_other or b_other:
        return False              # refuse to reason about hostnames
    if b is None:
        return False              # a specific CIDR cannot cover 'any'
    return all(any(nb.version == na.version and nb.subnet_of(na) for na in a)
               for nb in b)


def proto_covers(a, b):
    a = (a or "any").lower()
    b = (b or "any").lower()
    return a == "any" or a == b


def rule_covers(a, b):
    """True when rule a matches every packet rule b would match, so b is dead.

    Deliberately conservative: anything not provable returns False. A missed
    shadow is a quiet omission, a false one sends someone to delete a working
    rule.
    """
    return (proto_covers(a.get("protocol"), b.get("protocol"))
            and cidrs_cover(a.get("destCidr"), b.get("destCidr"))
            and ports_cover(parse_ports(a.get("destPort")),
                            parse_ports(b.get("destPort"))))


# ------------------------------------------------------------------ scheduling

DAYS = ("monday", "tuesday", "wednesday", "thursday",
        "friday", "saturday", "sunday")


def _mins(hhmm):
    try:
        h, _, m = str(hhmm).partition(":")
        return int(h) * 60 + int(m)
    except Exception:
        return None


def schedule_state(sched, tzname):
    """(active_now, description) for a policy's schedule."""
    if not sched or not sched.get("enabled"):
        return True, "always on"
    now = None
    if ZoneInfo and tzname:
        try:
            now = datetime.now(ZoneInfo(tzname))
        except Exception:
            now = None
    if now is None:
        now = datetime.now()
        tzname = "local time (network timezone unavailable)"

    today = DAYS[now.weekday()]
    day = sched.get(today) or {}
    if not day.get("active"):
        return False, f"not active on {today} ({tzname})"
    lo, hi = _mins(day.get("from")), _mins(day.get("to"))
    cur = now.hour * 60 + now.minute
    if lo is None or hi is None:
        return True, f"active {today}, window unparsed"
    if hi == 0:
        hi = 24 * 60
    inside = lo <= cur < hi if lo <= hi else (cur >= lo or cur < hi)
    when = f"{day.get('from')}-{day.get('to')} {today} ({tzname})"
    return inside, ("inside window " + when) if inside else ("OUTSIDE window " + when)


# --------------------------------------------------------------------- helpers

def section_state(block):
    """Group policy sections carry a 'settings' field that decides whether the
    rest of the block is used at all. Returns (settings, is_active)."""
    s = (block or {}).get("settings") or "network default"
    return s, s not in ("network default",)


def has_content(block):
    """Does the section carry configuration that would do something if active?"""
    b = block or {}
    return bool(b.get("l3FirewallRules") or b.get("l7FirewallRules")
                or b.get("trafficShapingRules")
                or (b.get("bandwidthLimits") or {}).get("limitUp")
                or (b.get("bandwidthLimits") or {}).get("limitDown")
                or b.get("allowedUrlPatterns") or b.get("blockedUrlPatterns")
                or b.get("blockedUrlCategories"))


def render_defs(defs):
    """What traffic a shaping rule matches, as one readable line."""
    out = []
    for d in defs or []:
        v = d.get("value")
        if isinstance(v, dict):
            v = v.get("name") or v.get("id") or str(v)
        out.append(f"{d.get('type')}:{v}")
    return ", ".join(out) or "all traffic"


def per_client(block):
    """A shaping rule's own per-client limit, which is separate from and can
    override the policy's bandwidth setting."""
    b = block or {}
    s = b.get("settings") or "network default"
    lim = b.get("bandwidthLimits") or {}
    if s == "custom":
        return s, lim.get("limitUp"), lim.get("limitDown")
    return s, None, None


def find_speed_burst(obj):
    """Locate any speedBurst setting anywhere in a returned object.

    Speed Burst permits roughly 4x the configured limit for about 5 seconds,
    which is the most common reason a bandwidth limit looks like it is not
    applying: a short speed test reads 4x and settles, or finishes before it
    settles at all. Its position in the API payload has moved between
    versions, so this searches for the key rather than assuming a path.
    """
    found = []

    def walk(o, path):
        if isinstance(o, dict):
            for k, v in o.items():
                if k.lower() == "speedburst":
                    en = v.get("enabled") if isinstance(v, dict) else v
                    found.append((".".join(path + [k]), bool(en)))
                else:
                    walk(v, path + [k])
        elif isinstance(o, list):
            for i, v in enumerate(o):
                walk(v, path + [str(i)])

    walk(obj, [])
    return found


def fingerprint(gp):
    """A comparable shape for near-duplicate detection, name excluded."""
    import json
    return json.dumps({k: gp.get(k) for k in NEAR_DUPLICATE_FIELDS},
                      sort_keys=True, default=str)


def material_fingerprint(gp):
    """What a policy actually DOES, reduced so two networks can be compared.

    Two corrections over comparing the raw blocks, both learned the hard way:

    1. Firewall rule CONTENT is excluded. Two sites with different IP space
       always differ there, so including it reported every shared policy as
       a difference.
    2. The reduction is to EFFECTIVE behaviour, and every absent or null
       field is normalised to its default. The API returns 'network default'
       in one network and null in another for the same setting, and it
       returns a leftover vlanId on a section that is switched off. Compared
       raw, those read as differences when the behaviour is identical --
       which is what made the first attempt at this check useless.
    """
    import json
    bw = gp.get("bandwidth") or {}
    bset = bw.get("settings") or "network default"
    lim = bw.get("bandwidthLimits") or {}
    bandwidth = ([bset, lim.get("limitUp"), lim.get("limitDown")]
                 if bset == "custom" else [bset])

    vt = gp.get("vlanTagging") or {}
    vset = vt.get("settings") or "network default"
    vlan = [vset, vt.get("vlanId")] if vset == "custom" else [vset]

    fw = gp.get("firewallAndTrafficShaping") or {}
    return json.dumps([bandwidth, vlan,
                       fw.get("settings") or "network default",
                       gp.get("splashAuthSettings") or "network default"],
                      default=str)


# ----------------------------------------------------------------------- audit

def audit_network(dash, org_id, net, org_vlans, findings, registry):
    nid, nname = net["id"], net["name"]
    hdr(f"NETWORK: {nname}   ({nid})")

    gps = safe("group policies", dash.networks.getNetworkGroupPolicies, nid)
    if gps is None:
        print("  Could not read group policies for this network.")
        return
    if not gps:
        print("  No group policies defined.")
        return

    tz = (safe("network", dash.networks.getNetwork, nid) or {}).get("timeZone")
    by_id = {str(g.get("groupPolicyId")): g for g in gps}

    # ---------------------------------------------------------- 1. inventory
    sub(f"1. INVENTORY  ({len(gps)} policies)")
    for gp in sorted(gps, key=lambda g: (g.get("name") or "").lower()):
        gid = str(gp.get("groupPolicyId"))
        registry[gid].append((nname, gp.get("name"), material_fingerprint(gp)))
        print(f"\n  [{gid}] {gp.get('name')}")

        bw = gp.get("bandwidth") or {}
        bset, bactive = section_state(bw)
        lim = bw.get("bandwidthLimits") or {}
        if bactive and bset == "custom":
            print(f"      bandwidth        custom  up {kbps(lim.get('limitUp'))} / "
                  f"down {kbps(lim.get('limitDown'))}")
        elif bset == "ignore":
            print("      bandwidth        ignore network limit (unlimited)")
        else:
            # Flag the inert case on the inventory line itself. The dashboard
            # keeps displaying numbers that Meraki is not applying, so an
            # inventory that printed only 'network default' would hide exactly
            # the thing someone is scanning for.
            ghost = ""
            if lim.get("limitUp") or lim.get("limitDown"):
                ghost = (f"   <-- {kbps(lim.get('limitUp'))}/"
                         f"{kbps(lim.get('limitDown'))} configured but IGNORED")
            print(f"      bandwidth        {bset}{ghost}")

        fw = gp.get("firewallAndTrafficShaping") or {}
        fset, factive = section_state(fw)
        n3 = len(fw.get("l3FirewallRules") or [])
        n7 = len(fw.get("l7FirewallRules") or [])
        nts = len(fw.get("trafficShapingRules") or [])
        fghost = "   <-- rules IGNORED" if (not factive and (n3 or n7 or nts)) else ""
        print(f"      firewall/shaping {fset}  (L3 {n3}, L7 {n7}, shaping {nts}){fghost}")

        vt = gp.get("vlanTagging") or {}
        vset, vactive = section_state(vt)
        if vactive:
            vsuffix = f"  -> VLAN {vt.get('vlanId')}"
        elif vt.get("vlanId"):
            vsuffix = f"   <-- VLAN {vt.get('vlanId')} configured but IGNORED"
        else:
            vsuffix = ""
        print(f"      vlan tagging     {vset}{vsuffix}")

        cf = gp.get("contentFiltering") or {}
        cparts = []
        for key, label in (("allowedUrlPatterns", "allow"),
                           ("blockedUrlPatterns", "block"),
                           ("blockedUrlCategories", "categories")):
            blk = cf.get(key) or {}
            st = blk.get("settings") or "network default"
            cnt = len(blk.get("patterns") or blk.get("categories") or [])
            if st != "network default" or cnt:
                cparts.append(f"{label}={st}({cnt})")
        print(f"      content filter   {', '.join(cparts) if cparts else 'network default'}")

        print(f"      splash           {gp.get('splashAuthSettings') or 'network default'}")

        active, desc = schedule_state(gp.get("scheduling"), tz)
        print(f"      schedule         {desc}")

        # ---- conflict: configured but inert
        if not bactive and (lim.get("limitUp") or lim.get("limitDown")):
            findings.append((nname, "HIGH", f"[{gid}] {gp.get('name')}",
                             f"Bandwidth limits are configured ({kbps(lim.get('limitUp'))} up / "
                             f"{kbps(lim.get('limitDown'))} down) but the section is set to "
                             f"'{bset}', so Meraki ignores them entirely. The dashboard still "
                             f"displays the numbers, which is why this reads as a working limit."))
        if not factive and has_content(fw):
            findings.append((nname, "HIGH", f"[{gid}] {gp.get('name')}",
                             f"{n3} L3 rules, {n7} L7 rules and {nts} shaping rules are defined "
                             f"while the section is set to '{fset}'. None of them are applied."))
        if not vactive and vt.get("vlanId"):
            findings.append((nname, "MED", f"[{gid}] {gp.get('name')}",
                             f"VLAN {vt.get('vlanId')} is configured but tagging is set to "
                             f"'{vset}', so clients stay on the SSID's VLAN."))
        if not active:
            findings.append((nname, "MED", f"[{gid}] {gp.get('name')}",
                             f"Schedule is enabled and the policy is {desc}. Anything assigned "
                             f"to it is unpoliced right now."))

    # ------------------------------------------------------ 2. assignment map
    sub("2. ASSIGNMENT MAP")

    # Only ask for SSIDs where the network actually has wireless. Calling the
    # endpoint on an appliance-only network returns a 400 that reads like a
    # failure rather than an absence.
    if "wireless" in net.get("productTypes", []):
        ssids = safe("ssids", dash.wireless.getNetworkWirelessSsids, nid) or []
    else:
        ssids = []
        print("\n  No wireless on this network, so no SSID or iPSK assignments.")
    live = [s for s in ssids if s.get("enabled")]
    ipsk_by_gp = defaultdict(list)

    if live:
        print("\n  Enabled SSIDs:")
        for s in live:
            v = scrub(s, SSID_SHOW)
            bits = [f"auth={v.get('authMode')}"]
            if v.get("useVlanTagging"):
                bits.append(f"vlan={v.get('defaultVlanId')}")
            up, dn = v.get("perClientBandwidthLimitUp"), v.get("perClientBandwidthLimitDown")
            if up or dn:
                bits.append(f"per-client {kbps(up)}/{kbps(dn)}")
            if v.get("lanIsolationEnabled"):
                bits.append("L2 isolation ON")
            print(f"    {v.get('number'):>2}  {v.get('name'):24} {'  '.join(bits)}")

            # Identity PSKs map a passphrase to a group policy. The endpoint
            # returns the passphrase itself; scrub() drops it before anything
            # reaches the screen.
            #
            # Match "psk" anywhere in the auth mode, not as a suffix. The
            # mode that actually carries identity PSKs is called
            # 'ipsk-without-radius', which does not end in "psk" -- an
            # endswith test silently skipped the one SSID whose iPSK
            # mapping matters most.
            if "psk" in (s.get("authMode") or "").lower():
                ips = safe(f"ipsks ssid {s.get('number')}",
                           dash.wireless.getNetworkWirelessSsidIdentityPsks,
                           nid, s.get("number"))
                for p in (ips or []):
                    q = scrub(p, IPSK_SHOW)
                    gid = str(q.get("groupPolicyId"))
                    ipsk_by_gp[gid].append((s.get("name"), q.get("name")))
                    gname = (by_id.get(gid) or {}).get("name", "UNKNOWN POLICY")
                    print(f"          iPSK '{q.get('name')}' -> [{gid}] {gname}")
    elif "wireless" in net.get("productTypes", []):
        print("  No enabled wireless SSIDs on this network.")

    pbc = safe("policies by client", dash.networks.getNetworkPoliciesByClient,
               nid, total_pages="all", perPage=1000, timespan=AUDIT_TIMESPAN[0])
    client_gp = defaultdict(list)
    special = defaultdict(list)
    multi = []
    if pbc is None:
        print("\n  Per-client policy assignments unavailable on this network.")
    else:
        for row in pbc:
            seen = {}
            who = row.get("name") or row.get("clientId")
            for a in row.get("assigned") or []:
                gid = str(a.get("groupPolicyId"))
                pname = (a.get("name") or "").strip()
                # A per-client policy of Normal, Blocked or Allowed is a
                # built-in state, not a group policy, and carries no
                # groupPolicyId. Treating those as "assigned to a deleted
                # policy" is wrong and hides what they actually are.
                if gid in ("None", "null", ""):
                    if pname.lower() in SPECIAL_POLICIES:
                        if pname.lower() != "normal":
                            special[pname].append(who)
                        continue
                    # genuinely an id-less assignment we cannot explain
                    special[f"unresolved ({pname or 'unnamed'})"].append(who)
                    continue
                client_gp[gid].append(who)
                seen[(a.get("type"), gid, pname)] = a.get("ssid")
            distinct = {k[1] for k in seen}
            if len(distinct) > 1:
                multi.append((who, seen))
        assigned_total = sum(len(v) for v in client_gp.values())
        print(f"\n  {plural(len(pbc), 'client')} with a non-default policy, "
              f"{plural(assigned_total, 'group policy assignment')}.")
        print("  (Clients left on 'Normal' are not returned by this endpoint.)")
        if client_gp:
            print(f"\n    {'policy':38} {'clients':>7}  examples")
        for gid, names in sorted(client_gp.items(), key=lambda kv: -len(kv[1])):
            gname = (by_id.get(gid) or {}).get("name", "UNKNOWN / removed policy")
            uniq = sorted(set(names))
            sample = ", ".join(uniq[:4])
            more = f" (+{len(uniq)-4} more)" if len(uniq) > 4 else ""
            print(f"    {f'[{gid}] {gname}'[:38]:38} {len(uniq):>7}  {sample}{more}")
            if gid not in by_id:
                findings.append((nname, "HIGH", f"[{gid}] unknown",
                                 f"{plural(len(set(names)), 'client')} assigned to group policy "
                                 f"id {gid}, which no longer exists in this network. Deleting a "
                                 f"policy does not clear its client assignments."))

        if special:
            print("\n  Built-in per-client states (not group policies):")
            for state, who in sorted(special.items()):
                print(f"    {state:22} {plural(len(set(who)), 'client')}   "
                      f"{', '.join(sorted(set(who))[:5])}")
                if state.lower() in ("blocked", "allowed", "whitelisted"):
                    findings.append((nname, "MED", f"per-client '{state}'",
                                     f"{plural(len(set(who)), 'client')} manually set to "
                                     f"'{state}': {', '.join(sorted(set(who))[:5])}. This is a "
                                     f"hand-made exception that overrides normal policy and "
                                     f"survives staff and vendor turnover. Confirm each one is "
                                     f"still wanted and still belongs to someone current."))
                elif state.startswith("unresolved"):
                    findings.append((nname, "MED", "unresolved assignment",
                                     f"{plural(len(set(who)), 'client')} carry a policy "
                                     f"assignment with no group policy id and no recognised "
                                     f"built-in state: {', '.join(sorted(set(who))[:5])}. Check "
                                     f"these in the dashboard directly."))

    # -------------------------------------------------- 3. competing assignments
    sub("3. CLIENTS WITH COMPETING ASSIGNMENTS")
    if multi:
        print(f"\n  {plural(len(multi), 'client')} can receive more than one policy:")
        for name, seen in multi[:25]:
            print(f"\n    {name}")
            for (typ, gid, pname), ssid in seen.items():
                gname = (by_id.get(gid) or {}).get("name", pname or "?")
                print(f"      via {str(typ):12} [{gid}] {gname:28} ssid {ssid_list(ssid)}")
        findings.append((nname, "HIGH", "assignment precedence",
                         f"{plural(len(multi), 'client')} with more than one group policy path. "
                         f"Only one applies. Meraki's documented order is client-level assignment "
                         f"first, then Systems Manager sentry, then RADIUS or iPSK, then the "
                         f"SSID default - confirm against current documentation before relying "
                         f"on it, and remove the paths you do not want."))
    else:
        print("\n  None. Every client resolves to a single policy.")

    # ------------------------------------------------------- 4. vlan tagging
    sub("4. VLAN TAGGING")
    tagged = defaultdict(list)
    for gp in gps:
        vt = gp.get("vlanTagging") or {}
        _, vactive = section_state(vt)
        if vactive and vt.get("vlanId"):
            tagged[str(vt["vlanId"])].append(gp)
    if not tagged:
        print("\n  No policy overrides the VLAN.")
    for vid, pols in sorted(tagged.items(), key=lambda kv: int(kv[0])):
        known = org_vlans.get(vid)
        label = f"{known['name']} ({known['subnet']}) on {known['net']}" if known \
            else "NOT DEFINED ON ANY APPLIANCE IN THIS ORG"
        print(f"\n    VLAN {vid}: {label}")
        for gp in pols:
            print(f"      [{gp.get('groupPolicyId')}] {gp.get('name')}")
        if not known:
            findings.append((nname, "HIGH", f"VLAN {vid}",
                             f"{len(pols)} policy(ies) tag VLAN {vid}, which is not defined on "
                             f"any appliance in this organization. Clients tagged into an "
                             f"undefined VLAN get no gateway and no DHCP."))
        if len(pols) > 1:
            shapes = {fingerprint(p) for p in pols}
            if len(shapes) > 1:
                findings.append((nname, "MED", f"VLAN {vid}",
                                 f"{len(pols)} policies tag VLAN {vid} but treat it differently "
                                 f"(bandwidth, firewall or filtering differ). Clients on one "
                                 f"subnet get inconsistent treatment depending on which policy "
                                 f"caught them: "
                                 + ", ".join(p.get("name") or "?" for p in pols)))

    # --------------------------------------------------- 5. bandwidth resolution
    sub("5. BANDWIDTH, RESOLVED")
    ssid_limits = {s.get("number"): (s.get("perClientBandwidthLimitUp"),
                                     s.get("perClientBandwidthLimitDown"))
                   for s in live}
    if ssid_limits:
        print("\n  SSID per-client limits (the floor a 'network default' policy inherits):")
        for num, (u, d) in sorted(ssid_limits.items()):
            nm = next((s.get("name") for s in live if s.get("number") == num), "?")
            print(f"    ssid {num} {nm:24} up {kbps(u)} / down {kbps(d)}")
    print("\n  Effective per-policy limit:")
    for gp in sorted(gps, key=lambda g: (g.get("name") or "").lower()):
        bw = gp.get("bandwidth") or {}
        bset, bactive = section_state(bw)
        lim = bw.get("bandwidthLimits") or {}
        if bset == "custom":
            eff = f"{kbps(lim.get('limitUp'))} / {kbps(lim.get('limitDown'))}"
        elif bset == "ignore":
            eff = "unlimited (network limit ignored)"
        else:
            eff = "whatever the SSID sets"
        print(f"    {(gp.get('name') or '?'):32} {eff}")

    # ------------------------------------------------------ 6. rule shadowing
    sub("6. TRAFFIC SHAPING RULES INSIDE POLICIES")
    # A policy's bandwidth field is not the only limit it carries. Each
    # traffic shaping rule has its own per-client limit, which for the
    # traffic it matches can be lower than the policy's figure, or can be
    # set to ignore the limit entirely. Reporting only the rule COUNT hides
    # whichever of those is actually in force.
    any_shaping = False
    # Collected rather than reported per policy. Every policy here carries
    # the same rule, so one finding per policy produced ten restatements of
    # a single fact and buried everything else.
    ignoring = []
    builtin_ssids = []
    for gp in sorted(gps, key=lambda g: (g.get("name") or "").lower()):
        fw = gp.get("firewallAndTrafficShaping") or {}
        fset, factive = section_state(fw)
        rules = fw.get("trafficShapingRules") or []
        if not rules:
            continue
        any_shaping = True
        bw = gp.get("bandwidth") or {}
        bset = (bw.get("settings") or "network default")
        plim = (bw.get("bandwidthLimits") or {}).get("limitDown")
        print(f"\n    [{gp.get('groupPolicyId')}] {gp.get('name')}"
              f"   policy bandwidth: "
              f"{kbps(plim) if bset == 'custom' else bset}"
              + ("" if factive else "   (section inactive - rules do nothing)"))
        for i, r in enumerate(rules, 1):
            s, up, dn = per_client(r.get("perClientBandwidthLimits"))
            dscp = r.get("dscpTagValue")
            bits = [f"per-client {s}"]
            if s == "custom":
                bits.append(f"{kbps(up)} up / {kbps(dn)} down")
            if dscp is not None:
                bits.append(f"dscp {dscp}")
            if r.get("priority"):
                bits.append(f"priority {r['priority']}")
            print(f"      rule {i}: {render_defs(r.get('definitions'))}")
            print(f"              {'  '.join(bits)}")

            if not factive:
                continue
            if s == "ignore":
                ignoring.append((gp.get("name"), i, render_defs(r.get("definitions"))))
            elif s == "custom" and bset == "custom" and dn and plim and dn < plim:
                findings.append((nname, "MED", f"{gp.get('name')} shaping rule {i}",
                                 f"For {render_defs(r.get('definitions'))} this rule caps "
                                 f"clients at {kbps(dn)} down, below the policy's own "
                                 f"{kbps(plim)}. For that traffic the rule is the real limit, "
                                 f"not the number shown on the policy."))
    if not any_shaping:
        print("\n    No group policy carries a traffic shaping rule.")

    if ignoring:
        matched = sorted({m for _, _, m in ignoring})
        npol = len({n for n, _, _ in ignoring})
        findings.append((nname, "MED", "shaping rules exempt traffic from the limit",
                         f"{plural(len(ignoring), 'shaping rule')} across "
                         f"{npol} {'policy' if npol == 1 else 'policies'}"
                         f" set per-client bandwidth to IGNORE, so the traffic they match is "
                         f"exempt from the policy limit entirely. Matched traffic: "
                         + "; ".join(matched)
                         + ". Policies: " + ", ".join(sorted({n for n, _, _ in ignoring}))
                         + ". If a bandwidth limit appears not to apply, test with traffic "
                           "that is NOT in these categories before looking anywhere else."))

    # SSID-level shaping is a separate layer again, and sits between the
    # network default and the group policy.
    if live:
        print("\n    SSID-level shaping:")
        for s in live:
            tsr = safe(f"ssid {s.get('number')} shaping",
                       dash.wireless.getNetworkWirelessSsidTrafficShapingRules,
                       nid, s.get("number"))
            if tsr is None:
                continue
            on = tsr.get("trafficShapingEnabled")
            defaults = tsr.get("defaultRulesEnabled")
            rules = tsr.get("rules") or []
            print(f"      ssid {s.get('number')} {s.get('name'):22} "
                  f"shaping={'on' if on else 'off'}  "
                  f"built-in rules={'on' if defaults else 'off'}  custom={len(rules)}")
            for i, r in enumerate(rules, 1):
                st, up, dn = per_client(r.get("perClientBandwidthLimits"))
                extra = f" {kbps(up)}/{kbps(dn)}" if st == "custom" else ""
                print(f"          rule {i}: {render_defs(r.get('definitions'))}"
                      f"  -> per-client {st}{extra}")
            if defaults:
                builtin_ssids.append(f"{s.get('number')} {s.get('name')}")
        if builtin_ssids:
            findings.append((nname, "LOW", "built-in shaping rules",
                             "Meraki's built-in shaping rules are enabled on SSID "
                             + "; SSID ".join(builtin_ssids)
                             + ". They apply on top of any custom rule and the API cannot "
                               "enumerate them, so this audit proves what IS configured, not "
                               "that nothing else is. Read them in the dashboard before "
                               "concluding a limit has no other source."))

    # Speed Burst, searched for rather than assumed, across policies and SSIDs.
    bursts = []
    for gp in gps:
        for path, en in find_speed_burst(gp):
            if en:
                bursts.append(f"policy '{gp.get('name')}' ({path})")
    for s in live:
        for path, en in find_speed_burst(s):
            if en:
                bursts.append(f"ssid {s.get('number')} '{s.get('name')}' ({path})")
    if bursts:
        print("\n    Speed Burst ENABLED on:")
        for b in bursts:
            print(f"      {b}")
        findings.append((nname, "MED", "speed burst",
                         "Speed Burst is enabled on " + "; ".join(bursts) +
                         ". It permits roughly 4x the configured limit for about five "
                         "seconds, so a short speed test reads far above the limit and "
                         "the limit looks like it is not applying. Disable it before "
                         "measuring whether a bandwidth limit works."))
    else:
        print("\n    Speed Burst: not enabled anywhere (or not reported by this API version).")

    sub("7. FIREWALL RULE SHADOWING")
    any_shadow = False
    for gp in gps:
        fw = gp.get("firewallAndTrafficShaping") or {}
        _, factive = section_state(fw)
        rules = fw.get("l3FirewallRules") or []
        dead = []
        for i, b in enumerate(rules):
            for j, a in enumerate(rules[:i]):
                if rule_covers(a, b):
                    dead.append((j, a, i, b))
                    break
        l7 = fw.get("l7FirewallRules") or []
        dupes = [v for v, n in Counter(
            (r.get("type"), str(r.get("value"))) for r in l7).items() if n > 1]
        if dead or dupes:
            any_shadow = True
            print(f"\n    [{gp.get('groupPolicyId')}] {gp.get('name')}"
                  + ("" if factive else "   (section inactive - cosmetic only)"))
            for j, a, i, b in dead:
                print(f"      rule {i+1} ({b.get('policy')} {b.get('protocol')} "
                      f"{b.get('destCidr')}:{b.get('destPort')}) is unreachable")
                print(f"           shadowed by rule {j+1} ({a.get('policy')} "
                      f"{a.get('protocol')} {a.get('destCidr')}:{a.get('destPort')})")
                if factive:
                    sev = "HIGH" if a.get("policy") != b.get("policy") else "MED"
                    findings.append((nname, sev, f"{gp.get('name')} rule {i+1}",
                                     f"L3 rule {i+1} can never match: rule {j+1} above it "
                                     f"already covers every packet it would. "
                                     + ("The two rules have opposite actions, so the intended "
                                        "behaviour is not happening."
                                        if a.get("policy") != b.get("policy")
                                        else "Same action, so it is redundant rather than wrong.")))
            for typ, val in dupes:
                print(f"      duplicate L7 rule: {typ} = {val}")
    if not any_shadow:
        print("\n  No unreachable L3 rules and no duplicate L7 rules.")

    # ----------------------------------------------------- 7. cross-policy drift
    sub("8. CROSS-POLICY DRIFT")
    shapes = defaultdict(list)
    for gp in gps:
        shapes[fingerprint(gp)].append(gp.get("name") or "?")
    dups = {k: v for k, v in shapes.items() if len(v) > 1}
    if dups:
        for _, names in dups.items():
            print(f"\n    Identical settings, different names: {', '.join(names)}")
            findings.append((nname, "MED", "duplicate policies",
                             f"These policies are byte-identical in every setting that matters: "
                             f"{', '.join(names)}. Whichever one a client lands on, the result "
                             f"is the same - but the names imply otherwise, which is how people "
                             f"end up editing the wrong one."))
    else:
        print("\n    No two policies share identical settings.")

    if pbc is not None:
        unused = [g for g in gps if str(g.get("groupPolicyId")) not in client_gp
                  and str(g.get("groupPolicyId")) not in ipsk_by_gp]
        if unused:
            print(f"\n    {len(unused)} policies with nothing assigned:")
            for g in unused:
                print(f"      [{g.get('groupPolicyId')}] {g.get('name')}")
            findings.append((nname, "LOW", "unused policies",
                             f"{len(unused)} policies have no clients and no iPSK pointing at "
                             f"them: " + ", ".join(g.get("name") or "?" for g in unused)
                             + ". Harmless, but they are what makes the list hard to read."))


# ------------------------------------------------------------------------ main

AUDIT_TIMESPAN = [2592000]       # 30d; set from --timespan in main()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--org-id", required=True)
    p.add_argument("--network-id", help="audit one network instead of all")
    p.add_argument("--timespan", type=duration, default=2592000, metavar="SPAN",
                   help="how far back to look for client assignments "
                        "(7d, 30d, or seconds; default 30d)")
    args = p.parse_args()
    AUDIT_TIMESPAN[0] = args.timespan

    key = os.environ.get("MERAKI_DASHBOARD_API_KEY")
    if not key:
        sys.exit("Set MERAKI_DASHBOARD_API_KEY first.")

    dash = meraki.DashboardAPI(api_key=key, simulate=True, wait_on_rate_limit=True,
                               maximum_retries=5, suppress_logging=True,
                               print_console=False)
    preflight(dash)

    nets = safe("networks", dash.organizations.getOrganizationNetworks,
                args.org_id, total_pages="all") or []
    if not nets:
        sys.exit("No networks found.")

    # VLANs are defined on appliance networks, but group policies that tag a
    # VLAN usually live on the wireless network. Collect the union across the
    # org so a tag can be validated wherever it was written.
    org_vlans = {}
    for n in nets:
        if "appliance" not in n.get("productTypes", []):
            continue
        for v in (safe(f"vlans {n['name']}", dash.appliance.getNetworkApplianceVlans,
                       n["id"]) or []):
            org_vlans[str(v.get("id"))] = {"name": v.get("name"),
                                           "subnet": v.get("subnet"),
                                           "net": n["name"]}

    targets = [n for n in nets if n["id"] == args.network_id] if args.network_id \
        else [n for n in nets if {"wireless", "appliance", "switch"} & set(n.get("productTypes", []))]
    if not targets:
        sys.exit("No matching networks.")

    hdr("GROUP POLICY AUDIT")
    print(f"  {len(targets)} network(s), {len(org_vlans)} VLANs known org-wide")
    print(f"  client assignment lookback: {args.timespan//86400}d")

    findings = []
    registry = defaultdict(list)
    for n in targets:
        audit_network(dash, args.org_id, n, org_vlans, findings, registry)

    # Group policy ids are per-network, so the same id means different things
    # in different networks. That is normal; what is dangerous is the same id
    # carrying a different NAME, because anything written against the id --
    # a script, a runbook, a note -- then does something else depending on
    # which network it runs in.
    if len(targets) > 1:
        hdr("SAME POLICY ID, DIFFERENT MEANING ACROSS NETWORKS")
        clashes = 0
        for gid, entries in sorted(registry.items(), key=lambda kv: kv[0]):
            if len(entries) < 2:
                continue
            names = {e[1] for e in entries}
            shapes = {e[2] for e in entries}
            if len(names) == 1 and len(shapes) == 1:
                continue
            clashes += 1
            print(f"\n  id {gid}:")
            for net_name, pol_name, _ in entries:
                print(f"    {net_name:28} {pol_name}")
            if len(names) > 1:
                findings.append(("org-wide", "MED", f"policy id {gid}",
                                 "The same group policy id means different policies in "
                                 "different networks: "
                                 + "; ".join(f"{n} = '{p}'" for n, p, _ in entries)
                                 + ". Anything written against the id rather than the name "
                                   "will do something different depending on where it runs."))
            elif len(shapes) > 1:
                findings.append(("org-wide", "LOW", f"policy id {gid}",
                                 f"'{list(names)[0]}' exists in "
                                 + " and ".join(n for n, _, _ in entries)
                                 + " with the same id and name but different bandwidth, VLAN "
                                   "or splash settings. Firewall rule content is not compared, "
                                   "since it is expected to differ between sites."))
        if not clashes:
            print("\n  None. Shared ids carry the same name and settings everywhere.")

    hdr("CONFLICTS")
    if not findings:
        print("  None found.")
    else:
        order = {"HIGH": 0, "MED": 1, "LOW": 2}
        for net, sev, where, text in sorted(findings,
                                            key=lambda f: (order.get(f[1], 9), f[0])):
            print(f"\n  [{sev}] {net}  //  {where}")
            for line in _wrap(text, 68):
                print(f"        {line}")
    print()
    print("  Precedence between assignment paths is Meraki behaviour, not")
    print("  something this script can measure. Where a client has competing")
    print("  paths, the fix is to remove the ones you do not want rather than")
    print("  to rely on the order.")
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
