// SPDX-License-Identifier: MIT
// Traffic-routing detection and enforcement. Detects whether the user manages
// routing themselves (custom routing table or static routes/rules referencing
// the VPN interface) and, only when automatic routing is enabled AND no manual
// scheme is detected, maintains the firewall zone, the kill-switch and
// IPv6-leak rules and the DNS override. Every object this module creates is
// stamped with `nordvpn_managed`/`nordvpn_role`, and only stamped objects are
// ever modified or removed — user configuration is never touched.

'use strict';

import { readfile } from 'fs';
const _common = require('nordvpn.common');
const run = _common.run,
      atomic_write = _common.atomic_write;
const _clients = require('nordvpn.clients');

const MARK = 'nordvpn_managed';
const ROLE = 'nordvpn_role';
// NordVPN DNS resolvers by mode. 'standard' is the plain resolver; 'threat' is
// Threat Protection (blocks ads and malware at the DNS level). Both only work
// reliably through the tunnel.
const VPN_DNS = {
	standard: '103.86.96.100 103.86.99.100',
	threat:   '103.86.96.96 103.86.99.99'
};
const RT_TABLES = '/etc/iproute2/rt_tables';

// ── Small uci helpers ────────────────────────────────────────────────

// Normalize a zone/forwarding 'network' option (string or list) to an array.
function as_list(v) {
	if (v == null)
		return [];
	if (type(v) == 'array')
		return v;
	return split('' + v, ' ');
}

function find_peer(uci, iface) {
	let found = null;
	uci.foreach('network', null, function(sec) {
		if (sec['.type'] && index(sec['.type'], 'wireguard_') == 0 && sec.interface == iface) {
			found = sec['.name'];
			return false;
		}
	});
	return found;
}

// Zone whose network list contains the interface: { name, section, managed }.
function find_zone_of(uci, iface) {
	let found = null;
	uci.foreach('firewall', 'zone', function(sec) {
		for (let n in as_list(sec.network)) {
			if (n == iface) {
				found = { name: sec.name, section: sec['.name'], managed: sec[MARK] == '1' };
				return false;
			}
		}
	});
	return found;
}

// Best-effort WAN zone: prefer a masquerading zone, fall back to name 'wan'.
function find_wan_zone(uci) {
	let masq = null, named = null;
	uci.foreach('firewall', 'zone', function(sec) {
		if (sec[MARK] == '1')
			return;
		if (sec.masq == '1' && !masq)
			masq = sec.name;
		if (sec.name == 'wan' && !named)
			named = sec.name;
	});
	return masq || named;
}

// Best-effort LAN zone: name 'lan', else a zone containing network 'lan'.
function find_lan_zone(uci) {
	let named = null, holding = null;
	uci.foreach('firewall', 'zone', function(sec) {
		if (sec[MARK] == '1')
			return;
		if (sec.name == 'lan' && !named)
			named = sec.name;
		for (let n in as_list(sec.network))
			if (n == 'lan' && !holding)
				holding = sec.name;
	});
	return named || holding;
}

// User (hand-written) static routes/rules referencing the interface or its
// table. A section is machine-generated only when it carries a complete stamp
// family under one prefix: `X_managed` equal to '1' AND the companions
// `X_role` and `X_iface` (real managing applications always stamp all three).
// A lone `X_managed`, a partial family, or mixed prefixes are not a stamp.
function count_user_routes(uci, iface, table) {
	let n = 0;
	let check = function(sec) {
		for (let k in keys(sec)) {
			let m = match(k, /^(.+)_managed$/);
			if (m && sec[k] == '1' &&
			    sec[m[1] + '_role'] != null &&
			    sec[m[1] + '_iface'] != null)
				return;
		}
		if (sec.interface == iface)
			n++;
		else if (table && table != '' && sec.table == table)
			n++;
	};
	for (let t in [ 'route', 'route6', 'rule', 'rule6' ])
		uci.foreach('network', t, check);
	return n;
}

// Stamped firewall section (rule/forwarding/zone) with the given role, or
// null. Zone/forwarding objects are per-interface (pass `iface`); the kill
// switch and IPv6 block are global (leave `iface` null).
function find_managed(uci, sectype, role, iface) {
	let found = null;
	uci.foreach('firewall', sectype, function(sec) {
		if (sec[MARK] == '1' && sec[ROLE] == role && (iface == null || sec.nordvpn_iface == iface)) {
			found = sec['.name'];
			return false;
		}
	});
	return found;
}

// The automatic kill switch / IPv6 block of instance `iface`. Rules from
// before they were owned per instance carry no nordvpn_iface; those are
// returned too (legacy: true) so the owner can adopt them.
function find_owned(uci, role, iface) {
	let own = find_managed(uci, 'rule', role, iface);
	if (own)
		return { name: own, legacy: false };
	let legacy = null;
	uci.foreach('firewall', 'rule', function(sec) {
		if (sec[MARK] == '1' && sec[ROLE] == role && !sec.nordvpn_iface) {
			legacy = sec['.name'];
			return false;
		}
	});
	return legacy ? { name: legacy, legacy: true } : null;
}

// Whether instance `iface` has its automatic `role` rule: its own, or an
// unowned legacy one while it is the instance routing all LAN traffic.
function owned_here(uci, role, iface, auto) {
	let f = find_owned(uci, role, iface);
	return f != null && (!f.legacy || !!auto);
}

// The instance that routes all LAN traffic, as seen by instance `name`: the
// first enabled instance (main first) with "Route all LAN traffic" on that
// comes before `name`. Only one instance can own the LAN's default path —
// two would race for the same default route or policy-rule priority and one
// tunnel would silently carry everything. null when `name` may have it.
function all_lan_owner(uci, name) {
	for (let n in _common.list_instances(uci)) {
		if (n == name)
			return null;
		let o = _common.load_settings(uci, n);
		if (o.enabled && o.auto_routing)
			return n;
	}
	return null;
}

// True when an enabled instance other than `skip` has "Route all LAN
// traffic" on.
function any_all_lan(uci, skip) {
	for (let n in _common.list_instances(uci)) {
		if (n == skip)
			continue;
		let o = _common.load_settings(uci, n);
		if (o.enabled && o.auto_routing)
			return true;
	}
	return false;
}

// ── Local subnets (steering bypass) ──────────────────────────────────
// A steered table's default swallows traffic to OTHER local subnets too, so
// LAN↔VLAN and LAN↔tunnel-services connectivity would silently die. Steering
// therefore maintains stamped bypass routes for every local IPv4 subnet.

function ip4_to_int(a) {
	// No newline: ucode's anchors are per-line (see common.full_match).
	if (type(a) != 'string' || index(a, '\n') >= 0)
		return null;
	let m = match(a, /^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$/);
	if (!m)
		return null;
	let o1 = int(m[1]), o2 = int(m[2]), o3 = int(m[3]), o4 = int(m[4]);
	if (o1 > 255 || o2 > 255 || o3 > 255 || o4 > 255)
		return null;
	return ((o1 * 256 + o2) * 256 + o3) * 256 + o4;
}

function int_to_ip4(n) {
	return sprintf('%d.%d.%d.%d',
		(n >> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff);
}

function mask_len(netmask) {
	let n = ip4_to_int(netmask);
	if (n == null)
		return null;
	let len = 0;
	while (len < 32 && (n & 0x80000000)) {
		len++;
		n = (n << 1) & 0xffffffff;
	}
	return (n & 0xffffffff) == 0 ? len : null;
}

// Normalized 'a.b.c.d/len' network of a uci route section, accepting both the
// CIDR target form and the separate target+netmask form. Null when unparsable.
function route_cidr(sec) {
	let t = '' + (sec.target || '');
	let addr = null, len = null;
	let m = match(t, /^([0-9.]+)\/([0-9]+)$/);
	if (m) {
		addr = m[1];
		len = int(m[2]);
	} else if (sec.netmask) {
		addr = t;
		len = mask_len('' + sec.netmask);
	} else {
		return null;
	}
	if (len == null || len < 0 || len > 32)
		return null;
	let ip = ip4_to_int(addr);
	if (ip == null)
		return null;
	let mask = (len == 0) ? 0 : ((0xffffffff << (32 - len)) & 0xffffffff);
	return sprintf('%s/%d', int_to_ip4(ip & mask), len);
}

// Every local IPv4 subnet as { target: 'a.b.c.d/len', iface: <logical name> },
// from the static config plus (when available) netifd's runtime state, which
// also covers DHCP-assigned networks and tunnels like a user WireGuard link.
// `skip` maps interface names to ignore (the nordvpn instances themselves —
// they all share the fixed NordLynx range).
function local_subnets(uci, skip) {
	let out = [];
	let seen = {};
	let add = function(name, addr, len) {
		if (name == 'loopback' || skip[name] || addr == null || len == null || len < 1 || len > 30)
			return;
		let ip = ip4_to_int(addr);
		if (ip == null)
			return;
		let mask = (0xffffffff << (32 - len)) & 0xffffffff;
		let target = sprintf('%s/%d', int_to_ip4(ip & mask), len);
		if (target == '10.5.0.0/16' || seen[target])
			return;
		seen[target] = 1;
		push(out, { target: target, iface: name });
	};

	uci.foreach('network', 'interface', function(sec) {
		if (sec.proto != 'static')
			return;
		let addrs = sec.ipaddr;
		if (type(addrs) != 'array')
			addrs = (addrs != null) ? [ addrs ] : [];
		for (let a in addrs) {
			let m = match('' + a, /^([0-9.]+)\/([0-9]+)$/);
			if (m)
				add(sec['.name'], m[1], int(m[2]));
			else if (sec.netmask)
				add(sec['.name'], '' + a, mask_len(sec.netmask));
		}
	});

	// User static routes in the main table (e.g. a subnet behind their own
	// WireGuard link, where the interface address is a /32) are local
	// destinations too — mirror them.
	uci.foreach('network', 'route', function(sec) {
		if (sec[MARK] == '1' || (sec.table != null && sec.table != ''))
			return;
		let c = route_cidr(sec);
		if (c) {
			let m = match(c, /^([0-9.]+)\/([0-9]+)$/);
			add(sec.interface, m[1], int(m[2]));
		}
	});

	// Subnets routed through the user's OWN WireGuard links (peer allowed_ips
	// with route_allowed_ips) — e.g. services behind a personal wg tunnel.
	uci.foreach('network', null, function(sec) {
		if (!sec['.type'] || index(sec['.type'], 'wireguard_') != 0)
			return;
		if (sec.route_allowed_ips != '1' || sec.interface == null || skip[sec.interface])
			return;
		let ips = sec.allowed_ips;
		if (type(ips) != 'array')
			ips = (ips != null) ? [ ips ] : [];
		for (let a in ips) {
			let m = match('' + a, /^([0-9.]+)\/([0-9]+)$/);
			if (m)
				add(sec.interface, m[1], int(m[2]));
		}
	});

	let d = run([ 'ubus', 'call', 'network.interface', 'dump' ]);
	if (d.code == 0) {
		let data;
		try {
			data = json(d.stdout);
		} catch (e) {
			data = null;
		}
		let dev2iface = {};
		for (let ifc in ((data ? data.interface : null) || [])) {
			if (ifc.l3_device)
				dev2iface[ifc.l3_device] = ifc.interface;
			for (let a in (ifc['ipv4-address'] || []))
				add(ifc.interface, a.address, a.mask);
		}

		// Pinned exception routes and foreign connected subnets in the main
		// table, any prefix length. netifd/scripted routes carry proto static,
		// hand-added `ip route add` ones proto boot, and connected subnets of
		// interfaces netifd does not manage itself (docker bridges etc.) carry
		// proto kernel — mirror all three so steered clients keep every local
		// or pinned destination. Only on-device (needs ubus for the mapping).
		let pin_lines = [];
		for (let proto in [ 'static', 'boot', 'kernel' ]) {
			let rt = run([ 'ip', '-4', 'route', 'show', 'table', 'main', 'proto', proto ]);
			if (rt.code == 0)
				for (let l in split(trim(rt.stdout || ''), '\n'))
					push(pin_lines, l);
		}
		{
			for (let line in pin_lines) {
				let m = match(line, /^([0-9.]+(\/[0-9]+)?) +via +([0-9.]+) +dev +([^ ]+)/);
				let target = null, gw = null, dev = null;
				if (m) {
					target = m[1];
					gw = m[3];
					dev = m[4];
				} else {
					m = match(line, /^([0-9.]+(\/[0-9]+)?) +dev +([^ ]+)/);
					if (m) {
						target = m[1];
						dev = m[3];
					}
				}
				if (!target || target == 'default' || !dev2iface[dev] || skip[dev2iface[dev]])
					continue;
				if (index(target, '/') < 0)
					target += '/32';
				if (seen[target])
					continue;
				seen[target] = 1;
				push(out, { target: target, iface: dev2iface[dev], gateway: gw });
			}
		}
	}
	return out;
}

// Reconcile the stamped bypass routes of one instance with the desired subnet
// list. Subnets already covered by an unstamped user route in the same table
// are left to the user's route. Returns true on change.
function reconcile_local_routes(uci, iface, table, desired) {
	let changed = false;
	let have = [];
	let covered = {};
	uci.foreach('network', 'route', function(sec) {
		if (sec[MARK] == '1' && sec[ROLE] == 'steer_local' && sec.nordvpn_iface == iface) {
			push(have, { section: sec['.name'], target: sec.target, table: sec.table });
		} else if (sec[MARK] != '1' && sec.table == table) {
			let c = route_cidr(sec);
			if (c)
				covered[c] = true;
		}
	});
	for (let h in have) {
		// A user route for the same subnet wins over ours.
		let keep = (h.table == table) && !covered[h.target];
		if (keep) {
			keep = false;
			for (let d in desired)
				if (d.target == h.target)
					keep = true;
		}
		if (!keep) {
			uci.delete('network', h.section);
			changed = true;
		}
	}
	for (let d in desired) {
		let present = false;
		for (let h in have)
			if (h.target == d.target && h.table == table && !covered[h.target])
				present = true;
		if (covered[d.target] || present)
			continue;
		let sec = uci.add('network', 'route');
		uci.set('network', sec, 'interface', d.iface);
		uci.set('network', sec, 'target', d.target);
		if (d.gateway)
			uci.set('network', sec, 'gateway', d.gateway);
		uci.set('network', sec, 'table', table);
		uci.set('network', sec, MARK, '1');
		uci.set('network', sec, ROLE, 'steer_local');
		uci.set('network', sec, 'nordvpn_iface', iface);
		changed = true;
	}
	return changed;
}

// netifd resolves named routing tables through /etc/iproute2/rt_tables; an
// unregistered name makes ip4table and lookup rules silently inert. Register
// the instance's table with a stamped line (best effort). Numeric tables and
// already-registered names need nothing.
function ensure_rt_table(name) {
	if (_common.full_match(name, /^[0-9]+$/))
		return true;
	let data = readfile(RT_TABLES) || '';
	let used = {};
	for (let line in split(data, '\n')) {
		let m = match(line, /^[ \t]*([0-9]+)[ \t]+([^ \t#]+)/);
		if (!m)
			continue;
		if (m[2] == name)
			return true;
		used[m[1]] = true;
	}
	for (let n = 100; n <= 252; n++) {
		if (used['' + n])
			continue;
		return atomic_write(RT_TABLES,
			data + (length(data) && substr(data, -1) != '\n' ? '\n' : '') +
			sprintf('%d\t%s # %s\n', n, name, MARK));
	}
	return false;
}

// Numeric id of a routing table (a number, a builtin name, or a name
// registered in rt_tables), or null when it cannot be resolved.
function rt_table_id(name) {
	if (_common.full_match(name, /^[0-9]+$/))
		return int(name);
	let builtin = { main: 254, 'default': 253 };
	if (builtin[name])
		return builtin[name];
	for (let line in split(readfile(RT_TABLES) || '', '\n')) {
		let m = match(line, /^[ \t]*([0-9]+)[ \t]+([^ \t#]+)/);
		if (m && m[2] == name)
			return int(m[1]);
	}
	return null;
}

// Firewall mark ('value/mask') carrying an instance's steered-device packets:
// the table id in the top byte. mwan3 (0x3f00) and pbr (0x00ff0000) use other
// bits. Null when the id does not fit in one byte.
const DEVICE_MARK_MASK = 0xff000000;
function device_mark(table_id) {
	if (type(table_id) != 'int' || table_id < 1 || table_id > 255)
		return null;
	return sprintf('0x%x/0x%x', table_id << 24, DEVICE_MARK_MASK);
}

// Name of the fw4 nft set (and the dnsmasq nftset target) holding the
// resolved addresses of an instance's steered domains.
function domain_set_name(iface) {
	return 'nv_' + iface + '_dom';
}

// Same for the domains an instance excludes from the tunnel.
function bypass_set_name(iface) {
	return 'nv_' + iface + '_byp';
}

// Mark of excluded traffic: the main table's id (254) in the same top byte as
// the steering marks, so one rule sends it to the main table.
const BYPASS_TABLE_ID = 254;

// Logical networks of the (unmanaged) firewall zone named `zone`.
function zone_networks(uci, zone) {
	let nets = [];
	uci.foreach('firewall', 'zone', function(sec) {
		if (sec.name == zone && sec[MARK] != '1') {
			nets = as_list(sec.network);
			return false;
		}
	});
	return nets;
}

// Whether the installed dnsmasq can fill nft sets (dnsmasq-full; the stock
// dnsmasq is built without it). Same test as OpenWrt's dnsmasq init script:
// 'nftset' among the compile-time options ('no-nftset' when absent). Cached
// for a minute, since rpcd asks on every status poll.
let nftset_cache = null;
function nftset_supported() {
	if (nftset_cache && time() - nftset_cache.at < 60)
		return nftset_cache.ok;
	let ok = false;
	let r = run([ 'dnsmasq', '--version' ]);
	if (r.code == 0)
		for (let line in split(r.stdout, '\n'))
			if (index(line, 'Compile time options:') == 0 &&
			    index(line + ' ', ' nftset ') >= 0)
				ok = true;
	nftset_cache = { at: time(), ok: ok };
	return ok;
}

// MAC -> owning instance. A device belongs to at most one tunnel: the first
// enabled instance (list_instances order, 'main' first) that lists it.
function device_owners(uci) {
	let owners = {};
	for (let n in _common.list_instances(uci)) {
		let st = _common.load_settings(uci, n);
		if (!st.enabled)
			continue;
		for (let mac in st.source_devices)
			if (!owners[mac])
				owners[mac] = n;
	}
	return owners;
}

// Remove ONLY a stamped rt_tables line for `name`; user entries are kept.
function drop_rt_table(name) {
	if (name == null || name == '' || _common.full_match(name, /^[0-9]+$/))
		return;
	let data = readfile(RT_TABLES);
	if (!data || index(data, MARK) < 0)
		return;
	let kept = [];
	let changed = false;
	for (let line in split(data, '\n')) {
		let m = match(line, /^[ \t]*[0-9]+[ \t]+([^ \t#]+)[ \t]*#[ ]*nordvpn_managed/);
		if (m && m[1] == name) {
			changed = true;
			continue;
		}
		push(kept, line);
	}
	if (changed)
		atomic_write(RT_TABLES, join('\n', kept));
}

// Is routing table `name` any instance's (effective) table? `skip` names an
// instance to leave out, usually the caller's own.
function table_in_use(uci, name, skip) {
	for (let n in _common.list_instances(uci))
		if (n != skip && _common.load_settings(uci, n).routing_table == name)
			return true;
	return false;
}

// True when the WAN has a default IPv6 route (potential leak path).
function wan_has_ipv6() {
	let r = run([ 'ip', '-6', 'route', 'show', 'default' ]);
	return r.code == 0 && length(trim(r.stdout || '')) > 0;
}

// L3-device MTU of the WAN uplink (the path WireGuard's UDP actually takes to
// the endpoint — NOT the tunnel). Found via the WAN firewall zone's networks so
// an active auto-routing default through the tunnel does not mislead us. Returns
// the smallest MTU across WAN devices, or null when it cannot be determined.
function wan_l3_mtu(uci) {
	let wannets = {};
	uci.foreach('firewall', 'zone', function(sec) {
		if (sec[MARK] == '1')
			return;
		if (sec.masq == '1' || sec.name == 'wan')
			for (let n in as_list(sec.network))
				wannets[n] = 1;
	});
	let d = run([ 'ubus', 'call', 'network.interface', 'dump' ]);
	if (d.code != 0)
		return null;
	let data;
	try {
		data = json(d.stdout);
	} catch (e) {
		return null;
	}
	let best = null;
	for (let ifc in ((data ? data.interface : null) || [])) {
		if (!ifc.up || !ifc.l3_device || !wannets[ifc.interface])
			continue;
		// Never count a WireGuard tunnel as the WAN uplink: it is the path
		// WireGuard's UDP rides ON, not the uplink itself. Counting it creates
		// a feedback loop — setting the recommended tunnel MTU makes the tunnel
		// the smallest "WAN" device, dragging the next recommendation down 80.
		if (ifc.proto == 'wireguard')
			continue;
		let l = run([ 'ip', 'link', 'show', 'dev', ifc.l3_device ]);
		if (l.code != 0)
			continue;
		let m = match(l.stdout || '', /mtu ([0-9]+)/);
		if (m) {
			let v = int(m[1]);
			if (best == null || v < best)
				best = v;
		}
	}
	return best;
}

// Recommended WireGuard interface MTU for a given WAN MTU: subtract 80 (60 bytes
// of real WG/UDP/IPv4 overhead + 20 safety, matching NordLynx's 1420 on a 1500
// path and 1412 on 1492 PPPoE), clamped to [1280 (IPv6 minimum), 1420 (vendor
// maximum)]. Null when the WAN MTU is unknown.
function recommend_mtu(wanmtu) {
	if (type(wanmtu) != 'int' || wanmtu <= 0)
		return null;
	let v = wanmtu - 80;
	if (v < 1280)
		v = 1280;
	if (v > 1420)
		v = 1420;
	return v;
}

// Logical networks a user could steer through an instance: every interface
// section except loopback and WireGuard tunnels.
function available_networks(uci) {
	let out = [];
	uci.foreach('network', 'interface', function(sec) {
		if (sec['.name'] == 'loopback' || sec.proto == 'wireguard')
			return;
		push(out, sec['.name']);
	});
	return out;
}

// Stamped sections of one instance and role in `config` ('network' rule/rule6
// or 'firewall' rule). `key` names the option that identifies each one
// (default 'in', the source network), returned as `net`.
function find_managed_rules(uci, sectype, role, iface, key, config) {
	let out = [];
	uci.foreach(config || 'network', sectype, function(sec) {
		if (sec[MARK] == '1' && sec[ROLE] == role && sec.nordvpn_iface == iface)
			push(out, { section: sec['.name'], net: sec[key || 'in'] });
	});
	return out;
}

// Reconcile stamped rules with the desired list of keys (source networks by
// default; `key`/`config` as for find_managed_rules): delete stamped rules
// whose key is no longer wanted, create missing ones. `mkopts(k)` returns the
// option map for a new rule. Returns true on change.
function reconcile_rules(uci, sectype, role, iface, want_nets, mkopts, key, config) {
	config = config || 'network';
	let changed = false;
	let have = find_managed_rules(uci, sectype, role, iface, key, config);
	for (let r in have) {
		if (index(want_nets, r.net) < 0) {
			uci.delete(config, r.section);
			changed = true;
		}
	}
	for (let net in want_nets) {
		let present = false;
		for (let r in have)
			if (r.net == net)
				present = true;
		if (!present) {
			let sec = uci.add(config, sectype);
			let opts = mkopts(net);
			for (let k in opts)
				uci.set(config, sec, k, opts[k]);
			uci.set(config, sec, MARK, '1');
			uci.set(config, sec, ROLE, role);
			uci.set(config, sec, 'nordvpn_iface', iface);
			changed = true;
		}
	}
	return changed;
}

// Reconcile the one stamped dnsmasq 'ipset' section of an instance and role
// ('domain_dns' for steered domains, 'bypass_dns' for excluded ones) with the
// wanted domain list (empty = remove it). dnsmasq resolves each domain (and
// its subdomains) into the fw4 set `setname`. Returns true on change.
function reconcile_domain_dns(uci, iface, setname, domains, role) {
	role = role || 'domain_dns';
	let have = find_managed_rules(uci, 'ipset', role, iface, 'nordvpn_set', 'dhcp');
	let changed = false;
	for (let i = 0; i < length(have); i++) {
		if (length(domains) == 0 || i > 0) {
			uci.delete('dhcp', have[i].section);
			changed = true;
		}
	}
	if (length(domains) == 0)
		return changed;
	let sec = length(have) ? have[0].section : null;
	if (!sec) {
		sec = uci.add('dhcp', 'ipset');
		uci.set('dhcp', sec, MARK, '1');
		uci.set('dhcp', sec, ROLE, role);
		uci.set('dhcp', sec, 'nordvpn_iface', iface);
		changed = true;
	}
	let want = { nordvpn_set: setname, name: [ setname ], domain: domains,
		table: 'fw4', table_family: 'inet', family: '4' };
	for (let k in want) {
		if (sprintf('%J', uci.get('dhcp', sec, k)) != sprintf('%J', want[k])) {
			uci.set('dhcp', sec, k, want[k]);
			changed = true;
		}
	}
	return changed;
}

// Resolvers the WAN networks hand out (netifd's dns-server, plus any static
// `dns` option), IPv4/IPv6 literals only. `wan_zone` null -> none. Empty
// off-device.
function wan_resolvers(uci, wan_zone) {
	let out = [];
	for (let net in (wan_zone ? zone_networks(uci, wan_zone) : [])) {
		if (!_common.validate_interface(net))
			continue;
		let list = [];
		let r = run([ 'ubus', 'call', 'network.interface.' + net, 'status' ], true);
		if (r.code == 0) {
			try {
				let st = json(r.stdout);
				if (st && type(st['dns-server']) == 'array')
					list = st['dns-server'];
			} catch (e) {}
		}
		for (let d in as_list(uci.get('network', net, 'dns')))
			push(list, d);
		for (let ip in list)
			if (type(ip) == 'string' && (_common.validate_ipv4(ip) || match(ip, /^[0-9A-Fa-f:]+$/) && index(ip, ':') >= 0) &&
			    index(out, ip) < 0)
				push(out, ip);
	}
	return out;
}

// DNS lock on the (first) dnsmasq instance: with `want` a server list,
// dnsmasq stops reading the resolv file netifd writes (it merges the WAN's
// resolvers with the tunnel's, and dnsmasq keeps probing all of them, so
// lookups would leak to the WAN's resolver) and forwards only to `want`.
// With `want` null the lock is released and the previous state restored.
// Only the servers we added are touched; the user's own stay. One instance
// holds the lock (nordvpn_dns_lock). Returns { changed, notes }.
function reconcile_dns_lock(uci, iface, want) {
	let notes = [];
	let sec = null;
	uci.foreach('dhcp', 'dnsmasq', function(x) {
		sec = x['.name'];
		return false;
	});
	if (!sec) {
		if (want)
			push(notes, 'no dnsmasq instance found; DNS not locked to the VPN');
		return { changed: false, notes: notes };
	}
	let holder = uci.get('dhcp', sec, 'nordvpn_dns_lock');
	if (holder && holder != iface) {
		if (want)
			push(notes, 'DNS is already locked by ' + holder);
		return { changed: false, notes: notes };
	}
	let ours = as_list(uci.get('dhcp', sec, 'nordvpn_dns_servers'));
	let cur = as_list(uci.get('dhcp', sec, 'server'));
	let theirs = filter(cur, (x) => index(ours, x) < 0);
	let changed = false;
	let set_list = function(opt, list) {
		if (sprintf('%J', as_list(uci.get('dhcp', sec, opt))) == sprintf('%J', list))
			return;
		if (length(list))
			uci.set('dhcp', sec, opt, list);
		else
			uci.delete('dhcp', sec, opt);
		changed = true;
	};
	if (want) {
		if (!holder) {
			uci.set('dhcp', sec, 'nordvpn_noresolv_prev', uci.get('dhcp', sec, 'noresolv') || '');
			uci.set('dhcp', sec, 'nordvpn_dns_lock', iface);
			changed = true;
		}
		if (uci.get('dhcp', sec, 'noresolv') != '1') {
			uci.set('dhcp', sec, 'noresolv', '1');
			changed = true;
		}
		set_list('server', [ ...theirs, ...want ]);
		set_list('nordvpn_dns_servers', want);
		let plain = filter(theirs, (x) => substr(x, 0, 1) != '/');
		if (length(plain))
			push(notes, 'dnsmasq also forwards to your own servers (' + join(', ', plain) + '); those lookups bypass the VPN');
	} else if (holder == iface) {
		let prev = uci.get('dhcp', sec, 'nordvpn_noresolv_prev');
		if (prev == null || prev == '')
			uci.delete('dhcp', sec, 'noresolv');
		else
			uci.set('dhcp', sec, 'noresolv', prev);
		set_list('server', theirs);
		uci.delete('dhcp', sec, 'nordvpn_dns_servers');
		uci.delete('dhcp', sec, 'nordvpn_noresolv_prev');
		uci.delete('dhcp', sec, 'nordvpn_dns_lock');
		changed = true;
	}
	return { changed: changed, notes: notes };
}

// Reconcile stamped firewall forwardings (into the instance zone) with the
// desired source-zone list. Returns true on change.
function reconcile_forwardings(uci, iface, dest_zone, want_srcs) {
	let changed = false;
	let have = [];
	uci.foreach('firewall', 'forwarding', function(sec) {
		if (sec[MARK] == '1' && sec[ROLE] == 'forwarding' && sec.nordvpn_iface == iface)
			push(have, { section: sec['.name'], src: sec.src });
	});
	for (let f in have) {
		if (index(want_srcs, f.src) < 0) {
			uci.delete('firewall', f.section);
			changed = true;
		}
	}
	for (let src in want_srcs) {
		let present = false;
		for (let f in have)
			if (f.src == src)
				present = true;
		if (!present) {
			let sec = uci.add('firewall', 'forwarding');
			uci.set('firewall', sec, 'src', src);
			uci.set('firewall', sec, 'dest', dest_zone);
			uci.set('firewall', sec, MARK, '1');
			uci.set('firewall', sec, ROLE, 'forwarding');
			uci.set('firewall', sec, 'nordvpn_iface', iface);
			changed = true;
		}
	}
	return changed;
}

// Firewall zones of the networks the given MACs are currently seen on (the
// neighbour table mapped through netifd). Empty off-device.
function device_zones(uci, macs) {
	let out = [];
	let r = run([ 'ip', 'neigh', 'show' ]);
	if (r.code != 0)
		return out;
	let dev2net = _clients.device_networks();
	for (let n in _clients.parse_neigh(r.stdout)) {
		if (index(macs, n.mac) < 0 || !dev2net[n.dev])
			continue;
		let z = find_zone_of(uci, dev2net[n.dev]);
		if (z && !z.managed && index(out, z.name) < 0)
			push(out, z.name);
	}
	return out;
}

// ── Detection (read-only) ────────────────────────────────────────────

// Classify the routing situation for the UI and for enforce(). `runtime`
// enables checks that need external commands (disabled in offline tests).
// Modes: 'manual'  — unstamped user routes/rules reference the interface or
//                    its table, or a table is set without steering: never touch;
//        'auto'    — route everything (auto_routing);
//        'steered' — route the configured source networks via the instance table;
//        'none'    — tunnel only, no managed routing.
function detect(uci, s, runtime) {
	let iface = s.interface;
	let zone = find_zone_of(uci, iface);
	let peer = find_peer(uci, iface);
	let steering = length(s.source_networks || []) > 0 || length(s.source_devices || []) > 0 ||
		length(s.source_domains || []) > 0 || length(s.source_ips || []) > 0;
	// "Route all LAN traffic" already owned by an earlier instance: this one
	// falls back to its steering (or none) and reports who holds it.
	let owner = s.auto_routing ? all_lan_owner(uci, s.name) : null;
	let auto = s.auto_routing && !owner;
	// Exceptions only mean something while traffic is routed at all; with
	// "Route all LAN traffic" they move it onto the steered machinery.
	let exceptions = (auto || steering) &&
		(length(s.bypass_devices || []) > 0 || length(s.bypass_domains || []) > 0);
	// With steering active, extra user routes INSIDE the instance's table are
	// legitimate companions (e.g. a media→LAN route); only routes referencing
	// the interface itself signal a hand-built scheme. Without steering, a
	// table reference is the manual-mode signal it always was.
	let user_routes = count_user_routes(uci, iface, (steering || exceptions) ? '' : s.routing_table);
	// A bare routing_table is NOT manual on its own — only actual user routes or
	// rules (referencing the interface, or living in the instance's table when
	// not steering) are. A hand-built policy scheme always has such routes, so
	// this still detects it; but merely naming a table no longer collapses the
	// panel into the hands-off view, so the table can be used for steered mode.
	let manual = user_routes > 0;

	let wanmtu = runtime ? wan_l3_mtu(uci) : null;
	return {
		mode: manual ? 'manual' : (auto ? 'auto' : (steering ? 'steered' : 'none')),
		all_lan_owner: owner,
		zone: zone ? zone.name : null,
		zone_managed: zone ? zone.managed : false,
		user_routes: user_routes,
		source_networks: s.source_networks || [],
		source_devices: s.source_devices || [],
		source_domains: s.source_domains || [],
		source_ips: s.source_ips || [],
		exceptions: exceptions,
		// 'unsupported' when steered or excluded domains are configured but
		// dnsmasq cannot fill nft sets (needs dnsmasq-full); null when not
		// checked or not needed.
		domain_steering: (runtime && (length(s.source_domains || []) > 0 || length(s.bypass_domains || []) > 0))
			? (nftset_supported() ? 'ok' : 'unsupported') : null,
		route_allowed_ips: peer ? (uci.get('network', peer, 'route_allowed_ips') == '1') : false,
		killswitch: owned_here(uci, 'killswitch', iface, auto) ||
			length(find_managed_rules(uci, 'rule', 'steer_ks', iface)) > 0,
		ipv6_block: owned_here(uci, 'ipv6block', iface, auto) ||
			length(find_managed_rules(uci, 'rule6', 'steer_v6', iface)) > 0,
		wan_zone: find_wan_zone(uci),
		lan_zone: find_lan_zone(uci),
		networks: available_networks(uci),
		ipv6_wan: runtime ? wan_has_ipv6() : null,
		wan_mtu: wanmtu,
		recommended_mtu: recommend_mtu(wanmtu)
	};
}

// ── Enforcement ──────────────────────────────────────────────────────

// Bring the stamped configuration in line with the settings. Creates objects
// only in automatic mode; removes ONLY stamped objects when their toggle (or
// automatic mode itself) is off. Does not commit — the caller owns the
// transaction. `opts.nftset` overrides the dnsmasq nftset capability check
// (tests). Returns { changed_network, changed_firewall, changed_dhcp,
// domains_active, notes }.
function enforce(uci, s, opts) {
	let notes = [];
	let cn = false, cf = false, cd = false;
	let iface = s.interface;
	let det = detect(uci, s, false);
	// A disabled instance releases all managed objects: an explicit Disable
	// means "give me normal networking back" (IPv6 included); the next apply
	// recreates everything. Missing `enabled` (test fixtures) counts as on.
	let active = (s.enabled == null) ? true : !!s.enabled;
	let auto = (det.mode == 'auto') && active;
	let steer = (det.mode == 'steered') && active;
	if (det.all_lan_owner && active)
		push(notes, 'route all LAN traffic is already enabled on instance ' + det.all_lan_owner + '; not applied here');
	let has_table = s.routing_table != null && s.routing_table != '';
	if (steer && !has_table) {
		push(notes, 'steering needs a routing table; set one for this instance');
		steer = false;
	}
	// "Route all LAN traffic" runs as steering of the LAN zone's networks
	// whenever the instance has a routing table. The tunnel's default route
	// then lives in that table (ip4table), which the automatic path, built on
	// the main table, never consults: LAN traffic would silently keep using
	// the WAN. Exceptions need this path too, since its kill switch is
	// prohibit rules, which the earlier exception rule gets past, whereas the
	// automatic kill switch is a LAN→WAN REJECT that would block the excluded
	// devices as well; load_settings() supplies a table for them.
	let all_lan = false;
	if (auto && (has_table || det.exceptions)) {
		let lan_nets = det.lan_zone ? zone_networks(uci, det.lan_zone) : [];
		if (!has_table)
			push(notes, 'exceptions need a routing table; set one for this instance');
		else if (!length(lan_nets))
			push(notes, 'could not determine the LAN networks to route through table ' + s.routing_table);
		else {
			auto = false;
			steer = true;
			all_lan = lan_nets;
		}
	}
	let managed = auto || steer;
	let peer = find_peer(uci, iface);

	// 1. Routes via the tunnel (netifd routes for allowed_ips; they land in the
	//    instance's ip4table when a routing table is set). Stamped on the
	//    interface so a user-set route_allowed_ips is never removed.
	if (managed) {
		// Stamp the interface even before the first peer exists — write_relay
		// propagates the stamp to route_allowed_ips when it creates the peer.
		if (uci.get('network', iface, MARK + '_routing') != '1') {
			uci.set('network', iface, MARK + '_routing', '1');
			cn = true;
		}
		if (peer && uci.get('network', peer, 'route_allowed_ips') != '1') {
			uci.set('network', peer, 'route_allowed_ips', '1');
			cn = true;
		}
	} else if (uci.get('network', iface, MARK + '_routing') == '1') {
		if (peer)
			uci.delete('network', peer, 'route_allowed_ips');
		uci.delete('network', iface, MARK + '_routing');
		cn = true;
		if (det.mode == 'manual')
			push(notes, 'manual routing detected; automatic default route removed');
	}

	// 1b. Steering rules: per source network, a lookup rule into the instance
	//     table, plus prohibit rules that act as kill switch (IPv4, only when
	//     enabled) and IPv6 leak block (the tunnel carries no IPv6). Prohibit
	//     sits between the lookup and the main table, so it only fires when
	//     the tunnel's table cannot serve the traffic.
	let steer_nets = steer ? (all_lan || s.source_networks) : [];
	let table = s.routing_table;
	if (steer) {
		if (!ensure_rt_table(table))
			push(notes, 'could not register routing table ' + table + ' in ' + RT_TABLES);
	} else {
		drop_rt_table(s.routing_table);
		// The implicit table of all-LAN exceptions is named after the
		// interface; release it too once no other instance uses that name.
		if (s.routing_table != iface && !table_in_use(uci, iface, s.name))
			drop_rt_table(iface);
	}
	if (reconcile_rules(uci, 'rule', 'steer_lookup', iface, steer_nets, function(net) {
		return { 'in': net, lookup: table, priority: '20000' };
	}))
		cn = true;
	// Those rules are keyed by network, so a table change must re-point the
	// existing ones, or they keep sending traffic to the old table. The old
	// table's stamped rt_tables line goes once no instance uses it.
	let old_tables = {};
	if (steer)
		uci.foreach('network', 'rule', function(sec) {
			if (sec[MARK] == '1' && sec[ROLE] == 'steer_lookup' && sec.nordvpn_iface == iface &&
			    sec.lookup != table) {
				old_tables[sec.lookup] = true;
				uci.set('network', sec['.name'], 'lookup', table);
				cn = true;
			}
		});
	for (let t in old_tables)
		if (!table_in_use(uci, t))
			drop_rt_table(t);
	if (reconcile_rules(uci, 'rule', 'steer_ks', iface, (steer && s.killswitch) ? steer_nets : [], function(net) {
		return { 'in': net, action: 'prohibit', priority: '21000' };
	}))
		cn = true;
	if (reconcile_rules(uci, 'rule6', 'steer_v6', iface, (steer && s.block_ipv6) ? steer_nets : [], function(net) {
		return { 'in': net, action: 'prohibit', priority: '21000' };
	}))
		cn = true;

	// 1b'. Device steering: fw4 marks each selected MAC's packets (mangle
	//      prerouting) and one mark rule per family sends them into the table,
	//      with the same prohibit rules as networks. Priority 19000 sits above
	//      the network lookups, so a device choice beats a network choice. A
	//      MAC already owned by another instance is left to that instance.
	// All-LAN mode already sends every LAN network through the table; steered
	// devices and domains only mean something in steered mode.
	let steer_devs = [];
	let mark = null;
	if (steer && !all_lan && length(s.source_devices || []) > 0) {
		let owners = device_owners(uci);
		for (let mac in s.source_devices) {
			if (owners[mac] && s.name && owners[mac] != s.name)
				push(notes, 'device ' + mac + ' is already steered by instance ' + owners[mac]);
			else
				push(steer_devs, mac);
		}
		mark = device_mark(rt_table_id(table));
		if (!mark && length(steer_devs)) {
			push(notes, 'device steering needs a routing table with an id of 1-255; ' + table + ' has none');
			steer_devs = [];
		}
		if (!det.lan_zone && length(steer_devs)) {
			push(notes, 'device steering: could not determine the LAN zone');
			steer_devs = [];
		}
	}
	// 1b''. Domain steering: dnsmasq resolves the listed domains into a fw4
	//       nft set, and one MARK rule gives packets to those addresses the
	//       same mark as steered devices — so the device lookup and prohibit
	//       rules below route them (and apply the kill switch) unchanged.
	//       Only LAN-zone traffic is marked: that zone is the one given a
	//       forwarding into the VPN zone below.
	let steer_doms = [];
	if (steer && !all_lan && length(s.source_domains || []) > 0) {
		let supported = (opts && opts.nftset != null) ? !!opts.nftset : nftset_supported();
		if (!mark)
			mark = device_mark(rt_table_id(table));
		if (!supported)
			push(notes, 'domain steering needs dnsmasq with nftset support (dnsmasq-full)');
		else if (!det.lan_zone)
			push(notes, 'domain steering: could not determine the LAN zone');
		else if (!mark)
			push(notes, 'domain steering needs a routing table with an id of 1-255; ' + table + ' has none');
		else
			steer_doms = s.source_domains;
	}
	let setname = domain_set_name(iface);
	// 1b'''''. IP steering: one MARK rule per destination address/network, with
	//       the same mark (and so the same lookup, kill switch and IPv6
	//       block) as steered devices. LAN-zone traffic only, as for domains.
	let steer_ips = [];
	if (steer && !all_lan && length(s.source_ips || []) > 0) {
		if (!mark)
			mark = device_mark(rt_table_id(table));
		if (!det.lan_zone)
			push(notes, 'IP steering: could not determine the LAN zone');
		else if (!mark)
			push(notes, 'IP steering needs a routing table with an id of 1-255; ' + table + ' has none');
		else
			steer_ips = s.source_ips;
	}
	if (reconcile_rules(uci, 'rule', 'ip_mark', iface, steer_ips, function(ip) {
		return { name: 'NordVPN IP ' + ip, src: det.lan_zone, dest: '*', dest_ip: ip, family: 'ipv4',
			proto: 'all', target: 'MARK', set_xmark: mark };
	}, 'dest_ip', 'firewall'))
		cf = true;
	let dom_sets = length(steer_doms) ? [ setname ] : [];
	if (reconcile_rules(uci, 'ipset', 'domain_set', iface, dom_sets, function(n) {
		return { name: n, family: 'ipv4', match: [ 'dest_ip' ] };
	}, 'name', 'firewall'))
		cf = true;
	if (reconcile_rules(uci, 'rule', 'domain_mark', iface, dom_sets, function(n) {
		return { name: 'NordVPN domains ' + iface, src: det.lan_zone, dest: '*', ipset: n, family: 'ipv4',
			proto: 'all', target: 'MARK', set_xmark: mark };
	}, 'ipset', 'firewall'))
		cf = true;
	if (reconcile_domain_dns(uci, iface, setname, steer_doms))
		cd = true;

	let marks = (mark && (length(steer_devs) || length(steer_doms) || length(steer_ips))) ? [ mark ] : [];
	if (reconcile_rules(uci, 'rule', 'device_mark', iface, steer_devs, function(mac) {
		return { name: 'NordVPN device ' + mac, src: det.lan_zone, dest: '*', src_mac: mac, proto: 'all',
			target: 'MARK', set_xmark: mark };
	}, 'src_mac', 'firewall'))
		cf = true;
	// A table change moves the mark: rewrite MARK rules carrying a stale one.
	// (A renamed LAN zone is handled with the zone fix-up further down.)
	if (length(marks))
		uci.foreach('firewall', 'rule', function(sec) {
			if (sec[MARK] != '1' || sec.nordvpn_iface != iface)
				return;
			if ((sec[ROLE] == 'device_mark' || sec[ROLE] == 'domain_mark' || sec[ROLE] == 'ip_mark') && sec.set_xmark != mark) {
				uci.set('firewall', sec['.name'], 'set_xmark', mark);
				cf = true;
			}
		});
	// IPv4 only, like the network lookups: the tunnel carries no IPv6, which
	// the dev_v6 prohibit below blocks instead when block_ipv6 is on.
	if (reconcile_rules(uci, 'rule', 'dev_lookup', iface, marks, function(m) {
		return { mark: m, lookup: table, priority: '19000' };
	}, 'mark'))
		cn = true;
	if (reconcile_rules(uci, 'rule', 'dev_ks', iface, s.killswitch ? marks : [], function(m) {
		return { mark: m, action: 'prohibit', priority: '21000' };
	}, 'mark'))
		cn = true;
	if (reconcile_rules(uci, 'rule6', 'dev_v6', iface, s.block_ipv6 ? marks : [], function(m) {
		return { mark: m, action: 'prohibit', priority: '21000' };
	}, 'mark'))
		cn = true;

	// 1b'''. Exceptions: excluded devices (by MAC) and domains (a dnsmasq-filled
	//        set) get the main table's id as their mark, and one rule per
	//        family sends that mark to the main table at priority 18000,
	//        ahead of every steering lookup (19000, 20000) and prohibit
	//        (21000) rule: excluded traffic skips the tunnel and the kill
	//        switch, and keeps its IPv6.
	let byp_devs = [], byp_doms = [];
	let bmark = device_mark(BYPASS_TABLE_ID);
	if (steer && det.exceptions) {
		if (rt_table_id(table) == BYPASS_TABLE_ID)
			push(notes, 'exceptions need a routing table other than main');
		else {
			byp_devs = s.bypass_devices || [];
			if (length(byp_devs) && !det.lan_zone) {
				push(notes, 'excluded devices: could not determine the LAN zone');
				byp_devs = [];
			}
			if (length(s.bypass_domains || []) > 0) {
				let supported = (opts && opts.nftset != null) ? !!opts.nftset : nftset_supported();
				if (!supported)
					push(notes, 'excluded domains need dnsmasq with nftset support (dnsmasq-full)');
				else if (!det.lan_zone)
					push(notes, 'excluded domains: could not determine the LAN zone');
				else
					byp_doms = s.bypass_domains;
			}
		}
	}
	// fw4 applies MARK rules in config order and the last one wins, so the
	// exceptions must follow every steering MARK rule, or a steered device
	// visiting an excluded domain keeps the tunnel's mark. When a steering
	// rule was added after them, recreate ours at the end.
	let byp_secs = [], late = false;
	uci.foreach('firewall', 'rule', function(sec) {
		if (sec[MARK] != '1')
			return;
		let r = sec[ROLE];
		if ((r == 'bypass_mark' || r == 'bypass_domain_mark') && sec.nordvpn_iface == iface)
			push(byp_secs, sec['.name']);
		else if (length(byp_secs) && (r == 'device_mark' || r == 'domain_mark' || r == 'ip_mark'))
			late = true;
	});
	if (late) {
		for (let n in byp_secs)
			uci.delete('firewall', n);
		cf = true;
	}
	let bset = bypass_set_name(iface);
	let byp_sets = length(byp_doms) ? [ bset ] : [];
	if (reconcile_rules(uci, 'ipset', 'bypass_set', iface, byp_sets, function(n) {
		return { name: n, family: 'ipv4', match: [ 'dest_ip' ] };
	}, 'name', 'firewall'))
		cf = true;
	if (reconcile_rules(uci, 'rule', 'bypass_domain_mark', iface, byp_sets, function(n) {
		return { name: 'NordVPN exceptions ' + iface, src: det.lan_zone, dest: '*', ipset: n, family: 'ipv4',
			proto: 'all', target: 'MARK', set_xmark: bmark };
	}, 'ipset', 'firewall'))
		cf = true;
	if (reconcile_domain_dns(uci, iface, bset, byp_doms, 'bypass_dns'))
		cd = true;
	if (reconcile_rules(uci, 'rule', 'bypass_mark', iface, byp_devs, function(mac) {
		return { name: 'NordVPN exception ' + mac, src: det.lan_zone, dest: '*', src_mac: mac, proto: 'all',
			target: 'MARK', set_xmark: bmark };
	}, 'src_mac', 'firewall'))
		cf = true;
	let bmarks = (length(byp_devs) || length(byp_doms)) ? [ bmark ] : [];
	if (reconcile_rules(uci, 'rule', 'bypass_lookup', iface, bmarks, function(m) {
		return { mark: m, lookup: 'main', priority: '18000' };
	}, 'mark'))
		cn = true;
	if (reconcile_rules(uci, 'rule6', 'bypass_lookup6', iface, bmarks, function(m) {
		return { mark: m, lookup: 'main', priority: '18000' };
	}, 'mark'))
		cn = true;

	// fw4 places a MARK rule by its zones: only 'src <zone>' with 'dest *' lands
	// in mangle_prerouting, ahead of the routing decision these marks feed. A
	// rule without 'dest' is put in mangle_input and only sees traffic to the
	// router itself, which is how older versions wrote them (src '*', no dest):
	// nothing forwarded was ever marked. Marks are applied to LAN-zone traffic,
	// the zone the tunnel forwards from. Correct any rule still in the old shape.
	if (det.lan_zone)
		uci.foreach('firewall', 'rule', function(sec) {
			if (sec[MARK] != '1' || sec.nordvpn_iface != iface || sec.target != 'MARK')
				return;
			if (sec.src != det.lan_zone) {
				uci.set('firewall', sec['.name'], 'src', det.lan_zone);
				cf = true;
			}
			if (sec.dest != '*') {
				uci.set('firewall', sec['.name'], 'dest', '*');
				cf = true;
			}
		});

	// 1c. Bypass routes for local subnets, so the steered default does not
	//     swallow LAN↔VLAN or LAN↔local-tunnel traffic. The nordvpn instances'
	//     own interfaces are excluded (they share the fixed NordLynx range).
	let locals = [];
	if (steer) {
		let skip = {};
		for (let n in _common.list_instances(uci))
			skip[_common.load_settings(uci, n).interface] = true;
		locals = local_subnets(uci, skip);
	}
	if (reconcile_local_routes(uci, iface, table || '', locals))
		cn = true;

	// 2. Firewall zone (named after the interface, one per instance) and
	//    forwardings into it from the source zones: the LAN zone in auto mode,
	//    the zones holding the steered networks in steered mode. Sources
	//    already covered by an unstamped user forwarding are skipped.
	if (managed) {
		if (!det.zone) {
			let clash = false;
			uci.foreach('firewall', 'zone', function(sec) {
				if (sec.name == iface) {
					clash = true;
					return false;
				}
			});
			if (clash) {
				push(notes, 'a firewall zone named ' + iface + ' already exists; add the interface to a zone manually');
			} else {
				let z = uci.add('firewall', 'zone');
				uci.set('firewall', z, 'name', iface);
				uci.set('firewall', z, 'input', 'REJECT');
				uci.set('firewall', z, 'output', 'ACCEPT');
				uci.set('firewall', z, 'forward', 'REJECT');
				uci.set('firewall', z, 'masq', '1');
				uci.set('firewall', z, 'mtu_fix', '1');
				uci.set('firewall', z, 'network', [ iface ]);
				uci.set('firewall', z, MARK, '1');
				uci.set('firewall', z, ROLE, 'zone');
				uci.set('firewall', z, 'nordvpn_iface', iface);
				cf = true;
				det.zone = iface;
			}
		}
		if (det.zone) {
			let want_srcs = [];
			if (auto) {
				if (det.lan_zone)
					push(want_srcs, det.lan_zone);
				else
					push(notes, 'could not determine the LAN zone; add a forwarding to the VPN zone manually');
			} else {
				for (let net in steer_nets) {
					let z = find_zone_of(uci, net);
					if (!z)
						push(notes, 'network ' + net + ' is in no firewall zone; add a forwarding to the VPN zone manually');
					else if (index(want_srcs, z.name) < 0)
						push(want_srcs, z.name);
				}
				// Steered devices: the zones of the networks they were last
				// seen on, and the LAN zone for devices currently offline.
				// Steered domains: any LAN client may resolve them.
				if ((length(steer_doms) || length(steer_ips)) && det.lan_zone && index(want_srcs, det.lan_zone) < 0)
					push(want_srcs, det.lan_zone);
				if (length(steer_devs)) {
					let seen = device_zones(uci, steer_devs);
					if (det.lan_zone)
						push(seen, det.lan_zone);
					for (let zn in seen)
						if (index(want_srcs, zn) < 0)
							push(want_srcs, zn);
				}
			}
			let filtered = [];
			for (let src in want_srcs) {
				let covered = false;
				uci.foreach('firewall', 'forwarding', function(sec) {
					if (sec[MARK] != '1' && sec.dest == det.zone && sec.src == src) {
						covered = true;
						return false;
					}
				});
				if (!covered)
					push(filtered, src);
			}
			if (reconcile_forwardings(uci, iface, det.zone, filtered))
				cf = true;
		}
	} else {
		if (reconcile_forwardings(uci, iface, det.zone || '', []))
			cf = true;
		let z = find_managed(uci, 'zone', 'zone', iface);
		if (z) {
			uci.delete('firewall', z);
			cf = true;
		}
	}

	// 3. Kill switch: our own REJECT rule LAN->WAN. fw4 evaluates traffic rules
	//    before zone forwardings, so the user's forwardings stay untouched.
	// Each instance owns its rule (nordvpn_iface), so applying or deleting
	// another instance never removes it. An unowned rule from an older version
	// is adopted by the instance that wants it, and dropped once no instance
	// routes all LAN traffic any more.
	let want_ks = auto && s.killswitch;
	let ksf = find_owned(uci, 'killswitch', iface);
	let ks = ksf ? ksf.name : null;
	if (ksf && ksf.legacy) {
		if (want_ks) {
			uci.set('firewall', ks, 'nordvpn_iface', iface);
			cf = true;
		} else {
			if (!any_all_lan(uci, s.name)) {
				uci.delete('firewall', ks);
				cf = true;
			}
			ks = null;
		}
	}
	if (want_ks && !ks) {
		if (det.lan_zone && det.wan_zone) {
			let r = uci.add('firewall', 'rule');
			uci.set('firewall', r, 'name', 'NordVPN kill switch');
			uci.set('firewall', r, 'src', det.lan_zone);
			uci.set('firewall', r, 'dest', det.wan_zone);
			uci.set('firewall', r, 'proto', 'all');
			uci.set('firewall', r, 'target', 'REJECT');
			uci.set('firewall', r, MARK, '1');
			uci.set('firewall', r, ROLE, 'killswitch');
			uci.set('firewall', r, 'nordvpn_iface', iface);
			cf = true;
		} else {
			push(notes, 'could not determine the LAN/WAN zones; kill switch not installed');
		}
	} else if (!want_ks && ks) {
		uci.delete('firewall', ks);
		cf = true;
	}

	// 4. IPv6 leak block: same shape, family ipv6 only.
	let want_v6 = auto && s.block_ipv6;
	let v6f = find_owned(uci, 'ipv6block', iface);
	let v6 = v6f ? v6f.name : null;
	if (v6f && v6f.legacy) {
		if (want_v6) {
			uci.set('firewall', v6, 'nordvpn_iface', iface);
			cf = true;
		} else {
			if (!any_all_lan(uci, s.name)) {
				uci.delete('firewall', v6);
				cf = true;
			}
			v6 = null;
		}
	}
	if (want_v6 && !v6) {
		if (det.lan_zone && det.wan_zone) {
			let r = uci.add('firewall', 'rule');
			uci.set('firewall', r, 'name', 'NordVPN IPv6 leak block');
			uci.set('firewall', r, 'family', 'ipv6');
			uci.set('firewall', r, 'src', det.lan_zone);
			uci.set('firewall', r, 'dest', det.wan_zone);
			uci.set('firewall', r, 'proto', 'all');
			uci.set('firewall', r, 'target', 'REJECT');
			uci.set('firewall', r, MARK, '1');
			uci.set('firewall', r, ROLE, 'ipv6block');
			uci.set('firewall', r, 'nordvpn_iface', iface);
			cf = true;
		} else {
			push(notes, 'could not determine the LAN/WAN zones; IPv6 block not installed');
		}
	} else if (!want_v6 && v6) {
		uci.delete('firewall', v6);
		cf = true;
	}

	// 5. DNS override on the interface (stamped, netifd-managed lifecycle). The
	// stamp records the mode, so switching resolvers (standard <-> threat)
	// re-applies instead of being skipped as "already set".
	let mode = (managed && s.vpn_dns && s.vpn_dns != 'off') ? s.vpn_dns : null;
	let stamped = uci.get('network', iface, MARK + '_dns');
	if (mode && VPN_DNS[mode]) {
		if (stamped != mode) {
			uci.set('network', iface, 'dns', split(VPN_DNS[mode], ' '));
			uci.set('network', iface, MARK + '_dns', mode);
			cn = true;
		}
	} else if (stamped != null && stamped != '') {
		uci.delete('network', iface, 'dns');
		uci.delete('network', iface, MARK + '_dns');
		cn = true;
	}

	// 5b. Steered mode keeps the tunnel's routes in the instance table, so the
	//     router's own queries to those resolvers (dnsmasq forwards every
	//     client's lookups to them) would follow the main table out of the WAN,
	//     readable by the ISP. Send them into the instance table. netifd drops
	//     the interface's DNS servers while the tunnel is down, so no prohibit
	//     rule is needed. Keyed by resolver AND table, so a table change
	//     replaces the rules instead of leaving a stale lookup.
	let dns_keys = [];
	if (steer && mode && VPN_DNS[mode])
		for (let ip in split(VPN_DNS[mode], ' '))
			push(dns_keys, ip + '/32 ' + table);
	if (reconcile_rules(uci, 'rule', 'dns_lookup', iface, dns_keys, function(k) {
		let p = split(k, ' ');
		return { dest: p[0], lookup: p[1], priority: '19500', nordvpn_key: k };
	}, 'nordvpn_key'))
		cn = true;

	// 5c. DNS lock for the instance routing all LAN traffic: dnsmasq forwards
	//     only to the NordVPN resolvers (see reconcile_dns_lock), except that
	//     nordvpn.com names keep using the WAN's resolvers, so the router can
	//     still resolve server hostnames to reconnect or rotate while the
	//     tunnel is down. Excluded devices resolve through the VPN as well
	//     (their traffic itself still goes direct).
	let wans = null;
	let wan_dns = function() {
		if (wans == null) {
			wans = (opts && opts.wan_dns != null) ? opts.wan_dns : wan_resolvers(uci, det.wan_zone);
			wans = filter(wans, (ip) => index(split(VPN_DNS[mode], ' '), ip) < 0);
		}
		return wans;
	};
	let lock = null;
	if ((auto || !!all_lan) && mode && VPN_DNS[mode]) {
		wan_dns();
		if (!length(wans))
			push(notes, 'could not find the WAN DNS servers; DNS not locked to the VPN');
		else {
			lock = split(VPN_DNS[mode], ' ');
			for (let ip in wans)
				push(lock, '/nordvpn.com/' + ip);
		}
	}
	let dl = reconcile_dns_lock(uci, iface, lock);
	if (dl.changed)
		cd = true;
	for (let n in dl.notes)
		push(notes, n);
	// With dnsmasq pinned to the NordVPN resolvers, a tunnel that is down
	// would send those queries out of the WAN (the instance table is empty
	// then, so the lookup above falls through to main). Block them instead.
	// In the main-table variant of "Route all LAN" the tunnel's default and
	// the WAN's share that table, so there is no rule to tell them apart.
	let dns_ks = [];
	if (lock && steer)
		for (let ip in split(VPN_DNS[mode], ' '))
			push(dns_ks, ip + '/32');
	if (reconcile_rules(uci, 'rule', 'dns_ks', iface, dns_ks, function(ip) {
		return { dest: ip, action: 'prohibit', priority: '19501' };
	}, 'dest'))
		cn = true;

	// 5d. Excluded devices keep the WAN's DNS while the others use NordVPN's.
	//     dnsmasq cannot pick an upstream per client, so their lookups never
	//     reach it: DHCP hands them the WAN's IPv4 resolvers (option 6, one
	//     tag per MAC), and a DNAT sends any plain DNS they still send
	//     (manual DNS, a lease not yet renewed) to the first of them. The
	//     exception mark then routes it out of the WAN. IPv4 only: a device
	//     asking the router over IPv6 still gets the NordVPN resolvers.
	let byp_dns = [];
	if (length(byp_devs) && mode && VPN_DNS[mode]) {
		byp_dns = filter(wan_dns(), (ip) => _common.validate_ipv4(ip) != null);
		if (!length(byp_dns))
			push(notes, 'excluded devices: no IPv4 WAN DNS server found; they keep using the router\'s DNS');
	}
	let rdevs = length(byp_dns) ? byp_devs : [];
	let dhcp_dns = length(byp_dns) ? [ '6,' + join(',', byp_dns) ] : [];
	if (reconcile_rules(uci, 'redirect', 'bypass_dns_redirect', iface, rdevs, function(mac) {
		let r = { name: 'NordVPN exception DNS ' + mac, src: det.lan_zone, src_mac: mac, proto: 'tcp udp',
			src_dport: '53', dest_ip: byp_dns[0], dest_port: '53', family: 'ipv4', reflection: '0', target: 'DNAT' };
		if (det.wan_zone)
			r.dest = det.wan_zone;
		return r;
	}, 'src_mac', 'firewall'))
		cf = true;
	if (reconcile_rules(uci, 'mac', 'bypass_dhcp_dns', iface, rdevs, function(mac) {
		return { mac: mac, networkid: 'nvx' + replace(mac, /:/g, ''), dhcp_option: dhcp_dns };
	}, 'mac', 'dhcp'))
		cd = true;
	// The WAN's resolvers can change (DHCP on the WAN): follow them.
	if (length(rdevs)) {
		uci.foreach('firewall', 'redirect', function(sec) {
			if (sec[MARK] == '1' && sec[ROLE] == 'bypass_dns_redirect' && sec.nordvpn_iface == iface &&
			    sec.dest_ip != byp_dns[0]) {
				uci.set('firewall', sec['.name'], 'dest_ip', byp_dns[0]);
				cf = true;
			}
		});
		uci.foreach('dhcp', 'mac', function(sec) {
			if (sec[MARK] == '1' && sec[ROLE] == 'bypass_dhcp_dns' && sec.nordvpn_iface == iface &&
			    sprintf('%J', as_list(sec.dhcp_option)) != sprintf('%J', dhcp_dns)) {
				uci.set('dhcp', sec['.name'], 'dhcp_option', dhcp_dns);
				cd = true;
			}
		});
	}

	return { changed_network: cn, changed_firewall: cf, changed_dhcp: cd,
		domains_active: length(steer_doms) > 0 || length(byp_doms) > 0, dns_locked: lock != null, notes: notes };
}

return { detect, enforce, find_wan_zone, find_lan_zone, count_user_routes, recommend_mtu,
	rt_table_id, device_mark, device_owners, all_lan_owner, domain_set_name, bypass_set_name, nftset_supported };
