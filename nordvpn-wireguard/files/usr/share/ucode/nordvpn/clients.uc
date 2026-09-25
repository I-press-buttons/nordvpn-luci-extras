// SPDX-License-Identifier: MIT
// LAN client discovery for per-device steering. Merges the dnsmasq lease file,
// static DHCP hosts and the kernel neighbour table into one list keyed by MAC.
// The parsers are pure (text/uci in, list out) so they are testable offline;
// clients() only adds the file/command plumbing. Read-only: nothing here
// changes router state.

'use strict';

import { readfile } from 'fs';
const _common = require('nordvpn.common');
const validate_mac = _common.validate_mac,
      clean_label = _common.clean_label,
      full_match = _common.full_match,
      run = _common.run;

const DEFAULT_LEASEFILE = '/tmp/dhcp.leases';
const MAX_CLIENTS = 1024;

// Plain IPv4/IPv6 literal (charset + shape check; no zone ids).
function valid_ip(a) {
	if (type(a) != 'string' || length(a) < 2 || length(a) > 45)
		return null;
	if (full_match(a, /^[0-9]{1,3}([.][0-9]{1,3}){3}$/) || full_match(a, /^[0-9a-fA-F:]+$/))
		return lc(a);
	return null;
}

// dnsmasq lease file: "<expiry> <mac> <ip> <hostname|*> <client-id|*>".
// Returns [ { mac, ip, name } ].
function parse_leases(text) {
	let out = [];
	for (let line in split(text || '', '\n')) {
		let f = split(trim(line), ' ');
		if (length(f) < 4)
			continue;
		let mac = validate_mac(f[1]), ip = valid_ip(f[2]);
		if (!mac || !ip)
			continue;
		push(out, { mac: mac, ip: ip, name: (f[3] != '*') ? clean_label(f[3], null) : null });
	}
	return out;
}

// `ip neigh show` lines: "<ip> dev <dev> lladdr <mac> [router] <STATE>".
// Entries without a link-layer address (INCOMPLETE/FAILED) carry no MAC and are
// skipped. Returns [ { mac, ip, dev, online } ].
function parse_neigh(text) {
	let out = [];
	for (let line in split(text || '', '\n')) {
		let f = split(trim(line), ' ');
		let ip = valid_ip(f[0]), dev = null, mac = null;
		for (let i = 1; i < length(f) - 1; i++) {
			if (f[i] == 'dev')
				dev = f[i + 1];
			else if (f[i] == 'lladdr')
				mac = validate_mac(f[i + 1]);
		}
		if (!ip || !mac || !full_match(dev, /^[A-Za-z0-9._@-]{1,15}$/))
			continue;
		let state = f[length(f) - 1];
		push(out, { mac: mac, ip: ip, dev: dev,
			online: (state == 'REACHABLE' || state == 'DELAY' || state == 'PROBE' || state == 'STALE') });
	}
	return out;
}

// Static DHCP hosts (`config host` in /etc/config/dhcp; `mac` may be a list or
// a space-separated string). Returns [ { mac, ip, name } ].
function static_hosts(uci) {
	let out = [];
	uci.foreach('dhcp', 'host', function(sec) {
		let macs = sec.mac;
		if (type(macs) == 'string')
			macs = split(trim(macs), ' ');
		if (type(macs) != 'array')
			return;
		for (let m in macs) {
			let mac = validate_mac(m);
			if (mac)
				push(out, { mac: mac, ip: valid_ip(sec.ip), name: clean_label(sec.name, null) });
		}
	});
	return out;
}

// Merge the three sources into [ { mac, name, ips, network, online, static } ]
// sorted by name (then MAC). `dev2net` maps an L3 device to its logical
// network. Pure: exported for tests.
function merge(leases, statics, neigh, dev2net) {
	let by = {}, order = [];
	let get = function(mac) {
		if (!by[mac]) {
			by[mac] = { mac: mac, name: null, ips: [], network: null, online: false, static: false };
			push(order, mac);
		}
		return by[mac];
	};
	let add_ip = function(c, ip) {
		if (ip && index(c.ips, ip) < 0)
			push(c.ips, ip);
	};
	for (let s in statics) {
		let c = get(s.mac);
		c.static = true;
		c.name = c.name || s.name;
		add_ip(c, s.ip);
	}
	for (let l in leases) {
		let c = get(l.mac);
		c.name = c.name || l.name;
		add_ip(c, l.ip);
	}
	for (let n in neigh) {
		let c = get(n.mac);
		add_ip(c, n.ip);
		if (n.online)
			c.online = true;
		if (!c.network && dev2net && dev2net[n.dev])
			c.network = dev2net[n.dev];
	}
	let out = [];
	for (let mac in order)
		push(out, by[mac]);
	sort(out, function(a, b) {
		let x = lc(a.name || '~' + a.mac), y = lc(b.name || '~' + b.mac);
		return (x < y) ? -1 : (x > y) ? 1 : 0;
	});
	if (length(out) > MAX_CLIENTS)
		out = slice(out, 0, MAX_CLIENTS);
	return out;
}

// L3 device -> logical network name, from netifd's runtime state.
function device_networks() {
	let map = {};
	let d = run([ 'ubus', 'call', 'network.interface', 'dump' ]);
	if (d.code != 0)
		return map;
	let data;
	try {
		data = json(d.stdout);
	} catch (e) {
		return map;
	}
	for (let ifc in ((data ? data.interface : null) || []))
		if (ifc.l3_device && ifc.interface && !map[ifc.l3_device])
			map[ifc.l3_device] = ifc.interface;
	return map;
}

// All known LAN clients, merged by MAC.
function clients(uci) {
	let lf = null;
	uci.foreach('dhcp', 'dnsmasq', function(sec) {
		if (lf == null && type(sec.leasefile) == 'string' && substr(sec.leasefile, 0, 1) == '/')
			lf = sec.leasefile;
	});
	let leases = parse_leases(readfile(lf || DEFAULT_LEASEFILE) || '');
	let n = run([ 'ip', 'neigh', 'show' ]);
	let neigh = (n.code == 0) ? parse_neigh(n.stdout) : [];
	return merge(leases, static_hosts(uci), neigh, device_networks());
}

return { valid_ip, parse_leases, parse_neigh, static_hosts, merge, device_networks, clients };
