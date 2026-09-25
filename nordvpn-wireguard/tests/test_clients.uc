#!/usr/bin/ucode -S
// SPDX-License-Identifier: MIT
// LAN client discovery for per-device steering: the dnsmasq lease, neighbour
// table and static-host parsers and their merge. Pure functions only — no
// device, network or real uci needed.

'use strict';

import { cursor } from 'uci';
const _clients = require('nordvpn.clients');

let fails = 0;
function ok(l, c) { if (c) printf('ok   %s\n', l); else { fails++; printf('FAIL %s\n', l); } }
function eq(l, g, w) {
	let gs = sprintf('%J', g), ws = sprintf('%J', w);
	ok(l, gs == ws);
	if (gs != ws)
		printf('       got:  %s\n       want: %s\n', gs, ws);
}

// 1. dnsmasq lease file
{
	let leases = _clients.parse_leases(
		'1767225600 AA:BB:CC:DD:EE:01 192.168.1.20 Laptop 01:aa:bb:cc:dd:ee:01\n' +
		'1767225600 aa:bb:cc:dd:ee:02 192.168.1.21 * *\n' +
		'1767225600 aa:bb:cc:dd:ee:03 192.168.1.22 <img/src=x/onerror=alert(1)> *\n' +
		'garbage line\n' +
		'1767225600 not-a-mac 192.168.1.23 x *\n' +
		'1767225600 aa:bb:cc:dd:ee:04 not-an-ip x *\n');
	eq('leases: valid rows only', length(leases), 3);
	eq('leases: MAC normalized, name kept', leases[0], { mac: 'aa:bb:cc:dd:ee:01', ip: '192.168.1.20', name: 'Laptop' });
	eq('leases: * hostname is no name', leases[1].name, null);
	eq('leases: markup stripped from hostname', leases[2].name, 'img/src=x/onerror=alert(1)');
	eq('leases: empty input', _clients.parse_leases(null), []);
}

// 2. ip neigh show
{
	let n = _clients.parse_neigh(
		'192.168.1.20 dev br-lan lladdr aa:bb:cc:dd:ee:01 REACHABLE\n' +
		'192.168.1.30 dev br-lan lladdr aa:bb:cc:dd:ee:05 STALE\n' +
		'192.168.1.31 dev br-lan  FAILED\n' +
		'fe80::1 dev br-lan lladdr aa:bb:cc:dd:ee:01 router REACHABLE\n' +
		'10.0.0.5 dev eth0.2 lladdr aa:bb:cc:dd:ee:06 PERMANENT\n' +
		'10.0.0.6 dev bad;dev lladdr aa:bb:cc:dd:ee:07 REACHABLE\n');
	eq('neigh: entries with a MAC and a sane device', length(n), 4);
	eq('neigh: reachable is online', n[0], { mac: 'aa:bb:cc:dd:ee:01', ip: '192.168.1.20', dev: 'br-lan', online: true });
	eq('neigh: stale counts as online', n[1].online, true);
	eq('neigh: IPv6 neighbour kept', n[2].ip, 'fe80::1');
	eq('neigh: permanent is not online', n[3].online, false);
}

// 3. static DHCP hosts (mac as list or space-separated string)
{
	global.MOCK_UCI = { dhcp: {
		h1: { '.type': 'host', name: 'NAS', mac: 'AA:BB:CC:DD:EE:10', ip: '192.168.1.5' },
		h2: { '.type': 'host', name: 'TV', mac: [ 'aa:bb:cc:dd:ee:11', 'aa:bb:cc:dd:ee:12' ] },
		h3: { '.type': 'host', name: 'Two', mac: 'aa:bb:cc:dd:ee:13 aa:bb:cc:dd:ee:14', ip: 'bogus' },
		d1: { '.type': 'dnsmasq' }
	} };
	let st = _clients.static_hosts(cursor());
	eq('static: one entry per MAC', length(st), 5);
	eq('static: first host', st[0], { mac: 'aa:bb:cc:dd:ee:10', ip: '192.168.1.5', name: 'NAS' });
	eq('static: invalid ip dropped', st[3].ip, null);
}

// 4. merge by MAC
{
	let m = _clients.merge(
		[ { mac: 'aa:bb:cc:dd:ee:01', ip: '192.168.1.20', name: 'laptop' },
		  { mac: 'aa:bb:cc:dd:ee:02', ip: '192.168.1.21', name: null } ],
		[ { mac: 'aa:bb:cc:dd:ee:01', ip: '192.168.1.20', name: 'Work Laptop' } ],
		[ { mac: 'aa:bb:cc:dd:ee:01', ip: 'fe80::1', dev: 'br-lan', online: true },
		  { mac: 'aa:bb:cc:dd:ee:05', ip: '192.168.1.30', dev: 'br-guest', online: false } ],
		{ 'br-lan': 'lan', 'br-guest': 'guest' });
	eq('merge: one entry per MAC', length(m), 3);
	eq('merge: static name wins, IPs unioned, network + online from neigh', m[0],
		{ mac: 'aa:bb:cc:dd:ee:01', name: 'Work Laptop', ips: [ '192.168.1.20', 'fe80::1' ],
		  network: 'lan', online: true, static: true });
	eq('merge: unnamed clients sort after named ones', map(m, (c) => c.mac),
		[ 'aa:bb:cc:dd:ee:01', 'aa:bb:cc:dd:ee:02', 'aa:bb:cc:dd:ee:05' ]);
	eq('merge: offline neighbour still gets its network', m[2].network, 'guest');
}

printf('\n%s\n', fails ? ('FAILURES: ' + fails) : 'ALL CLIENT TESTS PASSED');
exit(fails ? 1 : 0);
