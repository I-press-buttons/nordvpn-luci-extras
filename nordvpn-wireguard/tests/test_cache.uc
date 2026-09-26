#!/usr/bin/ucode -S
// SPDX-License-Identifier: MIT
// Offline fixture test for the cache normalizer. No network or account needed.
// Run via tests/run.sh (passes the fixture path as the `fixture` global).

'use strict';

import { readfile } from 'fs';
const normalize = require('nordvpn.cache').normalize;

let raw = readfile(fixture);
if (!raw) {
	warn('cannot read fixture: ' + fixture + '\n');
	exit(2);
}

let out = normalize(json(raw));

let ok = true;
function check(label, got, want) {
	if (got != want) {
		ok = false;
		printf('FAIL %s: got %J want %J\n', label, got, want);
	} else {
		printf('ok   %s = %J\n', label, got);
	}
}

// Fixture: 5 servers — 4 WireGuard (1 multihop de-nl, 1 onion nl-onion),
// 1 non-WireGuard (skipped).
check('countries', out.stats.countries, 3);
check('cities', out.stats.cities, 3);
check('gateways', out.stats.gateways, 4);
check('servers_seen', out.stats.servers_seen, 5);

let multihop = 0, onion = 0, single = 0;
for (let c in out.countries)
	for (let ci in c.cities)
		for (let r in ci.relays)
			r.multihop ? multihop++ : (r.onion ? onion++ : single++);
check('multihop_relays', multihop, 1);
check('onion_relays', onion, 1);
check('single_relays', single, 2);

// Countries are sorted alphabetically.
check('first_country', out.countries[0].name, 'Estonia');
check('fixture cache marks group support', out.groups, true);

// Server groups: P2P and Dedicated IP flags come from groups[].identifier;
// the Double VPN / Onion groups classify even without the hostname pattern.
{
	let key = out.countries[0].cities[0].relays[0].public_key;
	let srv = function(host, name, groups) {
		return { hostname: host, station: '192.0.2.50', name: name, load: 20,
			locations: [ { latitude: 50.1, longitude: 8.7,
				country: { name: 'Germany', code: 'DE', city: { name: 'Frankfurt' } } } ],
			technologies: [ { identifier: 'wireguard_udp',
				metadata: [ { name: 'public_key', value: key } ] } ],
			groups: map(groups, function(g) { return { identifier: g, title: g }; }) };
	};
	let g = normalize([
		srv('de507.nordvpn.com', 'Germany #507', [ 'legacy_p2p', 'legacy_standard', 'europe' ]),
		srv('de508.nordvpn.com', 'Germany #508', [ 'legacy_standard' ]),
		srv('de900.nordvpn.com', 'Germany #900', [ 'legacy_dedicated_ip' ]),
		srv('de901.nordvpn.com', 'Germany #901', [ 'legacy_onion_over_vpn' ]),
		srv('de902.nordvpn.com', 'Germany #902', [ 'legacy_double_vpn' ]),
		{ ...srv('de903.nordvpn.com', 'Germany #903', []), groups: 'garbage' }
	]);
	let by = {};
	for (let r in g.countries[0].cities[0].relays)
		by[r.hostname] = r;
	check('p2p flag set', by['de507.nordvpn.com'].p2p, true);
	check('p2p flag clear', by['de508.nordvpn.com'].p2p, false);
	check('dedicated flag set', by['de900.nordvpn.com'].dedicated, true);
	check('dedicated flag clear', by['de507.nordvpn.com'].dedicated, false);
	check('onion from group', by['de901.nordvpn.com'].onion, true);
	check('multihop from group', by['de902.nordvpn.com'].multihop, true);
	check('garbage groups tolerated', by['de903.nordvpn.com'].p2p, false);

	let _c = require('nordvpn.cache');
	let tree = _c.locations_tree(g);
	check('tree counts p2p per country', tree[0].p2p, 1);
	check('tree skips dedicated in single count', tree[0].single, 3);
	let pool = _c.pool_relays(g, [ 'de' ], 'single', 'p2p');
	check('pool p2p only', length(pool), 1);
	check('pool p2p host', pool[0].hostname, 'de507.nordvpn.com');
	check('pool lists dedicated (flagged) for pinning',
		length(filter(_c.pool_relays(g, [ 'de' ], 'single', ''), function(r) { return r.dedicated; })), 1);
	check('pool ignores p2p for multihop', length(_c.pool_relays(g, [ 'de' ], 'multihop', 'p2p')), 1);
}

exit(ok ? 0 : 1);
