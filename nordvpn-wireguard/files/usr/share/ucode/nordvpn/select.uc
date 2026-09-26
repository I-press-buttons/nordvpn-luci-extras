// SPDX-License-Identifier: MIT
// Shared server selection over the normalized cache. Pure and testable; used by
// both the apply path (single pick) and the rotation worker (try many).

'use strict';

import { rand, log } from 'math';
const _common = require('nordvpn.common');
const relay_kind = _common.relay_kind;

// All relays matching country/city/hop_mode. city_code '' means any city.
// hop_mode 'multihop' and 'onion' select exactly that kind; anything else
// selects plain single-hop relays (Onion Over VPN is never picked implicitly).
// server_group 'p2p' narrows single-hop to P2P servers. Dedicated IP servers
// belong to one account each and are never an automatic candidate.
function candidates(cache, country_code, city_code, hop_mode, server_group) {
	let out = [];
	if (!cache || type(cache.countries) != 'array')
		return out;

	let want = (hop_mode == 'multihop' || hop_mode == 'onion') ? hop_mode : 'single';
	let cc = (country_code && country_code != '') ? lc(country_code) : null;
	let p2p_only = (want == 'single' && server_group == 'p2p');

	for (let country in cache.countries) {
		if (cc && lc(country.code) != cc)
			continue;
		for (let city in country.cities) {
			if (city_code && city_code != '' && city.code != city_code)
				continue;
			for (let relay in city.relays) {
				if (relay.dedicated || (p2p_only && !relay.p2p))
					continue;
				if (relay_kind(relay) == want)
					push(out, relay);
			}
		}
	}
	return out;
}

// Union of candidates() over a location set: entries are country codes
// ('de') or city codes ('de-berlin', the country derived from the prefix).
// Deduped by hostname so a city inside a set country appears once.
// Garbage entries contribute nothing.
function location_candidates(cache, locations, hop_mode, server_group) {
	let out = [], seen = {};
	if (type(locations) != 'array')
		return out;
	for (let entry in locations) {
		let list = [];
		if (_common.full_match(entry, /^[A-Za-z]{2}$/))
			list = candidates(cache, entry, '', hop_mode, server_group);
		else if (type(entry) == 'string' && index(entry, '-') > 0)
			list = candidates(cache, split(entry, '-')[0], entry, hop_mode, server_group);
		for (let r in list) {
			if (seen[r.hostname])
				continue;
			seen[r.hostname] = true;
			push(out, r);
		}
	}
	return out;
}

// The instance's candidate set, shared by apply and rotation: a non-empty
// location set wins; otherwise the legacy country/city selection.
function selection_candidates(cache, settings) {
	let loc = settings ? settings.locations : null;
	let grp = settings ? settings.server_group : null;
	if (loc && length(loc) > 0)
		return location_candidates(cache, loc, settings.hop_mode, grp);
	return candidates(cache, settings.country_code, settings.city_code, settings.hop_mode, grp);
}

// Find a specific relay by its gateway hostname.
function by_hostname(cache, hostname) {
	if (!cache || type(cache.countries) != 'array' || !hostname)
		return null;
	for (let country in cache.countries)
		for (let city in country.cities)
			for (let relay in city.relays)
				if (relay.hostname == hostname)
					return relay;
	return null;
}

// Random pick from a list, optionally excluding a hostname (falls back to the
// full list when the exclusion would leave nothing).
function pick(list, exclude_hostname) {
	if (type(list) != 'array' || length(list) == 0)
		return null;
	let pool = list;
	if (exclude_hostname) {
		pool = filter(list, function(r) { return r.hostname != exclude_hostname; });
		if (length(pool) == 0)
			pool = list;
	}
	return pool[rand() % length(pool)];
}

// Uniform random number in (0, 1), never exactly 0 or 1 (log() stays finite).
function unit_rand() {
	return ((rand() % 1000000) + 1) / 1000002.0;
}

function relay_load(r) {
	let l = r ? r.load : null;
	return (type(l) == 'int' && l >= 0 && l <= 100) ? l : 50;
}

// Order a candidate list for trying, by selection strategy (in a copy):
//  - 'least_load': ascending server load, ties broken at random;
//  - 'random':     a uniform shuffle (the historic behaviour);
//  - 'balanced' (default): a shuffle weighted by (101 - load), so lightly
//    loaded servers are usually tried first while independent instances and
//    routers still spread out instead of all landing on the one emptiest
//    server (Efraimidis–Spirakis: key = log(u) / w, largest first).
// Relays without a usable load count as 50. Pure/testable.
function order_candidates(list, strategy) {
	if (type(list) != 'array')
		return [];
	let deco = [];
	for (let r in list) {
		let u = unit_rand();
		let k;
		if (strategy == 'random')
			k = u;
		else if (strategy == 'least_load')
			k = -relay_load(r) * 2 - u;   // load dominates; u breaks ties
		else
			k = log(u) / (101 - relay_load(r));
		push(deco, { k: k, r: r });
	}
	sort(deco, function(a, b) { return (a.k > b.k) ? -1 : (a.k < b.k) ? 1 : 0; });
	return map(deco, function(d) { return d.r; });
}

return { candidates, location_candidates, selection_candidates, by_hostname, pick, order_candidates };
