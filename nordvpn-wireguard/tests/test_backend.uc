#!/usr/bin/ucode -S
// SPDX-License-Identifier: MIT
// Offline tests for credential handling, selection, apply and status.
// Uses the mock 'uci'/'ubus' modules (forced ahead on the module search path).
// Globals `fixture` and `KEY` are supplied by run.sh.

'use strict';

import { readfile, writefile, unlink, mkdir, popen, pipe } from 'fs';
const _cache = require('nordvpn.cache');
const normalize = _cache.normalize, write_cache = _cache.write_cache;
const _select = require('nordvpn.select');
const candidates = _select.candidates, by_hostname = _select.by_hostname, pick = _select.pick,
      location_candidates = _select.location_candidates,
      selection_candidates = _select.selection_candidates,
      order_candidates = _select.order_candidates;
const parse_credentials = require('nordvpn.api').parse_credentials;
const write_relay = require('nordvpn.apply').write_relay;
const _apply = require('nordvpn.apply');
const _cmn = require('nordvpn.common');
const load_settings = _cmn.load_settings, list_instances = _cmn.list_instances;
const status = require('nordvpn.status').status;
const _rotate = require('nordvpn.rotate');
const shuffle = _rotate.shuffle, plan_candidates = _rotate.plan_candidates,
      current_key = _rotate.current_key;
const _service = require('nordvpn.service');
const should_refresh = _service.should_refresh, should_rotate = _service.should_rotate,
      next_rotation = _service.next_rotation, should_recover = _service.should_recover,
      watchdog_update = _service.watchdog_update,
      watchdog_result_update = _service.watchdog_result_update;
const _routing = require('nordvpn.routing');
const detect_routing = _routing.detect, enforce_routing = _routing.enforce,
      recommend_mtu = _routing.recommend_mtu;
import { cursor } from 'uci';

let fails = 0;
function ok(l, c) { if (c) printf('ok   %s\n', l); else { fails++; printf('FAIL %s\n', l); } }
function eq(l, g, w) { ok(l, sprintf('%J', g) == sprintf('%J', w)); }

// 1. Credential fd-passing: the token reaches the child ONLY through the pipe,
//    never via argv. Prove a child process can read the config from the fd.
{
	let p = pipe();
	let r = p[0], w = p[1];
	let rfd = r.fileno();
	w.write('user = "token:SECRET_TOKEN_VALUE"\n');
	w.close();
	let proc = popen([ 'cat', '/proc/self/fd/' + rfd ], 'r');
	let out = proc.read('all') || '';
	proc.close();
	r.close();
	ok('credential pipe inherited by child', index(out, 'SECRET_TOKEN_VALUE') >= 0);
	ok('credential config is a curl user= line', index(out, 'user = "token:') == 0);
}

// 2. parse_credentials
{
	eq('parse good key', parse_credentials(sprintf('{"nordlynx_private_key":"%s"}', KEY)).private_key, KEY);
	ok('parse rejects non-json', parse_credentials('not json').error != null);
	ok('parse rejects missing key', parse_credentials('{"x":1}').error != null);
	ok('parse rejects bad key', parse_credentials('{"nordlynx_private_key":"short"}').error != null);

	let pi = require('nordvpn.api').parse_insights;
	eq('insights: full answer', pi('{"ip":"203.0.113.7","city":"Frankfurt","country":"Germany",' +
		'"country_code":"DE","isp":"Example GmbH","isp_asn":64500,"protected":true}'),
		{ ip: '203.0.113.7', protected: true, country: 'Germany', country_code: 'de',
		  city: 'Frankfurt', isp: 'Example GmbH' });
	eq('insights: ipv6', pi('{"ip":"2001:db8::1"}').ip, '2001:db8::1');
	eq('insights: without ip (NordVPN client shape)',
		pi('{"city":"Tallinn","country":"Estonia","country_code":"EE","protected":false}'),
		{ ip: null, protected: false, country: 'Estonia', country_code: 'ee', city: 'Tallinn', isp: null });
	eq('insights: non-json', pi('<html>rate limited</html>'), null);
	eq('insights: empty body', pi(''), null);
	eq('insights: not an object', pi('[1,2]'), null);
	eq('insights: neither ip nor verdict', pi('{"country":"Germany"}'), null);
	eq('insights: ip not a string', pi('{"ip":42}'), null);
	eq('insights: verdict must be a boolean', pi('{"protected":"yes"}'), null);
	eq('insights: markup ip refused', pi('{"ip":"<b>1.2.3.4</b>"}'), null);
	eq('insights: newline ip refused', pi('{"ip":"1.2.3.4\\nx"}'), null);
	let hostile = pi('{"protected":true,"isp":"<img src=x onerror=alert(1)>","country_code":"<b>"}');
	eq('insights: labels stripped of markup, bad code dropped', [ hostile.isp, hostile.country_code ],
		[ 'img src=x onerror=alert(1)', null ]);
}

// Build a cache on disk from the fixture.
let cache = normalize(json(readfile(fixture)));
let cdir = '/tmp/nvtest_' + time();
mkdir(cdir);
let cpath = cdir + '/nordvpn_servers_cache.json';
write_cache(cache, cpath);

// 3. selection
{
	eq('ee single count', length(candidates(cache, 'ee', '', 'single')), 1);
	eq('nl multihop count', length(candidates(cache, 'nl', '', 'multihop')), 1);
	eq('nl single count excludes onion', length(candidates(cache, 'nl', '', 'single')), 0);
	eq('nl onion count', length(candidates(cache, 'nl', '', 'onion')), 1);
	ok('onion relay is nl-onion1', candidates(cache, 'nl', '', 'onion')[0].hostname == 'nl-onion1.nordvpn.com');
	ok('by_hostname hit', by_hostname(cache, 'ee70.nordvpn.com') != null);
	ok('by_hostname miss', by_hostname(cache, 'nope.example') == null);
	let picked = pick(candidates(cache, 'ee', '', 'single'), null);
	ok('pick returns ee relay', picked != null && picked.hostname == 'ee70.nordvpn.com');
}

// 4. apply writes a correct interface + peer transactionally.
{
	global.MOCK_UCI = {
		nordvpn: { main: { '.type': 'settings', interface: 'nordvpn',
			country_code: 'ee', city_code: '', hop_mode: 'single', cache_dir: cdir } },
		network: { nordvpn: { '.type': 'interface', proto: 'wireguard',
			private_key: KEY, vpn_type: 'nordvpn' } }
	};
	let uci = cursor();
	let relay = candidates(cache, 'ee', '', 'single')[0];
	ok('candidate is ee70', relay && relay.hostname == 'ee70.nordvpn.com');
	write_relay(uci, 'nordvpn', relay, load_settings(uci));

	let net = global.MOCK_UCI.network;
	let peerkey = null;
	for (let k in net)
		if (index(net[k]['.type'], 'wireguard_') == 0)
			peerkey = k;
	ok('write_relay created a peer section', peerkey != null);
	let peer = net[peerkey];
	ok('peer public_key set', peer.public_key != null);
	eq('peer endpoint_host', peer.endpoint_host, 'ee70.nordvpn.com');
	ok('peer allowed_ips is a 2-item list', type(peer.allowed_ips) == 'array' && length(peer.allowed_ips) == 2);
	ok('iface addresses is a list', type(net.nordvpn.addresses) == 'array');
	eq('iface address value', net.nordvpn.addresses[0], '10.5.0.2/16');
}

// 5. status states
{
	global.MOCK_UCI = { nordvpn: { main: { '.type': 'settings', interface: 'nordvpn' } }, network: {} };
	global.MOCK_UBUS = {};
	eq('status not_configured', status(cursor()).state, 'not_configured');
	eq('status exposes enabled flag (default off)', status(cursor()).enabled, false);
	eq('status exposes fixed flag (default off)', status(cursor()).fixed, false);

	// Administrative flags surface for the UI's button gating.
	global.MOCK_UCI = { nordvpn: { main: { '.type': 'settings', interface: 'nordvpn',
		enabled: '1', fixed_server: 'ee70.nordvpn.com' } }, network: {} };
	eq('status reflects enabled=1', status(cursor()).enabled, true);
	eq('status reflects a pinned server', status(cursor()).fixed, true);

	global.MOCK_UCI = { nordvpn: { main: { '.type': 'settings', interface: 'nordvpn' } },
		network: { nordvpn: { '.type': 'interface', private_key: KEY } } };
	eq('status disconnected (iface down)', status(cursor()).state, 'disconnected');

	global.MOCK_UBUS = { 'network.interface.nordvpn~status': { up: true, l3_device: 'nordvpn' } };
	eq('status connecting (up, no handshake)', status(cursor()).state, 'connecting');

	// status() runs on every daemon tick once the watchdog is on. A ubus
	// connection leaked per call exhausts ubusd's descriptors within hours and
	// then NOTHING on the router can reach ubus — so assert we close them.
	global.MOCK_UBUS_OPEN = 0;
	for (let i = 0; i < 25; i++)
		status(cursor());
	eq('status leaves no ubus connection open', global.MOCK_UBUS_OPEN, 0);

	// Also when the interface is missing, i.e. the call itself fails.
	global.MOCK_UBUS = {};
	global.MOCK_UBUS_OPEN = 0;
	status(cursor());
	eq('status closes ubus even when the call fails', global.MOCK_UBUS_OPEN, 0);
}

// 6. rotation planning (pure): shuffle + candidate exclusion/limit
{
	let arr = [ 1, 2, 3, 4, 5 ];
	let sh = shuffle(arr);
	eq('shuffle preserves length', length(sh), 5);
	let sum = 0;
	for (let x in sh) sum += x;
	eq('shuffle preserves members', sum, 15);
	eq('shuffle does not mutate input', length(arr), 5);

	// current_key: prefer the stamped gateway, fall back to endpoint_host so an
	// unstamped peer is still excluded and can never be re-reported as a rotation.
	eq('current_key prefers gateway', current_key({ gateway: 'g', endpoint_host: 'e' }), 'g');
	eq('current_key falls back to endpoint_host', current_key({ endpoint_host: 'e' }), 'e');
	eq('current_key null when neither', current_key({}), null);
	eq('current_key null when no peer', current_key(null), null);

	let s_ee = { country_code: 'ee', city_code: '', hop_mode: 'single', max_retries: 10 };
	eq('plan excludes current gateway', length(plan_candidates(cache, s_ee, 'ee70.nordvpn.com', 10)), 0);
	eq('plan excludes via endpoint_host key', length(plan_candidates(cache, s_ee, current_key({ endpoint_host: 'ee70.nordvpn.com' }), 10)), 0);
	eq('plan includes when not excluded', length(plan_candidates(cache, s_ee, null, 10)), 1);

	let s_nl = { country_code: 'nl', city_code: '', hop_mode: 'multihop', max_retries: 10 };
	eq('plan nl multihop', length(plan_candidates(cache, s_nl, null, 10)), 1);
	eq('plan respects limit', length(plan_candidates(cache, s_nl, null, 0) || []) <= 1, true);
}

// 6b. rotation state persistence: the daemon's attempt clock survives a restart
//     and neither writer clobbers the other's timestamp.
{
	unlink('/tmp/nordvpn_rotate_state.json');
	eq('last_attempt 0 when no state', _rotate.last_attempt_ts(), 0);
	_rotate.mark_attempt(1000);
	eq('last_attempt persisted', _rotate.last_attempt_ts(), 1000);
	_rotate.record({ last_success: 2000, server: 'ee70.nordvpn.com' });
	eq('record keeps last_attempt', _rotate.last_attempt_ts(), 1000);
	eq('record merged last_success', _rotate.read_state().last_success, 2000);
	_rotate.mark_attempt(3000);
	eq('mark_attempt keeps last_success', _rotate.read_state().last_success, 2000);
	unlink('/tmp/nordvpn_rotate_state.json');
}

// 6c. unified locations: parsing in load_settings + the shared candidate set.
//     A non-empty `list locations` (country codes and/or cc-city codes) is the
//     instance's location set for BOTH apply and rotation; empty falls back to
//     the legacy country_code/city_code selection.
{
	// load_settings: locations defaults to empty, parses a mixed list, drops garbage.
	global.MOCK_UCI = { nordvpn: { main: { '.type': 'instance', interface: 'nordvpn' } }, network: {} };
	eq('locations default empty', load_settings(cursor()).locations, []);

	global.MOCK_UCI = { nordvpn: { main: { '.type': 'instance', interface: 'nordvpn',
		locations: [ 'DE', 'nl-amsterdam', 'se' ] } }, network: {} };
	eq('locations parses mixed countries and cities', load_settings(cursor()).locations, [ 'de', 'nl-amsterdam', 'se' ]);

	global.MOCK_UCI = { nordvpn: { main: { '.type': 'instance', interface: 'nordvpn',
		locations: [ 'de!bad', '', 'us9999.nordvpn.com', 'us' ] } }, network: {} };
	eq('locations drops invalid entries', load_settings(cursor()).locations, [ 'us' ]);

	global.MOCK_UCI = { nordvpn: { main: { '.type': 'instance', interface: 'nordvpn',
		locations: 'ee' } }, network: {} };
	eq('locations coerces a single string', load_settings(cursor()).locations, [ 'ee' ]);

	// location_candidates: union across countries/cities, dedup by hostname, hop filter.
	eq('set union of two countries', length(location_candidates(cache, [ 'ee', 'us' ], 'single')), 2);
	eq('set country + city of another country', length(location_candidates(cache, [ 'ee', 'nl-amsterdam' ], 'single')), 1);
	eq('set city only, onion', location_candidates(cache, [ 'nl-amsterdam' ], 'onion')[0].hostname, 'nl-onion1.nordvpn.com');
	eq('set dedups a city inside a set country', length(location_candidates(cache, [ 'nl', 'nl-amsterdam' ], 'multihop')), 1);
	eq('set empty list yields nothing', location_candidates(cache, [], 'single'), []);
	eq('set ignores garbage entries', length(location_candidates(cache, [ 'de!bad' ], 'single')), 0);

	// selection_candidates: the shared apply/rotation candidate set.
	let sl = { country_code: 'ee', city_code: '', hop_mode: 'single', locations: [ 'ee', 'us' ] };
	eq('selection prefers the location set', length(selection_candidates(cache, sl)), 2);
	let se = { country_code: 'ee', city_code: '', hop_mode: 'single', locations: [] };
	eq('selection falls back when set empty', length(selection_candidates(cache, se)), 1);
	let sg = { country_code: 'ee', city_code: '', hop_mode: 'single' };
	eq('selection falls back when set missing (legacy)', length(selection_candidates(cache, sg)), 1);

	// plan_candidates goes through the same set and excludes the gateway.
	eq('plan uses the location set', length(plan_candidates(cache, { ...sl, max_retries: 10 }, null, 10)), 2);
	eq('plan set excludes current gateway', plan_candidates(cache, { ...sl, max_retries: 10 }, 'ee70.nordvpn.com', 10)[0].hostname, 'us9999.nordvpn.com');
	eq('plan falls back when set missing', length(plan_candidates(cache, { ...sg, max_retries: 10 }, null, 10)), 1);
}

// 6d. load-aware ordering: the selection strategy decides which candidates are
//     tried first by apply and rotation.
{
	let pool = [ { hostname: 'a', load: 95 }, { hostname: 'b', load: 5 },
		{ hostname: 'c', load: 50 }, { hostname: 'd', load: 5 }, { hostname: 'e' } ];

	let ll = order_candidates(pool, 'least_load');
	eq('least_load puts the lowest loads first', sort([ ll[0].hostname, ll[1].hostname ]), [ 'b', 'd' ]);
	eq('least_load puts the highest load last', ll[4].hostname, 'a');
	eq('least_load treats a missing load as 50', ll[2].hostname == 'c' || ll[2].hostname == 'e', true);
	eq('order keeps every candidate', length(order_candidates(pool, 'random')), 5);
	eq('order does not mutate input', pool[0].hostname, 'a');
	eq('order tolerates garbage', order_candidates(null, 'balanced'), []);

	// balanced: a 5%-load server leads far more often than a 95%-load one,
	// but the busy one is not starved entirely.
	let two = [ { hostname: 'busy', load: 95 }, { hostname: 'idle', load: 5 } ];
	let idle_first = 0, n = 2000;
	for (let i = 0; i < n; i++)
		if (order_candidates(two, 'balanced')[0].hostname == 'idle')
			idle_first++;
	ok('balanced favours the idle server', idle_first > n * 0.85);
	ok('balanced still spreads load', idle_first < n);
	let rnd_first = 0;
	for (let i = 0; i < n; i++)
		if (order_candidates(two, 'random')[0].hostname == 'idle')
			rnd_first++;
	ok('random ignores load', rnd_first > n * 0.35 && rnd_first < n * 0.65);

	// Settings: default balanced, garbage falls back.
	global.MOCK_UCI = { nordvpn: { main: { '.type': 'instance', interface: 'nordvpn' } }, network: {} };
	eq('selection defaults to balanced', load_settings(cursor()).selection, 'balanced');
	global.MOCK_UCI = { nordvpn: { main: { '.type': 'instance', interface: 'nordvpn', selection: 'least_load' } }, network: {} };
	eq('selection parses least_load', load_settings(cursor()).selection, 'least_load');
	global.MOCK_UCI = { nordvpn: { main: { '.type': 'instance', interface: 'nordvpn', selection: 'bogus' } }, network: {} };
	eq('selection rejects garbage', load_settings(cursor()).selection, 'balanced');
}

// 6e. server groups: a P2P instance only picks P2P servers; Dedicated IP
//     servers are never automatic candidates but can still be pinned.
{
	let k = cache.countries[0].cities[0].relays[0].public_key;
	let mk = function(host, groups) {
		return { hostname: host, station: '192.0.2.60', name: 'Germany', load: 10,
			locations: [ { country: { name: 'Germany', code: 'DE', city: { name: 'Berlin' } } } ],
			technologies: [ { identifier: 'wireguard_udp', metadata: [ { name: 'public_key', value: k } ] } ],
			groups: map(groups, function(g) { return { identifier: g }; }) };
	};
	let gc = normalize([ mk('de1.nordvpn.com', [ 'legacy_p2p' ]), mk('de2.nordvpn.com', [ 'legacy_standard' ]),
		mk('de3.nordvpn.com', [ 'legacy_dedicated_ip' ]) ]);
	let hosts = function(l) { return sort(map(l, function(r) { return r.hostname; })); };
	eq('any group excludes dedicated', hosts(candidates(gc, 'de', '', 'single', '')), [ 'de1.nordvpn.com', 'de2.nordvpn.com' ]);
	eq('p2p group narrows', hosts(candidates(gc, 'de', '', 'single', 'p2p')), [ 'de1.nordvpn.com' ]);
	eq('p2p through a location set', hosts(selection_candidates(gc,
		{ locations: [ 'de-berlin' ], hop_mode: 'single', server_group: 'p2p' })), [ 'de1.nordvpn.com' ]);
	eq('p2p via legacy selection', hosts(selection_candidates(gc,
		{ country_code: 'de', city_code: '', hop_mode: 'single', server_group: 'p2p' })), [ 'de1.nordvpn.com' ]);
	eq('dedicated still pinnable', by_hostname(gc, 'de3.nordvpn.com').hostname, 'de3.nordvpn.com');

	global.MOCK_UCI = { nordvpn: { main: { '.type': 'instance', interface: 'nordvpn' } }, network: {} };
	eq('server_group defaults to any', load_settings(cursor()).server_group, '');
	global.MOCK_UCI = { nordvpn: { main: { '.type': 'instance', interface: 'nordvpn', server_group: 'p2p' } }, network: {} };
	eq('server_group parses p2p', load_settings(cursor()).server_group, 'p2p');
	global.MOCK_UCI = { nordvpn: { main: { '.type': 'instance', interface: 'nordvpn', server_group: 'dedicated' } }, network: {} };
	eq('server_group rejects others', load_settings(cursor()).server_group, '');
}

// 7. scheduler decisions (pure)
{
	let s = { cache_refresh_interval: 21600, enabled: true, rotation_enabled: true,
		fixed_server: '', rotation_mode: 'interval', rotation_interval: 360, rotation_time: '04:30' };

	// A real clock, not a small epoch: the old first-tick rule compared
	// now - 0 with the interval and refreshed on every daemon restart.
	let now = 1790000000;
	let refresh_seed = _service.refresh_seed, RETRY = _service.REFRESH_RETRY_BASE;
	ok('refresh without a usable cache', should_refresh(s, 0, now, 0) == true);
	ok('refresh after interval', should_refresh(s, 1000, 1000 + 21600, 0) == true);
	ok('no refresh before interval', should_refresh(s, 1000, 1000 + 100, 0) == false);

	// Restart: the clock comes from the cache's own write time.
	eq('seed: a stale cache refreshes now', refresh_seed(now - 100, true, now), 0);
	eq('seed: a missing cache refreshes now', refresh_seed(null, true, now), 0);
	eq('seed: a fresh cache keeps its write time', refresh_seed(now - 3600, false, now), now - 3600);
	eq('seed: a write time in the future counts as now', refresh_seed(now + 3600, false, now), now);
	ok('no refresh on restart with a fresh cache',
		should_refresh(s, refresh_seed(now - 3600, false, now), now, 0) == false);
	ok('refresh on restart once the interval since the write passed',
		should_refresh(s, refresh_seed(now - 21600, false, now), now, 0) == true);

	// A failed refresh retries sooner, backing off, never beyond the interval.
	ok('retry: not before the first backoff', should_refresh(s, now, now + RETRY - 1, 1) == false);
	ok('retry: after the first backoff', should_refresh(s, now, now + RETRY, 1) == true);
	ok('retry: the backoff doubles', should_refresh(s, now, now + RETRY, 2) == false &&
		should_refresh(s, now, now + 2 * RETRY, 2) == true);
	ok('retry: capped at the interval', should_refresh(s, now, now + 21600, 30) == true &&
		should_refresh(s, now, now + 21599, 30) == false);

	ok('rotate after interval', should_rotate(s, 1000, 1000 + 360 * 60, '12:00') == true);
	ok('no rotate before interval', should_rotate(s, 1000, 1000 + 60, '12:00') == false);
	ok('no rotate when disabled', should_rotate({ ...s, enabled: false }, 0, 999999, '12:00') == false);
	ok('no rotate with fixed server', should_rotate({ ...s, fixed_server: 'ee70.nordvpn.com' }, 0, 999999, '12:00') == false);

	let st = { ...s, rotation_mode: 'time', rotation_time: '04:30' };
	ok('rotate at matching time', should_rotate(st, 0, 999999, '04:30') == true);
	ok('no rotate at other time', should_rotate(st, 0, 999999, '04:31') == false);
}

// 7b. next rotation time (pure)
{
	let s = { enabled: true, rotation_enabled: true, fixed_server: '',
		rotation_mode: 'interval', rotation_interval: 360, rotation_time: '04:30' };
	let now = time();

	eq('next_run from last attempt', next_rotation(s, 1000, 500), 1000 + 360 * 60);
	eq('next_run without history', next_rotation(s, 0, now), now + 360 * 60);
	eq('next_run overdue clamps to now', next_rotation(s, 100, 999999), 999999);
	eq('next_run null when rotation off', next_rotation({ ...s, rotation_enabled: false }, 0, now), null);
	eq('next_run null when master off', next_rotation({ ...s, enabled: false }, 0, now), null);
	eq('next_run null with fixed server', next_rotation({ ...s, fixed_server: 'ee70.nordvpn.com' }, 0, now), null);

	let st = { ...s, rotation_mode: 'time' };
	let nr = next_rotation(st, 0, now);
	ok('time mode is in the future', nr > now);
	ok('time mode within 24h', (nr - now) <= 86400);
	let lt = localtime(nr);
	ok('time mode lands on 04:30:00', lt.hour == 4 && lt.min == 30 && lt.sec == 0);
}

// 7c. watchdog recovery decision (pure). Gate order: master switch + watchdog
//     option, pinned server, unhealthy state, grace, cooldown with backoff.
//     Constants: GRACE=60, COOLDOWN_BASE=120, COOLDOWN_MAX=900.
{
	let s = { enabled: true, watchdog: true, fixed_server: '' };
	let now = 100000;
	let ds = now - 120; // unhealthy for 120s, grace (60s) elapsed

	// Option/master gates.
	ok('recover: watchdog off -> false', should_recover({ ...s, watchdog: false }, 'degraded', ds, 0, 0, now) == false);
	ok('recover: instance disabled -> false', should_recover({ ...s, enabled: false }, 'degraded', ds, 0, 0, now) == false);
	ok('recover: pinned server -> false', should_recover({ ...s, fixed_server: 'ee70.nordvpn.com' }, 'degraded', ds, now - 1000, 0, now) == false);

	// State gate: connecting gets the same grace period as other unhealthy
	// states, so a tunnel that never handshakes eventually recovers.
	ok('recover: connected -> false', should_recover(s, 'connected', 0, 0, 0, now) == false);
	ok('recover: connecting within grace -> false', should_recover(s, 'connecting', now - 30, 0, 0, now) == false);
	ok('recover: connecting past grace -> true', should_recover(s, 'connecting', ds, 0, 0, now) == true);
	ok('recover: not_configured -> false', should_recover(s, 'not_configured', 0, 0, 0, now) == false);

	// Grace gate.
	ok('recover: within grace -> false', should_recover(s, 'degraded', now - 30, 0, 0, now) == false);
	ok('recover: no degraded_since -> false', should_recover(s, 'degraded', 0, 0, 0, now) == false);

	// First attempt once the grace elapsed.
	ok('recover: grace elapsed, never recovered -> true', should_recover(s, 'degraded', ds, 0, 0, now) == true);

	// Cooldown gate with exponential backoff: after one completed failure the
	// next attempt waits 120s; after two failures it waits 240s.
	ok('recover: first retry within base cooldown -> false', should_recover(s, 'degraded', ds, now - 60, 1, now) == false);
	ok('recover: first retry after base cooldown -> true', should_recover(s, 'degraded', ds, now - 120, 1, now) == true);
	ok('recover: second retry before doubled cooldown -> false', should_recover(s, 'degraded', ds, now - 180, 2, now) == false);
	ok('recover: second retry after doubled cooldown -> true', should_recover(s, 'degraded', ds, now - 240, 2, now) == true);
	ok('recover: third retry before 480s cooldown -> false', should_recover(s, 'degraded', ds, now - 300, 3, now) == false);
	ok('recover: third retry after 480s cooldown -> true', should_recover(s, 'degraded', ds, now - 480, 3, now) == true);

	// Backoff clamps to COOLDOWN_MAX.
	ok('recover: clamped backoff not elapsed -> false', should_recover(s, 'degraded', ds, now - 600, 10, now) == false);
	ok('recover: clamped backoff elapsed -> true', should_recover(s, 'degraded', ds, now - 900, 10, now) == true);

	// disconnected is unhealthy too.
	ok('recover: disconnected past grace -> true', should_recover(s, 'disconnected', ds, 0, 0, now) == true);
}

// 7d. watchdog state transitions (pure): the daemon folds status() into the
//     persisted timers once per tick.
{
	let now = 100000;

	// Entering an unhealthy state stamps degraded_since once.
	let u = watchdog_update('degraded', { degraded_since: 0, last_recover: 0, recover_fails: 0 }, now, true);
	eq('watchdog: degraded stamps degraded_since', u.degraded_since, now);
	eq('watchdog: stamp keeps fails', u.recover_fails, 0);

	// Staying unhealthy keeps the original stamp.
	u = watchdog_update('degraded', { degraded_since: now - 90, last_recover: now - 60, recover_fails: 1 }, now, true);
	eq('watchdog: still degraded keeps stamp', u.degraded_since, now - 90);
	eq('watchdog: still degraded keeps last recovery', u.last_recover, now - 60);
	eq('watchdog: still degraded keeps fails', u.recover_fails, 1);

	// connected clears all watchdog timing state.
	u = watchdog_update('connected', { degraded_since: now - 90, last_recover: now - 60, recover_fails: 3 }, now, true);
	eq('watchdog: connected clears timers', [ u.degraded_since, u.last_recover, u.recover_fails ], [ 0, 0, 0 ]);

	// connecting starts the grace window even before the first handshake.
	u = watchdog_update('connecting', { degraded_since: 0, last_recover: 0, recover_fails: 0 }, now, true);
	eq('watchdog: connecting stamps degraded_since', u.degraded_since, now);

	// Inactive and not-configured instances start with a fresh watchdog state
	// when they become eligible again.
	let stale = { degraded_since: now - 90, last_recover: now - 60, recover_fails: 2 };
	u = watchdog_update('disconnected', stale, now, false);
	eq('watchdog: inactive clears timers', [ u.degraded_since, u.last_recover, u.recover_fails ], [ 0, 0, 0 ]);
	u = watchdog_update('not_configured', stale, now, true);
	eq('watchdog: not configured clears timers', [ u.degraded_since, u.last_recover, u.recover_fails ], [ 0, 0, 0 ]);

	// Only a completed failed recovery advances the backoff. A successful
	// worker or one that merely lost the rotation-lock race does not.
	eq('watchdog: failed result increments backoff',
		watchdog_result_update({ error: 'no working server found' }, 0), 1);
	eq('watchdog: skipped no-op increments backoff',
		watchdog_result_update({ skipped: true, reason: 'no other server for the current selection' }, 1), 2);
	eq('watchdog: success keeps backoff',
		watchdog_result_update({ ok: true, server: 'ee70.nordvpn.com' }, 2), 2);
	eq('watchdog: lock skip keeps backoff',
		watchdog_result_update({ skipped: true, reason: 'rotation already running' }, 2), 2);

	// Watchdog keys live in the same per-instance rotate state: a recovery
	// result persists last_recover + an incremented recover_fails without
	// clobbering the rotation clock.
	unlink('/tmp/nordvpn_rotate_state.json');
	_rotate.mark_attempt(1000);
	_rotate.record({ degraded_since: 2000 });
	_rotate.record({ last_recover: 3000, recover_fails: 1 });
	let st8 = _rotate.read_state();
	eq('watchdog: recovery keys persisted', [ st8.last_recover, st8.recover_fails, st8.degraded_since ], [ 3000, 1, 2000 ]);
	eq('watchdog: rotation clock untouched', _rotate.last_attempt_ts(), 1000);
	unlink('/tmp/nordvpn_rotate_state.json');

	// Concurrent record() calls must serialize the read-modify-write cycle.
	// Capture the parent snapshot before the child starts; without a state lock
	// the parent overwrites the child's field from that stale snapshot.
	let state_path = '/tmp/nordvpn_rotate_state.json';
	let state_lock_path = '/tmp/nordvpn_rotate_state.lock';
	let child_script = '/tmp/nordvpn_record_child.uc';
	unlink(state_path);
	unlink(state_lock_path);
	_rotate.record({ base: 1 });
	let parent_snapshot = _rotate.read_state();
	let state_lock = _cmn.acquire_lock(state_lock_path, 30);
	ok('watchdog: test acquired state lock', state_lock != null);
	writefile(child_script,
		"'use strict';\nrequire('nordvpn.rotate').record({ child_writer: 1 });\n");
	let libdir = replace(RPCD, /\/rpcd\/ucode\/nordvpn\.uc$/, '/ucode');
	let mocks = replace(fixture, /\/fixtures\/[^/]+$/, '/mocks');
	// A minimal ucode build (CI, dev hosts) ships fs.so/math.so outside the
	// default search path; forward run.sh's extra -L so the child resolves them.
	let child_argv = [
		getenv('UCODE') || 'ucode',
		'-L', mocks + '/*.uc',
		'-L', libdir + '/*.uc'
	];
	let extra_l = getenv('UCODE_EXTRA_L');
	if (extra_l)
		push(child_argv, '-L', extra_l);
	push(child_argv, '-S', child_script);
	let child = _cmn.open_cmd(child_argv, 'r');
	sleep(100);
	parent_snapshot.parent_writer = 1;
	_cmn.atomic_write(state_path, sprintf('%J', parent_snapshot));
	_cmn.release_lock(state_lock);
	child.read('all');
	child.close();
	let concurrent = _rotate.read_state();
	eq('watchdog: concurrent state writers preserve both updates',
		[ concurrent.parent_writer, concurrent.child_writer ], [ 1, 1 ]);
	unlink(child_script);
	unlink(state_path);
	unlink(state_lock_path);
}

// 8. routing detection and enforcement (mock uci; stamped objects only)
{
	let mks = function(over) {
		let base = { interface: 'nordvpn', routing_table: '', auto_routing: false,
			killswitch: false, block_ipv6: true, use_vpn_dns: false };
		for (let k in over)
			base[k] = over[k];
		return base;
	};
	let mknet = function() {
		return {
			nordvpn: { '.type': 'interface', proto: 'wireguard', private_key: KEY },
			peer: { '.type': 'wireguard_nordvpn', interface: 'nordvpn', endpoint_host: 'x.nordvpn.com' }
		};
	};
	let mkfw = function() {
		return {
			zlan: { '.type': 'zone', name: 'lan', network: [ 'lan' ] },
			zwan: { '.type': 'zone', name: 'wan', masq: '1', network: [ 'wan' ] }
		};
	};

	// A bare custom routing table is NOT manual on its own — only user routes
	// or rules make it manual, so the table can be used for steered mode.
	global.MOCK_UCI = { network: mknet(), firewall: mkfw() };
	let uci = cursor();
	eq('routing: bare table is not manual', detect_routing(uci, mks({ routing_table: 'vpn' }), false).mode, 'none');

	// A user route living in the instance's table (not referencing the iface)
	// still forces manual — that is a real hand-built policy scheme.
	global.MOCK_UCI = { network: mknet(), firewall: mkfw() };
	global.MOCK_UCI.network.tblroute = { '.type': 'route', interface: 'lan', target: '10.0.0.0/8', table: 'vpn' };
	uci = cursor();
	eq('routing: route in the table forces manual', detect_routing(uci, mks({ routing_table: 'vpn' }), false).mode, 'manual');

	// A user route referencing the interface means manual mode, and enforce()
	// must not change a single byte even with every toggle on.
	global.MOCK_UCI = { network: mknet(), firewall: mkfw() };
	global.MOCK_UCI.network.myroute = { '.type': 'route', interface: 'nordvpn', target: '0.0.0.0/0' };
	uci = cursor();
	eq('routing: manual via user route', detect_routing(uci, mks({ auto_routing: true }), false).mode, 'manual');
	let before = sprintf('%J', global.MOCK_UCI);
	let res = enforce_routing(uci, mks({ auto_routing: true, killswitch: true, use_vpn_dns: true }));
	eq('routing: manual scheme untouched', sprintf('%J', global.MOCK_UCI), before);
	eq('routing: manual reports no changes', res.changed_network || res.changed_firewall, false);

	// A section stamped by a SIBLING application is machine-generated, not
	// hand-written: any `*_managed='1'` option marks it, so it must not force
	// manual mode. Live-router case: a protonvpn bypass route referencing the
	// default `nordvpn` interface of instance `main`.
	global.MOCK_UCI = { network: mknet(), firewall: mkfw() };
	global.MOCK_UCI.network.sibling = { '.type': 'route', interface: 'nordvpn',
		target: '10.5.0.0/16', table: 'guest',
		protonvpn_managed: '1', protonvpn_role: 'steer_local', protonvpn_iface: 'protonvpn' };
	uci = cursor();
	let sib = detect_routing(uci, mks({}), false);
	eq('routing: foreign-managed route is not manual', sib.mode, 'none');
	eq('routing: foreign-managed route not counted', sib.user_routes, 0);

	// Same for a foreign-managed route living in the instance's own table
	// while steering is off: still not a user scheme.
	global.MOCK_UCI = { network: mknet(), firewall: mkfw() };
	global.MOCK_UCI.network.sibling = { '.type': 'route', interface: 'lan',
		target: '10.5.0.0/16', table: 'vpn',
		protonvpn_managed: '1', protonvpn_role: 'steer_local', protonvpn_iface: 'protonvpn' };
	uci = cursor();
	sib = detect_routing(uci, mks({ routing_table: 'vpn' }), false);
	eq('routing: foreign-managed table route is not manual', sib.mode, 'none');
	eq('routing: foreign-managed table route not counted', sib.user_routes, 0);

	// A LONE `*_managed` option is not a stamp: real stamps come as a family
	// (`X_managed` + `X_role` + `X_iface`). A hand-written route carrying an
	// unrelated annotation like `qos_managed='1'` (no `qos_role`) is still a
	// user route and must force manual mode.
	global.MOCK_UCI = { network: mknet(), firewall: mkfw() };
	global.MOCK_UCI.network.qosroute = { '.type': 'route', interface: 'nordvpn',
		target: '0.0.0.0/0', qos_managed: '1' };
	uci = cursor();
	let lone = detect_routing(uci, mks({ auto_routing: true }), false);
	eq('routing: lone foreign _managed option stays manual', lone.mode, 'manual');
	eq('routing: lone foreign _managed option still counted', lone.user_routes, 1);

	// The family rule is generic, not a protonvpn exception: another complete
	// family (mullvad_*) must be skipped too.
	global.MOCK_UCI = { network: mknet(), firewall: mkfw() };
	global.MOCK_UCI.network.mvroute = { '.type': 'route', interface: 'nordvpn',
		target: '10.5.0.0/16',
		mullvad_managed: '1', mullvad_role: 'bypass', mullvad_iface: 'mullvad' };
	uci = cursor();
	let mv = detect_routing(uci, mks({ auto_routing: true }), false);
	eq('routing: other complete stamp family is not manual', mv.mode, 'auto');
	eq('routing: other complete stamp family not counted', mv.user_routes, 0);

	// The family must share ONE prefix: `qos_managed` plus `audit_role` /
	// `audit_iface` is not a stamp — the route is hand-written, so manual.
	global.MOCK_UCI = { network: mknet(), firewall: mkfw() };
	global.MOCK_UCI.network.mixed = { '.type': 'route', interface: 'nordvpn',
		target: '0.0.0.0/0',
		qos_managed: '1', audit_role: 'x', audit_iface: 'y' };
	uci = cursor();
	let mixed = detect_routing(uci, mks({ auto_routing: true }), false);
	eq('routing: mixed-prefix options stay manual', mixed.mode, 'manual');
	eq('routing: mixed-prefix options still counted', mixed.user_routes, 1);

	// The family must be COMPLETE: `qos_managed` + `qos_role` without
	// `qos_iface` is not a stamp either — still a user route, still manual.
	global.MOCK_UCI = { network: mknet(), firewall: mkfw() };
	global.MOCK_UCI.network.half = { '.type': 'route', interface: 'nordvpn',
		target: '0.0.0.0/0',
		qos_managed: '1', qos_role: 'bulk' };
	uci = cursor();
	let half = detect_routing(uci, mks({ auto_routing: true }), false);
	eq('routing: incomplete stamp family stays manual', half.mode, 'manual');
	eq('routing: incomplete stamp family still counted', half.user_routes, 1);

	// Each companion must match the prefix INDEPENDENTLY: a same-prefix
	// `qos_role` with a foreign `audit_iface` is not a stamp — still manual.
	global.MOCK_UCI = { network: mknet(), firewall: mkfw() };
	global.MOCK_UCI.network.xiface = { '.type': 'route', interface: 'nordvpn',
		target: '0.0.0.0/0',
		qos_managed: '1', qos_role: 'bulk', audit_iface: 'wan' };
	uci = cursor();
	let xiface = detect_routing(uci, mks({ auto_routing: true }), false);
	eq('routing: foreign-prefix _iface stays manual', xiface.mode, 'manual');
	eq('routing: foreign-prefix _iface still counted', xiface.user_routes, 1);

	// Symmetric case: a same-prefix `qos_iface` with a foreign `audit_role`
	// is not a stamp either — still a user route, still manual.
	global.MOCK_UCI = { network: mknet(), firewall: mkfw() };
	global.MOCK_UCI.network.xrole = { '.type': 'route', interface: 'nordvpn',
		target: '0.0.0.0/0',
		qos_managed: '1', audit_role: 'x', qos_iface: 'wan' };
	uci = cursor();
	let xrole = detect_routing(uci, mks({ auto_routing: true }), false);
	eq('routing: foreign-prefix _role stays manual', xrole.mode, 'manual');
	eq('routing: foreign-prefix _role still counted', xrole.user_routes, 1);

	// Fresh install with automatic routing: zone, forwarding, default route,
	// kill switch and IPv6 block appear; everything stamped.
	global.MOCK_UCI = { network: mknet(), firewall: mkfw() };
	uci = cursor();
	let pristine = sprintf('%J', global.MOCK_UCI);
	res = enforce_routing(uci, mks({ auto_routing: true, killswitch: true }));
	ok('routing: auto changed firewall', res.changed_firewall);
	ok('routing: auto changed network', res.changed_network);
	let det = detect_routing(uci, mks({ auto_routing: true }), false);
	eq('routing: auto mode', det.mode, 'auto');
	eq('routing: zone created', det.zone, 'nordvpn');
	ok('routing: zone is stamped', det.zone_managed);
	ok('routing: default route set', det.route_allowed_ips);
	ok('routing: kill switch installed', det.killswitch);
	ok('routing: ipv6 block installed', det.ipv6_block);

	// Idempotent: a second run changes nothing.
	res = enforce_routing(uci, mks({ auto_routing: true, killswitch: true }));
	eq('routing: idempotent', res.changed_network || res.changed_firewall, false);

	// IP masquerading follows the vpn_masq setting on the VPN zone.
	let zmasq = function() {
		let v = null;
		uci.foreach('firewall', 'zone', function(sec) {
			if (sec.name == 'nordvpn')
				v = sec.masq;
		});
		return v;
	};
	eq('routing: zone masquerades by default', zmasq(), '1');
	res = enforce_routing(uci, mks({ auto_routing: true, killswitch: true, vpn_masq: false }));
	ok('routing: masq off changed firewall', res.changed_firewall);
	eq('routing: zone masq off', zmasq(), '0');
	res = enforce_routing(uci, mks({ auto_routing: true, killswitch: true }));
	eq('routing: zone masq back on', zmasq(), '1');

	// Turning a single toggle off removes exactly that object.
	res = enforce_routing(uci, mks({ auto_routing: true, killswitch: false }));
	ok('routing: kill switch removed', !detect_routing(uci, mks({ auto_routing: true }), false).killswitch);

	// Turning automatic mode off restores the pristine configuration.
	res = enforce_routing(uci, mks({ auto_routing: false }));
	eq('routing: off restores pristine config', sprintf('%J', global.MOCK_UCI), pristine);

	// DNS override: the vpn_dns enum drives the resolver, and switching modes
	// re-applies (the stamp records the mode, not a bare flag).
	global.MOCK_UCI = { network: mknet(), firewall: mkfw() };
	uci = cursor();
	enforce_routing(uci, mks({ auto_routing: true, vpn_dns: 'standard' }));
	eq('dns: standard pair applied', global.MOCK_UCI.network.nordvpn.dns, [ '103.86.96.100', '103.86.99.100' ]);
	eq('dns: stamp records the mode', global.MOCK_UCI.network.nordvpn.nordvpn_managed_dns, 'standard');
	enforce_routing(uci, mks({ auto_routing: true, vpn_dns: 'threat' }));
	eq('dns: switch re-applies threat pair', global.MOCK_UCI.network.nordvpn.dns, [ '103.86.96.96', '103.86.99.99' ]);
	eq('dns: stamp updated to threat', global.MOCK_UCI.network.nordvpn.nordvpn_managed_dns, 'threat');
	enforce_routing(uci, mks({ auto_routing: true, vpn_dns: 'custom', custom_dns: [ '9.9.9.9', '149.112.112.112' ] }));
	eq('dns: custom resolvers applied', global.MOCK_UCI.network.nordvpn.dns, [ '9.9.9.9', '149.112.112.112' ]);
	eq('dns: custom stamp records the list', global.MOCK_UCI.network.nordvpn.nordvpn_managed_dns, 'custom:9.9.9.9,149.112.112.112');
	enforce_routing(uci, mks({ auto_routing: true, vpn_dns: 'custom', custom_dns: [ '1.1.1.1' ] }));
	eq('dns: editing the custom list re-applies', global.MOCK_UCI.network.nordvpn.dns, [ '1.1.1.1' ]);
	enforce_routing(uci, mks({ auto_routing: true, vpn_dns: 'custom', custom_dns: [] }));
	eq('dns: custom with no servers is no override', global.MOCK_UCI.network.nordvpn.dns, null);
	enforce_routing(uci, mks({ auto_routing: true, vpn_dns: 'off' }));
	eq('dns: off removes the override', global.MOCK_UCI.network.nordvpn.dns, null);
	eq('dns: off clears the stamp', global.MOCK_UCI.network.nordvpn.nordvpn_managed_dns, null);
}

// 8b. source-network steering: lookup/prohibit rules, reconciliation, teardown
{
	let ssteer = function(over) {
		let base = { interface: 'nordvpn_rs', routing_table: 'nv_media', auto_routing: false,
			killswitch: false, block_ipv6: true, use_vpn_dns: false, source_networks: [ 'media' ] };
		for (let k in over)
			base[k] = over[k];
		return base;
	};
	global.MOCK_UCI = { network: {
		nordvpn_rs: { '.type': 'interface', proto: 'wireguard', private_key: KEY },
		peer_rs: { '.type': 'wireguard_nordvpn_rs', interface: 'nordvpn_rs', endpoint_host: 'x.nordvpn.com' },
		media: { '.type': 'interface', proto: 'static', ipaddr: '10.9.1.1', netmask: '255.255.255.0' },
		guest: { '.type': 'interface', proto: 'static', ipaddr: '10.9.2.1/24' },
		hetzroute: { '.type': 'route', interface: 'wgx', target: '10.28.0.0', netmask: '255.255.255.0' },
		wgxpeer: { '.type': 'wireguard_wgx', interface: 'wgx', route_allowed_ips: '1',
			allowed_ips: [ '10.29.0.0/24', '0.0.0.0/0' ] }
	}, firewall: {
		zlan: { '.type': 'zone', name: 'lan', network: [ 'lan' ] },
		zwan: { '.type': 'zone', name: 'wan', masq: '1', network: [ 'wan' ] },
		zmedia: { '.type': 'zone', name: 'media', network: [ 'media' ] }
	} };
	let uci = cursor();
	let pris = sprintf('%J', global.MOCK_UCI);

	let res = enforce_routing(uci, ssteer({}));
	ok('steer: changed network', res.changed_network);
	ok('steer: changed firewall', res.changed_firewall);
	let det = detect_routing(uci, ssteer({}), false);
	eq('steer: mode', det.mode, 'steered');
	eq('steer: zone named after iface', det.zone, 'nordvpn_rs');
	ok('steer: default route into table', det.route_allowed_ips);
	ok('steer: v6 block on by default', det.ipv6_block);
	ok('steer: no kill switch by default', !det.killswitch);
	ok('steer: networks listed', index(det.networks, 'media') >= 0 && index(det.networks, 'nordvpn_rs') < 0);

	let lookup = null;
	for (let k in global.MOCK_UCI.network) {
		let sec = global.MOCK_UCI.network[k];
		if (sec['.type'] == 'rule' && sec['in'] == 'media' && sec.nordvpn_managed == '1' && sec.lookup)
			lookup = sec;
	}
	ok('steer: media lookup rule targets the table', lookup != null && lookup.lookup == 'nv_media');

	// Local subnets get stamped bypass routes in the instance table.
	let localr = 0;
	for (let k in global.MOCK_UCI.network) {
		let sec = global.MOCK_UCI.network[k];
		if (sec['.type'] == 'route' && sec.nordvpn_role == 'steer_local' && sec.table == 'nv_media')
			localr++;
	}
	eq('steer: local bypass routes created', localr, 4);
	let mirrored = 0;
	for (let k in global.MOCK_UCI.network) {
		let sec = global.MOCK_UCI.network[k];
		if (sec['.type'] == 'route' && sec.nordvpn_role == 'steer_local' &&
		    (sec.target == '10.28.0.0/24' || sec.target == '10.29.0.0/24'))
			mirrored++;
	}
	eq('steer: user route and wg allowed_ips mirrored', mirrored, 2);

	// An unstamped user route for the same subnet (netmask form) is respected:
	// no duplicate is created and an existing stamped twin is withdrawn.
	global.MOCK_UCI.network.userlocal = { '.type': 'route', interface: 'media',
		target: '10.9.1.0', netmask: '255.255.255.0', table: 'nv_media' };
	enforce_routing(uci, ssteer({}));
	let dup = 0;
	for (let k in global.MOCK_UCI.network) {
		let sec = global.MOCK_UCI.network[k];
		if (sec['.type'] == 'route' && sec.table == 'nv_media' &&
		    (sec.target == '10.9.1.0/24' || sec.target == '10.9.1.0'))
			dup++;
	}
	eq('steer: user companion route not duplicated', dup, 1);
	delete global.MOCK_UCI.network.userlocal;
	enforce_routing(uci, ssteer({}));

	// Reconciliation: switch the steering to another network, kill switch on.
	res = enforce_routing(uci, ssteer({ source_networks: [ 'guest' ], killswitch: true }));
	let media_rules = 0, guest_rules = 0;
	for (let k in global.MOCK_UCI.network) {
		let sec = global.MOCK_UCI.network[k];
		if ((sec['.type'] == 'rule' || sec['.type'] == 'rule6') && sec.nordvpn_managed == '1') {
			if (sec['in'] == 'media') media_rules++;
			if (sec['in'] == 'guest') guest_rules++;
		}
	}
	eq('steer: old network rules removed', media_rules, 0);
	eq('steer: new network gets lookup+ks+v6', guest_rules, 3);

	// A user route inside the instance's table is a companion, not a manual
	// scheme — steering stays; a route referencing the interface forces manual.
	global.MOCK_UCI.network.companion = { '.type': 'route', interface: 'lan',
		target: '10.0.0.0/24', table: 'nv_media' };
	eq('steer: companion route in table keeps steering',
		detect_routing(uci, ssteer({ source_networks: [ 'guest' ] }), false).mode, 'steered');
	global.MOCK_UCI.network.takeover = { '.type': 'route', interface: 'nordvpn_rs', target: '0.0.0.0/0' };
	eq('steer: interface route forces manual',
		detect_routing(uci, ssteer({ source_networks: [ 'guest' ] }), false).mode, 'manual');
	delete global.MOCK_UCI.network.companion;
	delete global.MOCK_UCI.network.takeover;

	// A missing routing table disables steering with a note, creating nothing.
	global.MOCK_UCI = { network: { nordvpn_rs: { '.type': 'interface', proto: 'wireguard' } }, firewall: {} };
	uci = cursor();
	let before = sprintf('%J', global.MOCK_UCI);
	res = enforce_routing(uci, ssteer({ routing_table: '' }));
	eq('steer: no table -> untouched', sprintf('%J', global.MOCK_UCI), before);
	ok('steer: no table -> note', length(res.notes) > 0);

	// Teardown restores the pristine configuration.
	global.MOCK_UCI = { network: {
		nordvpn_rs: { '.type': 'interface', proto: 'wireguard', private_key: KEY },
		peer_rs: { '.type': 'wireguard_nordvpn_rs', interface: 'nordvpn_rs', endpoint_host: 'x.nordvpn.com' },
		media: { '.type': 'interface', proto: 'static', ipaddr: '10.9.1.1', netmask: '255.255.255.0' },
		guest: { '.type': 'interface', proto: 'static', ipaddr: '10.9.2.1/24' }
	}, firewall: {
		zlan: { '.type': 'zone', name: 'lan', network: [ 'lan' ] },
		zwan: { '.type': 'zone', name: 'wan', masq: '1', network: [ 'wan' ] },
		zmedia: { '.type': 'zone', name: 'media', network: [ 'media' ] }
	} };
	uci = cursor();
	pris = sprintf('%J', global.MOCK_UCI);
	enforce_routing(uci, ssteer({ killswitch: true }));
	enforce_routing(uci, ssteer({ source_networks: [] }));
	eq('steer: teardown restores pristine config', sprintf('%J', global.MOCK_UCI), pris);
}

// 9. multi-instance: settings, listing, isolated state, per-instance status
{
	global.MOCK_UCI = { nordvpn: {
		main: { '.type': 'instance', interface: 'nordvpn', country_code: 'de', cache_dir: '/shared' },
		media: { '.type': 'instance', interface: 'nordvpn_rs', country_code: 'rs' }
	}, network: {} };
	let uci = cursor();
	eq('instances listed, main first', list_instances(uci), [ 'main', 'media' ]);
	eq('instance interface', load_settings(uci, 'media').interface, 'nordvpn_rs');
	eq('instance country', load_settings(uci, 'media').country_code, 'rs');
	eq('cache options shared from main', load_settings(uci, 'media').cache_dir, '/shared');
	eq('default instance is main', load_settings(uci).name, 'main');
	eq('invalid instance falls back to main', load_settings(uci, '../evil').name, 'main');

	// A legacy `config settings 'main'` is still listed.
	global.MOCK_UCI = { nordvpn: { main: { '.type': 'settings', interface: 'nordvpn' } }, network: {} };
	uci = cursor();
	eq('legacy settings section listed', list_instances(uci), [ 'main' ]);

	// Rotation state files are isolated per instance ('main' keeps the old path).
	unlink('/tmp/nordvpn_rotate_state.json');
	unlink('/tmp/nordvpn_rotate_state_media.json');
	_rotate.mark_attempt(1000);
	_rotate.mark_attempt(2000, 'media');
	eq('main rotate state isolated', _rotate.last_attempt_ts(), 1000);
	eq('media rotate state isolated', _rotate.last_attempt_ts('media'), 2000);
	unlink('/tmp/nordvpn_rotate_state.json');
	unlink('/tmp/nordvpn_rotate_state_media.json');

	// Status is per instance and reports its name.
	global.MOCK_UCI = { nordvpn: {
		main: { '.type': 'instance', interface: 'nordvpn' },
		media: { '.type': 'instance', interface: 'nordvpn_rs' }
	}, network: { nordvpn_rs: { '.type': 'interface', private_key: KEY } } };
	global.MOCK_UBUS = {};
	uci = cursor();
	eq('status per instance: media configured', status(uci, 'media').configured, true);
	eq('status per instance: main not configured', status(uci, 'main').configured, false);
	eq('status carries the instance name', status(uci, 'media').instance, 'media');
}

// 9b. Hardening: cache_dir and routing_table validation, relay validation.
{
	let vd = _cmn.validate_dir, vt = _cmn.validate_routing_table;
	eq('dir: /tmp allowed', vd('/tmp'), '/tmp');
	eq('dir: user storage allowed', vd('/mnt/usb/nordvpn'), '/mnt/usb/nordvpn');
	eq('dir: /etc/uci-defaults refused (sourced by sh at boot)', vd('/etc/uci-defaults'), null);
	eq('dir: /etc/hotplug.d refused', vd('/etc/hotplug.d/iface'), null);
	eq('dir: traversal refused', vd('/tmp/../etc/uci-defaults'), null);
	eq('dir: trailing slash still refused', vd('/usr/'), null);
	eq('dir: prefix is by path segment', vd('/etcetera'), '/etcetera');
	eq('dir: root refused', vd('/'), null);
	eq('dir: refused dir falls back to /tmp',
		_cmn.cache_file_path({ cache_dir: '/etc/uci-defaults' }), '/tmp/nordvpn_servers_cache.json');
	eq('table: name ok', vt('vpn'), 'vpn');
	eq('table: local refused', vt('local'), null);
	eq('table: 255 refused', vt('255'), null);
	eq('table: newline refused', vt('vpn\n100 evil'), null);

	global.MOCK_UCI = { nordvpn: { main: { '.type': 'instance', routing_table: 'local' } } };
	eq('table: invalid falls back to main', load_settings(cursor()).routing_table, '');

	let k = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';
	let srv = function(host, key, name) {
		return { hostname: host, name: name, locations: [ { country: { code: 'DE',
			name: 'Germany', city: { name: 'Berlin' } } } ],
			technologies: [ { identifier: 'wireguard_udp',
				metadata: [ { name: 'public_key', value: key } ] } ] };
	};
	let n = normalize([ srv('de1.nordvpn.com', k, '<img src=x onerror=alert(1)> #1'),
		srv('evil;reboot', k, 'x'), srv('de2.nordvpn.com', 'nope', 'y') ]);
	eq('cache: only the valid relay kept', n.stats.gateways, 1);
	eq('cache: markup stripped from names', n.countries[0].cities[0].relays[0].name,
		'img src=x onerror=alert(1) #1');

	global.MOCK_UCI = { nordvpn: { main: { '.type': 'instance', interface: 'nordvpn' } },
		network: { nordvpn: { '.type': 'interface', vpn_type: 'nordvpn' } } };
	let uci = cursor();
	ok('write_relay refuses a bad endpoint', !write_relay(uci, 'nordvpn',
		{ hostname: 'a b', public_key: k, location: 'de-berlin' }, load_settings(uci)));
	ok('write_relay refuses a bad key', !write_relay(uci, 'nordvpn',
		{ hostname: 'de1.nordvpn.com', public_key: 'x', location: 'de-berlin' }, load_settings(uci)));
	// A tampered cache must not point the tunnel outside NordVPN.
	for (let h in [ '198.51.100.9', 'vpn.example.com', 'nordvpn.com.example.net',
	                'evilnordvpn.com', 'de1.nordvpn.com.', 'de1.nordvpn.com\nx' ])
		ok('write_relay refuses non-NordVPN endpoint ' + sprintf('%J', h), !write_relay(uci, 'nordvpn',
			{ hostname: h, public_key: k, location: 'de-berlin' }, load_settings(uci)));
	ok('nothing written for a refused relay', global.MOCK_UCI.network.nordvpn.nordvpn_gateway == null);
	for (let h in [ 'de1.nordvpn.com', 'de-nl12.nordvpn.com', 'nl-onion1.nordvpn.com' ])
		eq('nordvpn host accepted: ' + h, _cmn.validate_nordvpn_host(h), h);

	ok('managed: missing section is claimable', _cmn.managed_interface(uci, 'nv_new'));
	ok('managed: stamped interface', _cmn.managed_interface(uci, 'nordvpn'));
	global.MOCK_UCI.network.wan = { '.type': 'interface', proto: 'dhcp' };
	ok('managed: wan is not', !_cmn.managed_interface(uci, 'wan'));
}

// 8c. Device steering: MAC -> fw4 MARK rule, one mark lookup/prohibit set.
{
	eq('mac: colon form normalized', _cmn.validate_mac('AA:BB:CC:DD:EE:FF'), 'aa:bb:cc:dd:ee:ff');
	eq('mac: dash form normalized', _cmn.validate_mac('aa-bb-cc-dd-ee-0f'), 'aa:bb:cc:dd:ee:0f');
	eq('mac: bare hex normalized', _cmn.validate_mac('AABBCCDDEEFF'), 'aa:bb:cc:dd:ee:ff');
	eq('mac: short refused', _cmn.validate_mac('aa:bb:cc:dd:ee'), null);
	eq('mac: newline refused', _cmn.validate_mac('aa:bb:cc:dd:ee:ff\nx'), null);

	global.MOCK_UCI = { nordvpn: { main: { '.type': 'instance', enabled: '1',
		source_device: [ 'AA:BB:CC:DD:EE:01', 'aa-bb-cc-dd-ee-01', 'junk', 'aabbccddee02' ] } } };
	eq('load_settings: devices validated + deduped', load_settings(cursor()).source_devices,
		[ 'aa:bb:cc:dd:ee:01', 'aa:bb:cc:dd:ee:02' ]);
	global.MOCK_UCI.nordvpn.main.source_device = 'aa:bb:cc:dd:ee:03';
	eq('load_settings: single device string', load_settings(cursor()).source_devices, [ 'aa:bb:cc:dd:ee:03' ]);

	eq('mark: table 100 in the top byte', _routing.device_mark(100), '0x64000000/0xff000000');
	eq('mark: table id > 255 has none', _routing.device_mark(1000), null);
	eq('table id: numeric', _routing.rt_table_id('100'), 100);
	eq('table id: builtin main', _routing.rt_table_id('main'), 254);

	let D1 = 'aa:bb:cc:dd:ee:01', D2 = 'aa:bb:cc:dd:ee:02';
	let dsteer = function(over) {
		let base = { name: 'media', enabled: true, interface: 'nordvpn_rs', routing_table: '100',
			auto_routing: false, killswitch: true, block_ipv6: true, use_vpn_dns: false,
			source_networks: [], source_devices: [ D1, D2 ] };
		for (let k in over)
			base[k] = over[k];
		return base;
	};
	let count = function(conf, role) {
		let n = [];
		for (let k in global.MOCK_UCI[conf])
			if (global.MOCK_UCI[conf][k].nordvpn_role == role)
				push(n, global.MOCK_UCI[conf][k]);
		return n;
	};
	global.MOCK_UCI = { nordvpn: {
		main: { '.type': 'instance', interface: 'nordvpn', enabled: '1' },
		media: { '.type': 'instance', interface: 'nordvpn_rs', enabled: '1', source_device: [ D1, D2 ] }
	}, network: {
		nordvpn_rs: { '.type': 'interface', proto: 'wireguard', private_key: KEY, vpn_type: 'nordvpn' },
		lan: { '.type': 'interface', proto: 'static', ipaddr: '192.168.1.1/24' }
	}, firewall: {
		zlan: { '.type': 'zone', name: 'lan', network: [ 'lan' ] },
		zwan: { '.type': 'zone', name: 'wan', masq: '1', network: [ 'wan' ] }
	} };
	let uci = cursor();
	eq('devices alone make the instance steered', detect_routing(uci, dsteer({}), false).mode, 'steered');
	let res = enforce_routing(uci, dsteer({}));
	ok('device steering changes network + firewall', res.changed_network && res.changed_firewall);
	let marks = count('firewall', 'device_mark');
	eq('one MARK rule per device', length(marks), 2);
	let m1 = filter(marks, (r) => r.src_mac == D1)[0];
	ok('MARK rule shape', m1 && m1.target == 'MARK' && m1.src == 'lan' && m1.dest == '*' && m1.proto == 'all' &&
		m1.set_xmark == '0x64000000/0xff000000' && m1.nordvpn_iface == 'nordvpn_rs');
	let lk = count('network', 'dev_lookup');
	ok('one mark lookup rule into the table',
		length(lk) == 1 && lk[0].mark == '0x64000000/0xff000000' && lk[0].lookup == '100' && lk[0].priority == '19000');
	eq('kill switch prohibit for devices', length(count('network', 'dev_ks')), 1);
	eq('IPv6 prohibit for devices', length(count('network', 'dev_v6')), 1);
	eq('LAN zone forwards into the VPN zone', length(filter(count('firewall', 'forwarding'),
		(f) => f.src == 'lan' && f.dest == 'nordvpn_rs')), 1);

	res = enforce_routing(uci, dsteer({}));
	ok('device steering is idempotent', !res.changed_network && !res.changed_firewall);

	enforce_routing(uci, dsteer({ source_devices: [ D2 ] }));
	marks = count('firewall', 'device_mark');
	ok('deselecting removes only that MARK rule', length(marks) == 1 && marks[0].src_mac == D2);

	enforce_routing(uci, dsteer({ killswitch: false, block_ipv6: false }));
	ok('toggles off drop the device prohibits',
		length(count('network', 'dev_ks')) == 0 && length(count('network', 'dev_v6')) == 0);

	// Another instance listing the same MAC first owns it.
	global.MOCK_UCI.nordvpn.main.source_device = [ D1 ];
	res = enforce_routing(uci, dsteer({}));
	marks = count('firewall', 'device_mark');
	ok('a MAC owned by an earlier instance is skipped', length(marks) == 1 && marks[0].src_mac == D2);
	ok('... with a note', length(filter(res.notes, (n) => index(n, 'already steered by instance main') >= 0)) == 1);
	delete global.MOCK_UCI.nordvpn.main.source_device;

	res = enforce_routing(uci, dsteer({ routing_table: '1000' }));
	eq('table id > 255: no MARK rules', length(count('firewall', 'device_mark')), 0);
	eq('table id > 255: no lookup rule', length(count('network', 'dev_lookup')), 0);
	ok('table id > 255: note', length(filter(res.notes, (n) => index(n, 'id of 1-255') >= 0)) == 1);

	enforce_routing(uci, dsteer({}));
	enforce_routing(uci, dsteer({ source_devices: [] }));
	ok('clearing devices removes every device object',
		length(count('firewall', 'device_mark')) == 0 && length(count('network', 'dev_lookup')) == 0 &&
		length(count('network', 'dev_ks')) == 0 && length(count('network', 'dev_v6')) == 0);

	enforce_routing(uci, dsteer({}));
	enforce_routing(uci, dsteer({ enabled: false }));
	ok('disabling the instance releases device objects',
		length(count('firewall', 'device_mark')) == 0 && length(count('network', 'dev_lookup')) == 0);

	enforce_routing(uci, dsteer({}));
	ok('delete_instance removes device objects',
		_apply.delete_instance(uci, 'media').ok == true &&
		length(count('firewall', 'device_mark')) == 0 && length(count('network', 'dev_lookup')) == 0);
}

// 8d. NordVPN DNS through the tunnel: in steered mode the tunnel's routes live
//     in the instance table, so the router's own queries to the NordVPN
//     resolvers get stamped `dest` rules into that table.
{
	let count = function(conf, role) {
		let n = [];
		for (let k in global.MOCK_UCI[conf])
			if (global.MOCK_UCI[conf][k].nordvpn_role == role)
				push(n, global.MOCK_UCI[conf][k]);
		return sort(n, (a, b) => (a.dest < b.dest) ? -1 : (a.dest > b.dest) ? 1 : 0);
	};
	let sd = function(over) {
		let base = { name: 'main', enabled: true, interface: 'nordvpn', routing_table: '100',
			auto_routing: false, killswitch: false, block_ipv6: false, vpn_dns: 'standard',
			source_networks: [ 'lan' ], source_devices: [], source_domains: [] };
		for (let k in over)
			base[k] = over[k];
		return base;
	};
	global.MOCK_UCI = { nordvpn: { main: { '.type': 'instance', interface: 'nordvpn', enabled: '1' } },
		network: {
			nordvpn: { '.type': 'interface', proto: 'wireguard', private_key: KEY, vpn_type: 'nordvpn' },
			lan: { '.type': 'interface', proto: 'static', ipaddr: '192.168.1.1/24' } },
		firewall: {
			zlan: { '.type': 'zone', name: 'lan', network: [ 'lan' ] },
			zwan: { '.type': 'zone', name: 'wan', masq: '1', network: [ 'wan' ] } } };
	let uci = cursor();
	let shape = (l) => map(l, (r) => [ r.dest, r.lookup, r.priority ]);

	enforce_routing(uci, sd({}));
	eq('dns: a rule per standard resolver, into the table', shape(count('network', 'dns_lookup')),
		[ [ '103.86.96.100/32', '100', '19500' ], [ '103.86.99.100/32', '100', '19500' ] ]);
	eq('dns: the interface carries the resolvers', global.MOCK_UCI.network.nordvpn.dns,
		[ '103.86.96.100', '103.86.99.100' ]);
	eq('dns: the rules are stamped, not user rules', _routing.count_user_routes(uci, 'nordvpn', ''), 0);
	eq('dns: still steered, not manual', detect_routing(uci, sd({}), false).mode, 'steered');
	ok('dns: idempotent', !enforce_routing(uci, sd({})).changed_network);

	enforce_routing(uci, sd({ vpn_dns: 'threat' }));
	eq('dns: Threat Protection swaps the resolvers', shape(count('network', 'dns_lookup')),
		[ [ '103.86.96.96/32', '100', '19500' ], [ '103.86.99.99/32', '100', '19500' ] ]);

	enforce_routing(uci, sd({ vpn_dns: 'threat', routing_table: '101' }));
	eq('dns: a table change re-points the rules', map(count('network', 'dns_lookup'), (r) => r.lookup),
		[ '101', '101' ]);

	enforce_routing(uci, sd({ vpn_dns: 'off' }));
	eq('dns: off removes the rules', length(count('network', 'dns_lookup')), 0);

	enforce_routing(uci, sd({}));
	enforce_routing(uci, sd({ auto_routing: true, source_networks: [], routing_table: '' }));
	eq('dns: automatic mode needs none (the main table carries the tunnel)',
		length(count('network', 'dns_lookup')), 0);
	enforce_routing(uci, sd({ auto_routing: true, source_networks: [] }));
	eq('dns: all-LAN with a table keeps them (the tunnel lives in the table)',
		length(count('network', 'dns_lookup')), 2);

	enforce_routing(uci, sd({}));
	enforce_routing(uci, sd({ enabled: false }));
	eq('dns: a disabled instance releases them', length(count('network', 'dns_lookup')), 0);
}

// 8e. Exceptions: excluded devices and domains always take the main table,
//     ahead of every steering and prohibit rule. With "Route all LAN traffic"
//     they move the instance onto steering of the LAN zone's networks.
{
	let D1 = 'aa:bb:cc:dd:ee:01', D2 = 'aa:bb:cc:dd:ee:02', D3 = 'aa:bb:cc:dd:ee:03';
	let BMARK = '0xfe000000/0xff000000';

	// Settings: parsing, overlap, and the implicit table of all-LAN mode.
	global.MOCK_UCI = { nordvpn: { main: { '.type': 'instance', interface: 'nordvpn', auto_routing: '1',
		bypass_device: [ 'AA:BB:CC:DD:EE:01', 'aa-bb-cc-dd-ee-01', 'junk' ],
		source_device: [ D1, D2 ],
		bypass_domain: [ 'Bank.Example.com', 'not a domain!' ],
		steer_domain: [ 'bank.example.com', 'video.example.org' ] } } };
	let ls = load_settings(cursor());
	eq('exceptions: devices validated + deduped', ls.bypass_devices, [ D1 ]);
	global.MOCK_UCI.nordvpn.main.custom_dns = [ '9.9.9.9', 'junk', '9.9.9.9', '999.1.1.1', '1.1.1.1' ];
	eq('custom dns: validated + deduped', load_settings(cursor()).custom_dns, [ '9.9.9.9', '1.1.1.1' ]);
	delete global.MOCK_UCI.nordvpn.main.custom_dns;
	eq('exceptions: domains validated + normalized', ls.bypass_domains, [ 'bank.example.com' ]);
	eq('exceptions: an excluded device is not also steered', ls.source_devices, [ D2 ]);
	eq('exceptions: an excluded domain is not also steered', ls.source_domains, [ 'video.example.org' ]);
	eq('exceptions: all-LAN gets the interface as implicit table', ls.routing_table, 'nordvpn');
	global.MOCK_UCI.nordvpn.main.bypass_ip = [ '10.9.0.0/16', '10.9.0.0/33', '0.0.0.0/0', 'x.y', '8.8.8.8' ];
	global.MOCK_UCI.nordvpn.main.steer_ip = [ '8.8.8.8', '1.1.1.1/32' ];
	ls = load_settings(cursor());
	eq('exceptions: addresses validated', ls.bypass_ips, [ '10.9.0.0/16', '8.8.8.8' ]);
	eq('exceptions: an excluded address is not also steered', ls.source_ips, [ '1.1.1.1/32' ]);
	delete global.MOCK_UCI.nordvpn.main.bypass_ip;
	delete global.MOCK_UCI.nordvpn.main.steer_ip;
	global.MOCK_UCI.nordvpn.main.routing_table = '100';
	eq('exceptions: an explicit table wins', load_settings(cursor()).routing_table, '100');
	delete global.MOCK_UCI.nordvpn.main.routing_table;
	global.MOCK_UCI.nordvpn.main.auto_routing = '0';
	eq('exceptions: no implicit table outside all-LAN', load_settings(cursor()).routing_table, '');
	global.MOCK_UCI.nordvpn.main.auto_routing = '1';
	delete global.MOCK_UCI.nordvpn.main.bypass_device;
	delete global.MOCK_UCI.nordvpn.main.bypass_domain;
	eq('exceptions: removing them drops the implicit table', load_settings(cursor()).routing_table, '');

	let count = function(conf, role) {
		let n = [];
		for (let k in global.MOCK_UCI[conf])
			if (global.MOCK_UCI[conf][k].nordvpn_role == role)
				push(n, global.MOCK_UCI[conf][k]);
		return n;
	};
	let ex = function(over) {
		let base = { name: 'main', enabled: true, interface: 'nordvpn', routing_table: '100',
			auto_routing: true, killswitch: true, block_ipv6: true, vpn_dns: 'off',
			source_networks: [], source_devices: [], source_domains: [],
			bypass_devices: [ D1 ], bypass_domains: [] };
		for (let k in over)
			base[k] = over[k];
		return base;
	};
	let fresh = function() {
		global.MOCK_UCI = { nordvpn: { main: { '.type': 'instance', interface: 'nordvpn', enabled: '1' } },
			network: {
				nordvpn: { '.type': 'interface', proto: 'wireguard', private_key: KEY, vpn_type: 'nordvpn' },
				lan: { '.type': 'interface', proto: 'static', ipaddr: '192.168.1.1/24' },
				iot: { '.type': 'interface', proto: 'static', ipaddr: '192.168.5.1/24' } },
			firewall: {
				zlan: { '.type': 'zone', name: 'lan', network: [ 'lan', 'iot' ] },
				zwan: { '.type': 'zone', name: 'wan', masq: '1', network: [ 'wan' ] } },
			dhcp: {} };
		return cursor();
	};
	let yes = { nftset: true }, no = { nftset: false };

	// detect: exceptions only count while traffic is routed at all.
	let uci = fresh();
	let det = detect_routing(uci, ex({}), false);
	eq('exceptions: all-LAN still reads as auto', [ det.mode, det.exceptions ], [ 'auto', true ]);
	det = detect_routing(uci, ex({ auto_routing: false }), false);
	eq('exceptions: alone they route nothing', [ det.mode, det.exceptions ], [ 'none', false ]);

	// All-LAN + an excluded device: steering of every LAN-zone network.
	let res = enforce_routing(uci, ex({}), yes);
	eq('exceptions: every LAN-zone network steered into the table',
		sort(map(count('network', 'steer_lookup'), (r) => r['in'] + '>' + r.lookup)), [ 'iot>100', 'lan>100' ]);
	eq('exceptions: no automatic REJECT kill switch', count('firewall', 'killswitch'), []);
	eq('exceptions: kill switch as prohibit rules instead', length(count('network', 'steer_ks')), 2);
	let bm = count('firewall', 'bypass_mark');
	ok('exceptions: MARK rule for the excluded device', length(bm) == 1 && bm[0].src_mac == D1 &&
		bm[0].src == 'lan' && bm[0].dest == '*' && bm[0].target == 'MARK' && bm[0].set_xmark == BMARK);
	let bl = count('network', 'bypass_lookup'), bl6 = count('network', 'bypass_lookup6');
	ok('exceptions: mark -> main table at 18000, both families',
		length(bl) == 1 && bl[0].mark == BMARK && bl[0].lookup == 'main' && bl[0].priority == '18000' &&
		length(bl6) == 1 && bl6[0]['.type'] == 'rule6' && bl6[0].lookup == 'main');
	eq('exceptions: LAN zone forwards into the VPN zone', length(filter(count('firewall', 'forwarding'),
		(f) => f.src == 'lan' && f.dest == 'nordvpn')), 1);
	ok('exceptions: idempotent', !enforce_routing(uci, ex({}), yes).changed_firewall &&
		!enforce_routing(uci, ex({}), yes).changed_network);
	eq('exceptions: all-LAN objects are stamped, not manual', detect_routing(uci, ex({}), false).mode, 'auto');

	// Excluded domains: a dnsmasq-filled set and a MARK rule from the LAN zone.
	res = enforce_routing(uci, ex({ bypass_domains: [ 'bank.example.com' ] }), yes);
	let bs = count('firewall', 'bypass_set'), bdm = count('firewall', 'bypass_domain_mark');
	ok('exceptions: fw4 set for excluded domains', length(bs) == 1 && bs[0].name == 'nv_nordvpn_byp');
	ok('exceptions: domain MARK rule from the LAN zone', length(bdm) == 1 && bdm[0].src == 'lan' && bdm[0].dest == '*' &&
		bdm[0].ipset == 'nv_nordvpn_byp' && bdm[0].set_xmark == BMARK);
	let bd = count('dhcp', 'bypass_dns');
	ok('exceptions: dnsmasq fills the set', length(bd) == 1 && bd[0].domain[0] == 'bank.example.com' &&
		bd[0].name[0] == 'nv_nordvpn_byp');
	ok('exceptions: dnsmasq restarted for the set', res.domains_active);
	res = enforce_routing(uci, ex({ bypass_domains: [ 'bank.example.com' ] }), no);
	ok('exceptions: no dnsmasq-full -> domain objects removed, with a note',
		length(count('firewall', 'bypass_set')) == 0 && length(count('dhcp', 'bypass_dns')) == 0 &&
		length(filter(res.notes, (n) => index(n, 'dnsmasq-full') >= 0)) == 1);
	eq('exceptions: ... the excluded device stays', length(count('firewall', 'bypass_mark')), 1);

	// Excluded addresses: a MARK rule on the destination, no dnsmasq needed.
	res = enforce_routing(uci, ex({ bypass_ips: [ '203.0.113.0/24' ] }), no);
	let bip = count('firewall', 'bypass_ip_mark');
	ok('exceptions: destination MARK rule for an excluded network', length(bip) == 1 && bip[0].dest_ip == '203.0.113.0/24' &&
		bip[0].src == 'lan' && bip[0].dest == '*' && bip[0].set_xmark == BMARK);
	ok('exceptions: excluded addresses work without dnsmasq-full', length(filter(res.notes, (n) => index(n, 'dnsmasq-full') >= 0)) == 0);
	enforce_routing(uci, ex({}), no);
	eq('exceptions: excluded address removed with its entry', length(count('firewall', 'bypass_ip_mark')), 0);

	// Steered addresses ride the device mark and lookup.
	res = enforce_routing(uci, ex({ auto_routing: false, bypass_devices: [], source_networks: [], source_ips: [ '198.51.100.7', '192.0.2.0/24' ] }), no);
	let sip = count('firewall', 'ip_mark');
	ok('steer: a MARK rule per steered address', length(sip) == 2 && sip[0].dest_ip == '198.51.100.7' && sip[0].src == 'lan' &&
		sip[0].dest == '*' && sip[0].target == 'MARK');
	eq('steer: addresses use the tunnel table via the mark', length(count('network', 'dev_lookup')), 1);
	enforce_routing(uci, ex({ auto_routing: false, bypass_devices: [], source_ips: [ '198.51.100.7' ] }), no);
	eq('steer: dropped addresses lose their rule', length(count('firewall', 'ip_mark')), 1);

	// Removing the exceptions returns to plain automatic routing.
	enforce_routing(uci, ex({ bypass_devices: [], routing_table: '' }), yes);
	ok('exceptions: removed -> back to automatic routing',
		length(count('network', 'steer_lookup')) == 0 && length(count('firewall', 'killswitch')) == 1 &&
		length(count('firewall', 'bypass_mark')) == 0 && length(count('network', 'bypass_lookup')) == 0 &&
		length(count('network', 'bypass_lookup6')) == 0);

	// Without a table all-LAN stays automatic (exceptions not applied).
	uci = fresh();
	res = enforce_routing(uci, ex({ routing_table: '' }), yes);
	ok('exceptions: no table -> stays automatic, with a note',
		length(count('firewall', 'killswitch')) == 1 && length(count('firewall', 'bypass_mark')) == 0 &&
		length(filter(res.notes, (n) => index(n, 'need a routing table') >= 0)) == 1);

	// The main table cannot carry steering and exceptions at once.
	uci = fresh();
	res = enforce_routing(uci, ex({ routing_table: '254' }), yes);
	ok('exceptions: refused when the instance table is main',
		length(count('firewall', 'bypass_mark')) == 0 &&
		length(filter(res.notes, (n) => index(n, 'other than main') >= 0)) == 1);

	// Steered mode: exceptions sit next to device steering, and must follow
	// every steering MARK rule (fw4: the last matching MARK wins).
	uci = fresh();
	let st = (devs) => ex({ auto_routing: false, source_devices: devs });
	enforce_routing(uci, st([ D2 ]), yes);
	enforce_routing(uci, st([ D2, D3 ]), yes);
	let order = [];
	for (let k in global.MOCK_UCI.firewall) {
		let r = global.MOCK_UCI.firewall[k].nordvpn_role;
		if (r == 'device_mark' || r == 'bypass_mark')
			push(order, r);
	}
	eq('exceptions: recreated after a later steering MARK rule', order,
		[ 'device_mark', 'device_mark', 'bypass_mark' ]);
	ok('exceptions: order stable once fixed', !enforce_routing(uci, st([ D2, D3 ]), yes).changed_firewall);

	// Disabling the instance releases everything.
	enforce_routing(uci, ex({ enabled: false, bypass_domains: [ 'bank.example.com' ] }), yes);
	ok('exceptions: a disabled instance releases them',
		length(count('firewall', 'bypass_mark')) == 0 && length(count('network', 'bypass_lookup')) == 0 &&
		length(count('network', 'bypass_lookup6')) == 0 && length(count('dhcp', 'bypass_dns')) == 0 &&
		length(count('firewall', 'bypass_set')) == 0);
}

// 8f. "Route all LAN traffic" with a routing table: the tunnel's default route
//     lives in that table, so the LAN zone's networks are steered into it
//     (the automatic path only works through the main table).
{
	let count = function(conf, role) {
		let n = [];
		for (let k in global.MOCK_UCI[conf])
			if (global.MOCK_UCI[conf][k].nordvpn_role == role)
				push(n, global.MOCK_UCI[conf][k]);
		return n;
	};
	let at = function(over) {
		let base = { name: 'main', enabled: true, interface: 'nordvpn', routing_table: '100',
			auto_routing: true, killswitch: true, block_ipv6: true, vpn_dns: 'off',
			source_networks: [], source_devices: [], source_domains: [],
			bypass_devices: [], bypass_domains: [] };
		for (let k in over)
			base[k] = over[k];
		return base;
	};
	global.MOCK_UCI = { nordvpn: { main: { '.type': 'instance', interface: 'nordvpn', enabled: '1' } },
		network: {
			nordvpn: { '.type': 'interface', proto: 'wireguard', private_key: KEY, vpn_type: 'nordvpn' },
			lan: { '.type': 'interface', proto: 'static', ipaddr: '192.168.1.1/24' } },
		firewall: {
			zlan: { '.type': 'zone', name: 'lan', network: [ 'lan' ] },
			zwan: { '.type': 'zone', name: 'wan', masq: '1', network: [ 'wan' ] } } };
	let uci = cursor();

	// Before the fix: a REJECT kill switch and no rule into the table, so
	// the LAN kept using the WAN while the status said "connected".
	enforce_routing(uci, at({}));
	eq('all-LAN + table: reads as automatic', detect_routing(uci, at({}), false).mode, 'auto');
	eq('all-LAN + table: LAN steered into the table',
		map(count('network', 'steer_lookup'), (r) => [ r['in'], r.lookup, r.priority ]), [ [ 'lan', '100', '20000' ] ]);
	ok('all-LAN + table: prohibit kill switch, not the REJECT rule',
		length(count('network', 'steer_ks')) == 1 && length(count('firewall', 'killswitch')) == 0);
	eq('all-LAN + table: LAN zone forwards into the VPN zone', length(filter(count('firewall', 'forwarding'),
		(f) => f.src == 'lan' && f.dest == 'nordvpn')), 1);
	ok('all-LAN + table: idempotent', !enforce_routing(uci, at({})).changed_network);

	// Clearing the table goes back to the main-table path, cleanly.
	enforce_routing(uci, at({ routing_table: '' }));
	ok('all-LAN without a table: automatic path again',
		length(count('network', 'steer_lookup')) == 0 && length(count('network', 'steer_ks')) == 0 &&
		length(count('firewall', 'killswitch')) == 1);

	// Leftover steered devices/domains are not applied on top of all-LAN.
	enforce_routing(uci, at({ source_devices: [ 'aa:bb:cc:dd:ee:01' ], source_domains: [ 'example.com' ] }),
		{ nftset: true });
	ok('all-LAN + table: no per-device or per-domain steering',
		length(count('firewall', 'device_mark')) == 0 && length(count('firewall', 'domain_mark')) == 0 &&
		length(count('network', 'dev_lookup')) == 0);

	// A hand-made rule into the table still means "manual: hands off".
	global.MOCK_UCI.network.userroute = { '.type': 'route', interface: 'lan', target: '10.0.0.0/8', table: '100' };
	eq('all-LAN + table + own route: manual', detect_routing(uci, at({}), false).mode, 'manual');
}

// 8g. A routing table change re-points the steering rules (they are keyed by
//     network, so reconciliation alone would keep the old lookup).
{
	let count = function(conf, role) {
		let n = [];
		for (let k in global.MOCK_UCI[conf])
			if (global.MOCK_UCI[conf][k].nordvpn_role == role)
				push(n, global.MOCK_UCI[conf][k]);
		return n;
	};
	let st = function(over) {
		let base = { name: 'main', enabled: true, interface: 'nordvpn', routing_table: '100',
			auto_routing: false, killswitch: true, block_ipv6: true, vpn_dns: 'off',
			source_networks: [ 'lan', 'guest' ], source_devices: [], source_domains: [],
			bypass_devices: [], bypass_domains: [] };
		for (let k in over)
			base[k] = over[k];
		return base;
	};
	global.MOCK_UCI = { nordvpn: { main: { '.type': 'instance', interface: 'nordvpn', enabled: '1' } },
		network: {
			nordvpn: { '.type': 'interface', proto: 'wireguard', private_key: KEY, vpn_type: 'nordvpn' },
			lan: { '.type': 'interface', proto: 'static', ipaddr: '192.168.1.1/24' },
			guest: { '.type': 'interface', proto: 'static', ipaddr: '192.168.9.1/24' } },
		firewall: {
			zlan: { '.type': 'zone', name: 'lan', network: [ 'lan' ] },
			zguest: { '.type': 'zone', name: 'guest', network: [ 'guest' ] },
			zwan: { '.type': 'zone', name: 'wan', masq: '1', network: [ 'wan' ] } } };
	let uci = cursor();
	let lookups = () => sort(map(count('network', 'steer_lookup'), (r) => r['in'] + '>' + r.lookup));
	let locals = () => sort(map(count('network', 'steer_local'), (r) => r.target + '>' + r.table));

	enforce_routing(uci, st({}));
	eq('table change: before', lookups(), [ 'guest>100', 'lan>100' ]);
	let res = enforce_routing(uci, st({ routing_table: '101' }));
	ok('table change: reported as a network change', res.changed_network);
	eq('table change: every lookup re-pointed, none duplicated', lookups(), [ 'guest>101', 'lan>101' ]);
	eq('table change: local bypass routes follow', locals(),
		[ '192.168.1.0/24>101', '192.168.9.0/24>101' ]);
	ok('table change: stable afterwards', !enforce_routing(uci, st({ routing_table: '101' })).changed_network);
	enforce_routing(uci, st({ routing_table: '101', source_networks: [ 'lan' ] }));
	eq('table change: deselecting still removes only that network', lookups(), [ 'lan>101' ]);
}

// 9b. domain steering: dnsmasq resolves the listed domains into a stamped fw4
//     nft set, one MARK rule gives them the instance's device mark, and the
//     device lookup / prohibit rules route them. Needs dnsmasq nftset support.
{
	eq('domain: normalized', _cmn.validate_domain('*.Example.COM.'), 'example.com');
	eq('domain: leading dot dropped', _cmn.validate_domain('.netflix.com'), 'netflix.com');
	eq('domain: single label ok', _cmn.validate_domain('lan'), 'lan');
	eq('domain: slash refused', _cmn.validate_domain('a/b.com'), null);
	eq('domain: dnsmasq separator refused', _cmn.validate_domain('a.com#1'), null);
	eq('domain: newline refused', _cmn.validate_domain('a.com\nb.com'), null);
	eq('domain: hyphen edge refused', _cmn.validate_domain('-a.com'), null);
	eq('domain: empty refused', _cmn.validate_domain('*.'), null);

	global.MOCK_UCI = { nordvpn: { main: { '.type': 'instance', enabled: '1',
		steer_domain: [ 'Example.com', 'example.com.', 'bad domain', 'b.org' ] } } };
	eq('load_settings: domains validated + deduped', load_settings(cursor()).source_domains, [ 'example.com', 'b.org' ]);
	let many = [];
	for (let i = 0; i < 80; i++)
		push(many, 'd' + i + '.com');
	global.MOCK_UCI.nordvpn.main.steer_domain = many;
	eq('load_settings: domains capped', length(load_settings(cursor()).source_domains), _cmn.MAX_STEER_DOMAINS);

	let msteer = function(over) {
		let base = { name: 'media', enabled: true, interface: 'nordvpn_rs', routing_table: '100',
			auto_routing: false, killswitch: true, block_ipv6: true, use_vpn_dns: false,
			source_networks: [], source_devices: [], source_domains: [ 'example.com', 'b.org' ] };
		for (let k in over)
			base[k] = over[k];
		return base;
	};
	let count = function(conf, role) {
		let n = [];
		for (let k in global.MOCK_UCI[conf] || {})
			if (global.MOCK_UCI[conf][k].nordvpn_role == role)
				push(n, global.MOCK_UCI[conf][k]);
		return n;
	};
	global.MOCK_UCI = { nordvpn: {
		main: { '.type': 'instance', interface: 'nordvpn', enabled: '1' },
		media: { '.type': 'instance', interface: 'nordvpn_rs', enabled: '1' }
	}, network: {
		nordvpn_rs: { '.type': 'interface', proto: 'wireguard', private_key: KEY, vpn_type: 'nordvpn' },
		lan: { '.type': 'interface', proto: 'static', ipaddr: '192.168.1.1/24' }
	}, firewall: {
		zlan: { '.type': 'zone', name: 'lan', network: [ 'lan' ] },
		zwan: { '.type': 'zone', name: 'wan', masq: '1', network: [ 'wan' ] }
	}, dhcp: {
		user: { '.type': 'ipset', name: [ 'mine' ], domain: [ 'user.example' ] }
	} };
	let uci = cursor();
	let yes = { nftset: true };
	eq('domains alone make the instance steered', detect_routing(uci, msteer({}), false).mode, 'steered');
	let res = enforce_routing(uci, msteer({}), yes);
	ok('domain steering changes network + firewall + dhcp',
		res.changed_network && res.changed_firewall && res.changed_dhcp && res.domains_active);
	let sets = count('firewall', 'domain_set');
	ok('one fw4 ipset', length(sets) == 1 && sets[0]['.type'] == 'ipset' &&
		sets[0].name == 'nv_nordvpn_rs_dom' && sets[0].family == 'ipv4' &&
		sprintf('%J', sets[0].match) == sprintf('%J', [ 'dest_ip' ]));
	let mr = count('firewall', 'domain_mark');
	ok('one MARK rule on the set', length(mr) == 1 && mr[0].ipset == 'nv_nordvpn_rs_dom' &&
		mr[0].target == 'MARK' && mr[0].src == 'lan' && mr[0].dest == '*' && mr[0].set_xmark == '0x64000000/0xff000000');
	let dd = count('dhcp', 'domain_dns');
	ok('one dnsmasq nftset section', length(dd) == 1 && dd[0]['.type'] == 'ipset' &&
		sprintf('%J', dd[0].name) == sprintf('%J', [ 'nv_nordvpn_rs_dom' ]) &&
		sprintf('%J', dd[0].domain) == sprintf('%J', [ 'example.com', 'b.org' ]) &&
		dd[0].table == 'fw4' && dd[0].table_family == 'inet' && dd[0].family == '4');
	let lk = count('network', 'dev_lookup');
	ok('mark lookup rule shared with devices', length(lk) == 1 && lk[0].lookup == '100' && lk[0].priority == '19000');
	eq('kill switch prohibit on the mark', length(count('network', 'dev_ks')), 1);
	eq('LAN zone forwards into the VPN zone', length(filter(count('firewall', 'forwarding'),
		(f) => f.src == 'lan' && f.dest == 'nordvpn_rs')), 1);
	ok('user dnsmasq ipset untouched', global.MOCK_UCI.dhcp.user != null && global.MOCK_UCI.dhcp.user.domain[0] == 'user.example');

	res = enforce_routing(uci, msteer({}), yes);
	ok('domain steering is idempotent', !res.changed_network && !res.changed_firewall && !res.changed_dhcp);

	res = enforce_routing(uci, msteer({ source_domains: [ 'b.org' ] }), yes);
	dd = count('dhcp', 'domain_dns');
	ok('editing domains rewrites the one section', res.changed_dhcp && !res.changed_firewall &&
		length(dd) == 1 && sprintf('%J', dd[0].domain) == sprintf('%J', [ 'b.org' ]));

	res = enforce_routing(uci, msteer({ source_devices: [ 'aa:bb:cc:dd:ee:01' ] }), yes);
	ok('devices and domains share one lookup rule', length(count('network', 'dev_lookup')) == 1 &&
		length(count('firewall', 'device_mark')) == 1 && length(count('firewall', 'domain_mark')) == 1);

	res = enforce_routing(uci, msteer({ routing_table: '101' }), yes);
	ok('a table change moves the domain mark', count('firewall', 'domain_mark')[0].set_xmark == '0x65000000/0xff000000');

	res = enforce_routing(uci, msteer({}), { nftset: false });
	ok('unsupported dnsmasq: no domain objects', length(count('firewall', 'domain_set')) == 0 &&
		length(count('firewall', 'domain_mark')) == 0 && length(count('dhcp', 'domain_dns')) == 0 &&
		length(count('network', 'dev_lookup')) == 0);
	ok('unsupported dnsmasq: note', length(filter(res.notes, (n) => index(n, 'dnsmasq-full') >= 0)) == 1);

	enforce_routing(uci, msteer({}), yes);
	res = enforce_routing(uci, msteer({ routing_table: '1000' }), yes);
	ok('table id > 255: no domain objects', length(count('firewall', 'domain_mark')) == 0 &&
		length(count('dhcp', 'domain_dns')) == 0);

	let zl = global.MOCK_UCI.firewall.zlan;
	delete global.MOCK_UCI.firewall.zlan;
	res = enforce_routing(uci, msteer({}), yes);
	ok('no LAN zone: no domain objects + note', length(count('dhcp', 'domain_dns')) == 0 &&
		length(filter(res.notes, (n) => index(n, 'LAN zone') >= 0)) >= 1);
	global.MOCK_UCI.firewall.zlan = zl;

	enforce_routing(uci, msteer({}), yes);
	enforce_routing(uci, msteer({ source_domains: [] }), yes);
	ok('clearing domains removes every domain object', length(count('firewall', 'domain_set')) == 0 &&
		length(count('firewall', 'domain_mark')) == 0 && length(count('dhcp', 'domain_dns')) == 0 &&
		length(count('network', 'dev_lookup')) == 0 && global.MOCK_UCI.dhcp.user != null);

	enforce_routing(uci, msteer({}), yes);
	enforce_routing(uci, msteer({ auto_routing: true }), yes);
	ok('auto routing drops domain steering', length(count('dhcp', 'domain_dns')) == 0 &&
		length(count('firewall', 'domain_mark')) == 0);

	enforce_routing(uci, msteer({}), yes);
	enforce_routing(uci, msteer({ enabled: false }), yes);
	ok('disabling the instance releases domain objects', length(count('dhcp', 'domain_dns')) == 0 &&
		length(count('firewall', 'domain_set')) == 0);

	enforce_routing(uci, msteer({}), yes);
	global.MOCK_UCI.nordvpn.media.steer_domain = [ 'example.com' ];
	global.MOCK_UCI.nordvpn.media.routing_table = '100';
	ok('delete_instance removes domain objects',
		_apply.delete_instance(uci, 'media').ok == true &&
		length(count('dhcp', 'domain_dns')) == 0 && length(count('firewall', 'domain_set')) == 0 &&
		length(count('firewall', 'domain_mark')) == 0 && global.MOCK_UCI.dhcp.user != null);
}

// 10. MTU recommendation (pure): WAN MTU minus 80, clamped to [1280, 1420].
{
	eq('mtu 1500 -> 1420 (vendor default)', recommend_mtu(1500), 1420);
	eq('mtu 1492 PPPoE -> 1412', recommend_mtu(1492), 1412);
	eq('mtu 1428 LTE -> 1348', recommend_mtu(1428), 1348);
	eq('mtu clamps up to the 1280 IPv6 floor', recommend_mtu(1350), 1280);
	eq('mtu clamps down to the 1420 ceiling', recommend_mtu(1600), 1420);
	eq('mtu null when WAN unknown', recommend_mtu(null), null);
	eq('mtu null on zero/garbage', recommend_mtu(0), null);
}

// 11. egress probe settings, decisions and state folding (pure)
{
	const _status = require('nordvpn.status');
	const PT = _cmn.PROBE_FAIL_THRESHOLD;

	eq('ipv4: valid literal', _cmn.validate_ipv4('1.1.1.1'), '1.1.1.1');
	eq('ipv4: octet out of range', _cmn.validate_ipv4('1.1.1.256'), null);
	eq('ipv4: hostname refused', _cmn.validate_ipv4('one.one.one.one'), null);
	eq('ipv4: shell metachar refused', _cmn.validate_ipv4('1.1.1.1;reboot'), null);
	eq('ipv4: trailing line refused', _cmn.validate_ipv4('1.1.1.1\n8.8.8.8'), null);

	global.MOCK_UCI = { nordvpn: { main: { '.type': 'instance', interface: 'nordvpn' } }, network: {} };
	let s0 = load_settings(cursor());
	eq('probe: off by default', s0.egress_probe, false);
	eq('probe: default targets', s0.probe_targets, _cmn.DEFAULT_PROBE_TARGETS);
	global.MOCK_UCI = { nordvpn: { main: { '.type': 'instance', interface: 'nordvpn', egress_probe: '1',
		probe_target: [ '9.9.9.9', 'bogus', '9.9.9.9', '10.0.0.300', '149.112.112.112' ] } }, network: {} };
	let s1 = load_settings(cursor());
	eq('probe: enabled from config', s1.egress_probe, true);
	eq('probe: targets validated and deduped', s1.probe_targets, [ '9.9.9.9', '149.112.112.112' ]);
	global.MOCK_UCI = { nordvpn: { main: { '.type': 'instance', interface: 'nordvpn', probe_target: 'nope' } }, network: {} };
	eq('probe: all-invalid targets fall back to defaults', load_settings(cursor()).probe_targets, _cmn.DEFAULT_PROBE_TARGETS);

	// Nothing is run for a device or target that fails validation.
	eq('probe: invalid device refused', _status.egress_probe('wg0; reboot', [ '1.1.1.1' ]).ok, false);
	eq('probe: no valid target -> not ok', _status.egress_probe('nordvpn', [ 'x', null ]).ok, false);

	let on = { enabled: true, egress_probe: true };
	ok('should_probe: connected + on', _service.should_probe(on, 'connected'));
	ok('should_probe: not when degraded', !_service.should_probe(on, 'degraded'));
	ok('should_probe: not when probe off', !_service.should_probe({ ...on, egress_probe: false }, 'connected'));
	ok('should_probe: not when disabled', !_service.should_probe({ ...on, enabled: false }, 'connected'));

	let gw = 'ee70.nordvpn.com';
	let failing = { probe_server: gw, probe_fails: PT };
	eq('effective: failing probe -> no_egress', _service.effective_state(on, 'connected', failing, gw), 'no_egress');
	eq('effective: below threshold stays connected',
		_service.effective_state(on, 'connected', { probe_server: gw, probe_fails: PT - 1 }, gw), 'connected');
	eq('effective: failures from another server ignored',
		_service.effective_state(on, 'connected', failing, 'nl1.nordvpn.com'), 'connected');
	eq('effective: probe off ignores stale failures',
		_service.effective_state({ ...on, egress_probe: false }, 'connected', failing, gw), 'connected');
	eq('effective: other states pass through', _service.effective_state(on, 'degraded', failing, gw), 'degraded');

	// no_egress is unhealthy for the watchdog, with the usual grace period.
	let wd = { enabled: true, watchdog: true, fixed_server: '' };
	ok('recover: no_egress past grace -> true', _service.should_recover(wd, 'no_egress', 1000, 0, 0, 1100));
	ok('recover: no_egress within grace -> false', !_service.should_recover(wd, 'no_egress', 1070, 0, 0, 1100));
	eq('watchdog: no_egress stamps degraded_since',
		_service.watchdog_update('no_egress', { degraded_since: 0, last_recover: 0, recover_fails: 0 }, 1100, true).degraded_since, 1100);

	// Folding results: failures count up to the threshold (one lost event),
	// a success resets and reports the restore; a new server starts fresh.
	let st = {}, evs = [];
	for (let i = 1; i <= PT + 1; i++) {
		let u = _service.probe_update(st, { ok: false, target: null }, gw, 1000 + i);
		st = { ...st, ...u.fields };
		push(evs, u.event);
	}
	eq('fold: failures counted', st.probe_fails, PT + 1);
	eq('fold: exactly one egress_lost at the threshold', filter(evs, (e) => e == 'egress_lost'), [ 'egress_lost' ]);
	eq('fold: lost event on the threshold tick', evs[PT - 1], 'egress_lost');
	let u = _service.probe_update(st, { ok: true, target: '1.1.1.1' }, gw, 2000);
	eq('fold: success resets and restores', [ u.fields.probe_fails, u.fields.probe_ok_at, u.event ], [ 0, 2000, 'egress_restored' ]);
	u = _service.probe_update({ probe_server: gw, probe_fails: 1 }, { ok: true, target: '1.1.1.1' }, gw, 2000);
	eq('fold: success below threshold is no event', u.event, null);
	u = _service.probe_update(st, { ok: false }, 'nl1.nordvpn.com', 2000);
	eq('fold: new server restarts the count', [ u.fields.probe_fails, u.fields.probe_server ], [ 1, 'nl1.nordvpn.com' ]);
	eq('fold: null result counts as failure', _service.probe_update({}, null, gw, 1).fields.probe_fails, 1);

	eq('clear: nothing to clear', _service.probe_clear({ last_attempt: 5 }), null);
	eq('clear: resets probe fields', _service.probe_clear(st).probe_fails, 0);

	eq('report: probe off', _service.egress_report({ egress_probe: false }, st, gw), { enabled: false });
	eq('report: not yet checked', _service.egress_report(on, {}, gw).ok, null);
	let rep = _service.egress_report(on, { probe_server: gw, probe_at: 50, probe_fails: 0, probe_ok_at: 50, probe_target: '1.1.1.1' }, gw);
	eq('report: healthy', [ rep.ok, rep.fails, rep.checked_at, rep.ok_at, rep.target ], [ true, 0, 50, 50, '1.1.1.1' ]);
	rep = _service.egress_report(on, st, gw);
	eq('report: failing', [ rep.ok, rep.fails ], [ false, PT + 1 ]);
	eq('report: other server is unchecked', _service.egress_report(on, st, 'nl1.nordvpn.com').ok, null);
}

// 12. transfer counters and interface uptime in status
{
	const _status = require('nordvpn.status');
	eq('transfer: sums peers', _status.parse_transfer('AAA=\t100\t20\nBBB=\t5\t1\n'), { rx_bytes: 105, tx_bytes: 21 });
	eq('transfer: empty output -> null', _status.parse_transfer(''), null);
	eq('transfer: garbage -> null', _status.parse_transfer('x\ty\tz'), null);

	global.MOCK_UCI = { nordvpn: { main: { '.type': 'instance', interface: 'nordvpn' } },
		network: { nordvpn: { '.type': 'interface', private_key: KEY } } };
	global.MOCK_UBUS = { 'network.interface.nordvpn~status': { up: true, l3_device: 'nordvpn', uptime: 4242 } };
	let st = status(cursor());
	eq('status: uptime from netifd', st.uptime, 4242);
	eq('status: tunnel device', st.device, 'nordvpn');
	global.MOCK_UBUS = { 'network.interface.nordvpn~status': { up: false, l3_device: 'nordvpn', uptime: 4242 } };
	st = status(cursor());
	eq('status: no uptime while down', [ st.uptime, st.transfer ], [ null, null ]);
	global.MOCK_UBUS = {};
}

// 13. event history
{
	const _history = require('nordvpn.history');
	const _apply_m = require('nordvpn.apply');

	let ev = _history.make_event('rotate', { server: 'a', from: 'b', reason: 'schedule', junk: 'x' }, 77);
	eq('event: known fields kept, unknown dropped', ev, { ts: 77, type: 'rotate', server: 'a', from: 'b', reason: 'schedule' });
	eq('event: unknown type refused', _history.make_event('bogus', {}, 1), null);
	let tok = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
	eq('event: token-shaped text redacted', _history.make_event('connect_failed', { error: 'bad ' + tok }, 1).error, 'bad <redacted-token>');
	// Non-hex filler: a long hex run would be redacted before it is clipped.
	let longtxt = '';
	for (let i = 0; i < 200; i++)
		longtxt += 'x';
	eq('event: long text clipped', length(_history.make_event('connect_failed', { error: longtxt }, 1).error), 160);

	let l = [];
	for (let i = 0; i < 7; i++)
		l = _history.append_capped(l, { ts: i }, 5);
	eq('append: capped to newest', map(l, (e) => e.ts), [ 2, 3, 4, 5, 6 ]);
	eq('append: corrupt list tolerated', length(_history.append_capped('junk', { ts: 1 }, 5)), 1);

	let inst = 'nvtest_hist';
	_history.clear_events(inst);
	eq('history: empty when never written', _history.read_events(inst), []);
	_history.record_event(inst, 'connect', { server: 's1' }, 10);
	_history.record_event(inst, 'rotate', { server: 's2', from: 's1', reason: 'schedule' }, 20);
	_history.record_event(inst, 'nonsense', {}, 30);
	let got = _history.read_events(inst);
	eq('history: newest first, invalid skipped', map(got, (e) => e.type), [ 'rotate', 'connect' ]);
	eq('history: limit', length(_history.read_events(inst, 1)), 1);
	for (let i = 0; i < _cmn.HISTORY_MAX + 5; i++)
		_history.record_event(inst, 'watchdog', {}, 100 + i);
	eq('history: file stays capped', length(_history.read_events(inst)), _cmn.HISTORY_MAX);
	_history.clear_events(inst);
	eq('history: cleared', _history.read_events(inst), []);
	eq('history: main keeps the historical path', _history.history_path(null), '/tmp/nordvpn_events.json');

	// Outcome -> event mapping for rotation and apply.
	eq('rot event: success', _rotate.rotation_event({ ok: true, server: 'b', from: 'a' }, 'watchdog'),
		{ type: 'rotate', fields: { server: 'b', from: 'a', reason: 'watchdog' } });
	eq('rot event: lock race not recorded', _rotate.rotation_event({ skipped: true, reason: 'rotation already running' }, 'schedule'), null);
	eq('rot event: skip', _rotate.rotation_event({ skipped: true, reason: 'fixed server configured' }, 'manual').type, 'rotate_skipped');
	let rf = _rotate.rotation_event({ error: 'no working server found', restored: true }, 'schedule');
	eq('rot event: failure keeps the restore note', [ rf.type, rf.fields.detail ], [ 'rotate_failed', 'restored the previous server' ]);
	eq('apply event: success', _apply_m.apply_event({ state: 'success', gateway: 'g' }, 'reconnect'),
		{ type: 'connect', fields: { server: 'g', reason: 'reconnect' } });
	eq('apply event: the source is kept', _apply_m.apply_event({ state: 'success', gateway: 'g' }, 'save').fields.reason, 'save');
	eq('apply event: no source is external', _apply_m.apply_event({ state: 'success', gateway: 'g' }).fields.reason, 'external');
	eq('apply event: an unknown source is external', _apply_m.apply_event({ state: 'failure', error: 'e' }, 'cron; rm -rf').fields.reason, 'external');
	eq('apply event: failure', _apply_m.apply_event({ state: 'failure', error: 'boom' }).fields.error, 'boom');
	eq('apply event: partial failure is a failure', _apply_m.apply_event({ state: 'partial_failure', gateway: 'g', error: 'e' }).type, 'connect_failed');
}

// Multiple instances: the automatic kill switch / IPv6 block belong to the
// instance that made them, and only one instance may route all LAN traffic.
{
	let mkmulti = function(main_auto, media_auto) {
		return {
			nordvpn: {
				main: { '.type': 'instance', interface: 'nordvpn', enabled: '1', auto_routing: main_auto ? '1' : '0', killswitch: '1' },
				media: { '.type': 'instance', interface: 'nv_media', enabled: '1', auto_routing: media_auto ? '1' : '0', killswitch: '1' }
			},
			network: {
				nordvpn: { '.type': 'interface', proto: 'wireguard', private_key: KEY, vpn_type: 'nordvpn' },
				p1: { '.type': 'wireguard_nordvpn', interface: 'nordvpn', endpoint_host: 'x.nordvpn.com' },
				nv_media: { '.type': 'interface', proto: 'wireguard', private_key: KEY, vpn_type: 'nordvpn' },
				p2: { '.type': 'wireguard_nv_media', interface: 'nv_media', endpoint_host: 'y.nordvpn.com' }
			},
			firewall: {
				zlan: { '.type': 'zone', name: 'lan', network: [ 'lan' ] },
				zwan: { '.type': 'zone', name: 'wan', masq: '1', network: [ 'wan' ] }
			}
		};
	};
	let rules = function(role) {
		let out = [];
		for (let k, v in global.MOCK_UCI.firewall)
			if (v.nordvpn_role == role)
				push(out, v.nordvpn_iface || '-');
		return out;
	};
	let S = function(n) { return load_settings(cursor(), n); };

	// Main routes all LAN with a kill switch; media only tunnels.
	global.MOCK_UCI = mkmulti(true, false);
	enforce_routing(cursor(), S('main'));
	eq('multi: main owns its kill switch', rules('killswitch'), [ 'nordvpn' ]);
	eq('multi: main owns its IPv6 block', rules('ipv6block'), [ 'nordvpn' ]);
	enforce_routing(cursor(), S('media'));
	eq('multi: applying media keeps main\'s kill switch', rules('killswitch'), [ 'nordvpn' ]);
	eq('multi: applying media keeps main\'s IPv6 block', rules('ipv6block'), [ 'nordvpn' ]);
	let gone = S('media');
	gone.auto_routing = false; gone.killswitch = false; gone.block_ipv6 = false;
	enforce_routing(cursor(), gone);
	eq('multi: tearing media down keeps main\'s kill switch', rules('killswitch'), [ 'nordvpn' ]);
	ok('multi: main still reports its kill switch', detect_routing(cursor(), S('main'), false).killswitch);
	ok('multi: media reports none', !detect_routing(cursor(), S('media'), false).killswitch);

	// Only one instance may route all LAN traffic; main (first) keeps it.
	global.MOCK_UCI = mkmulti(true, true);
	let dm = detect_routing(cursor(), S('main'), false);
	let dx = detect_routing(cursor(), S('media'), false);
	eq('single owner: main is auto', [ dm.mode, dm.all_lan_owner ], [ 'auto', null ]);
	eq('single owner: media falls back and names the owner', [ dx.mode, dx.all_lan_owner ], [ 'none', 'main' ]);
	enforce_routing(cursor(), S('main'));
	let rx = enforce_routing(cursor(), S('media'));
	ok('single owner: media gets a note', index(join(' ', rx.notes), 'already enabled on instance main') >= 0);
	eq('single owner: media installs no kill switch of its own', rules('killswitch'), [ 'nordvpn' ]);
	ok('single owner: media gets no default route', global.MOCK_UCI.network.p2.route_allowed_ips == null);
	ok('single owner: main has its default route', global.MOCK_UCI.network.p1.route_allowed_ips == '1');
	// A disabled owner does not block: media takes over.
	global.MOCK_UCI.nordvpn.main.enabled = '0';
	eq('single owner: a disabled main frees it', detect_routing(cursor(), S('media'), false).mode, 'auto');

	// Legacy (unowned) rules from an older version.
	global.MOCK_UCI = mkmulti(true, false);
	global.MOCK_UCI.firewall.oldks = { '.type': 'rule', name: 'NordVPN kill switch', src: 'lan', dest: 'wan',
		proto: 'all', target: 'REJECT', nordvpn_managed: '1', nordvpn_role: 'killswitch' };
	ok('legacy: shown for the all-LAN instance before adoption', detect_routing(cursor(), S('main'), false).killswitch);
	enforce_routing(cursor(), S('media'));
	eq('legacy: another instance leaves it alone while main routes all LAN', rules('killswitch'), [ '-' ]);
	enforce_routing(cursor(), S('main'));
	eq('legacy: main adopts it (no duplicate)', rules('killswitch'), [ 'nordvpn' ]);
	global.MOCK_UCI = mkmulti(false, false);
	global.MOCK_UCI.firewall.oldks = { '.type': 'rule', nordvpn_managed: '1', nordvpn_role: 'killswitch', src: 'lan', dest: 'wan', target: 'REJECT' };
	enforce_routing(cursor(), S('media'));
	eq('legacy: dropped once no instance routes all LAN', rules('killswitch'), []);
}

// MARK rules must land in fw4's mangle_prerouting: fw4 only puts a MARK rule
// there for 'src <zone>' with 'dest *'. A rule without 'dest' goes to
// mangle_input and never marks forwarded traffic (older versions wrote
// src '*' with no dest), so an excluded device still took the tunnel.
{
	// fw4's placement (firewall4 fw4.uc, parse_rule, target mark/dscp).
	let fw4_chain = function(r) {
		let any = (z) => z == '*', zone = (z) => z != null && z != '*';
		if ((any(r.src) && any(r.dest)) || (zone(r.src) && zone(r.dest))) return 'mangle_forward';
		if (any(r.src) && zone(r.dest)) return 'mangle_postrouting';
		if (zone(r.src) && any(r.dest)) return 'mangle_prerouting';
		if (r.src && !r.dest) return 'mangle_input';
		return 'mangle_output';
	};
	let D = 'aa:bb:cc:dd:ee:01';
	global.MOCK_UCI = {
		nordvpn: { main: { '.type': 'instance', interface: 'nordvpn', enabled: '1', auto_routing: '1',
			bypass_device: [ D ] } },
		network: {
			lan: { '.type': 'interface', device: 'br-lan', proto: 'static', ipaddr: '192.168.1.1', netmask: '255.255.255.0' },
			nordvpn: { '.type': 'interface', proto: 'wireguard', private_key: KEY, vpn_type: 'nordvpn' },
			p1: { '.type': 'wireguard_nordvpn', interface: 'nordvpn', endpoint_host: 'x.nordvpn.com' }
		},
		firewall: {
			zlan: { '.type': 'zone', name: 'lan', network: [ 'lan' ] },
			zwan: { '.type': 'zone', name: 'wan', masq: '1', network: [ 'wan' ] },
			// A rule as older versions wrote it.
			old: { '.type': 'rule', name: 'NordVPN exception ' + D, src: '*', src_mac: D, proto: 'all',
				target: 'MARK', set_xmark: '0xfe000000/0xff000000', nordvpn_managed: '1',
				nordvpn_role: 'bypass_mark', nordvpn_iface: 'nordvpn' }
		}
	};
	eq('fw4: the old shape lands in mangle_input', fw4_chain(global.MOCK_UCI.firewall.old), 'mangle_input');
	let res = enforce_routing(cursor(), load_settings(cursor(), 'main'), { nftset: true });
	ok('fw4: fixing the old rule changes the firewall', res.changed_firewall);
	let marks = [];
	for (let k, v in global.MOCK_UCI.firewall)
		if (v.target == 'MARK')
			push(marks, v);
	eq('fw4: one exception rule, corrected in place', length(marks), 1);
	eq('fw4: the exception now lands in mangle_prerouting', fw4_chain(marks[0]), 'mangle_prerouting');
	ok('fw4: second run changes nothing', !enforce_routing(cursor(), load_settings(cursor(), 'main'), { nftset: true }).changed_firewall);
}

// DNS lock: with "Route all LAN" and NordVPN DNS, dnsmasq forwards only to the
// NordVPN resolvers (nordvpn.com names excepted, via the WAN's resolver), and
// everything is restored when routing or VPN DNS is turned off.
{
	let mk = function(extra) {
		let main = { '.type': 'instance', interface: 'nordvpn', enabled: '1', auto_routing: '1',
			routing_table: 'nordvpn', vpn_dns: 'standard' };
		for (let k in extra)
			main[k] = extra[k];
		return {
			nordvpn: { main: main },
			network: {
				lan: { '.type': 'interface', device: 'br-lan', proto: 'static', ipaddr: '192.168.1.1', netmask: '255.255.255.0' },
				wan: { '.type': 'interface', device: 'wan', proto: 'dhcp' },
				nordvpn: { '.type': 'interface', proto: 'wireguard', private_key: KEY, vpn_type: 'nordvpn' },
				p1: { '.type': 'wireguard_nordvpn', interface: 'nordvpn', endpoint_host: 'x.nordvpn.com' }
			},
			firewall: {
				zlan: { '.type': 'zone', name: 'lan', network: [ 'lan' ] },
				zwan: { '.type': 'zone', name: 'wan', masq: '1', network: [ 'wan' ] }
			},
			dhcp: { dm: { '.type': 'dnsmasq', server: [ '/home.lan/192.168.1.5' ] } }
		};
	};
	let o = { nftset: true, wan_dns: [ '192.168.10.166' ] };
	let dm = function() { return global.MOCK_UCI.dhcp.dm; };
	let ks = function() {
		let out = [];
		for (let k, v in global.MOCK_UCI.network)
			if (v.nordvpn_role == 'dns_ks')
				push(out, v.dest);
		return sort(out);
	};

	global.MOCK_UCI = mk({});
	let res = enforce_routing(cursor(), load_settings(cursor(), 'main'), o);
	ok('dns lock: reported and dnsmasq restarted', res.dns_locked && res.changed_dhcp);
	eq('dns lock: resolv file ignored', dm().noresolv, '1');
	eq('dns lock: only NordVPN resolvers, nordvpn.com via WAN, own entries kept', dm().server,
		[ '/home.lan/192.168.1.5', '103.86.96.100', '103.86.99.100', '/nordvpn.com/192.168.10.166' ]);
	eq('dns lock: blocked while the tunnel is down', ks(), [ '103.86.96.100/32', '103.86.99.100/32' ]);
	ok('dns lock: idempotent', !enforce_routing(cursor(), load_settings(cursor(), 'main'), o).changed_dhcp);

	// Switching to Threat Protection swaps the resolvers.
	global.MOCK_UCI.nordvpn.main.vpn_dns = 'threat';
	enforce_routing(cursor(), load_settings(cursor(), 'main'), o);
	eq('dns lock: threat protection resolvers', dm().server,
		[ '/home.lan/192.168.1.5', '103.86.96.96', '103.86.99.99', '/nordvpn.com/192.168.10.166' ]);

	// Turning VPN DNS off restores dnsmasq exactly.
	global.MOCK_UCI.nordvpn.main.vpn_dns = 'off';
	enforce_routing(cursor(), load_settings(cursor(), 'main'), o);
	eq('dns lock: released, previous state restored',
		[ dm().noresolv, dm().server, dm().nordvpn_dns_lock, dm().nordvpn_dns_servers ],
		[ null, [ '/home.lan/192.168.1.5' ], null, null ]);
	eq('dns lock: no DNS block rules left', ks(), []);

	// A user's own noresolv=1 survives the lock and its release.
	global.MOCK_UCI = mk({});
	global.MOCK_UCI.dhcp.dm.noresolv = '1';
	global.MOCK_UCI.dhcp.dm.server = [ '9.9.9.9' ];
	res = enforce_routing(cursor(), load_settings(cursor(), 'main'), o);
	ok('dns lock: warns about the user\'s own upstream', index(join(' ', res.notes), '9.9.9.9') >= 0);
	global.MOCK_UCI.nordvpn.main.auto_routing = '0';
	enforce_routing(cursor(), load_settings(cursor(), 'main'), o);
	eq('dns lock: user noresolv and server kept after release', [ dm().noresolv, dm().server ], [ '1', [ '9.9.9.9' ] ]);

	// No WAN resolvers known: no lock (reconnecting would need them).
	global.MOCK_UCI = mk({});
	res = enforce_routing(cursor(), load_settings(cursor(), 'main'), { nftset: true, wan_dns: [] });
	ok('dns lock: skipped without WAN resolvers, with a note', !res.dns_locked && dm().noresolv == null &&
		index(join(' ', res.notes), 'WAN DNS') >= 0);

	// Disabling the instance releases it.
	global.MOCK_UCI = mk({});
	enforce_routing(cursor(), load_settings(cursor(), 'main'), o);
	global.MOCK_UCI.nordvpn.main.enabled = '0';
	enforce_routing(cursor(), load_settings(cursor(), 'main'), o);
	eq('dns lock: disabled instance releases it', [ dm().noresolv, dm().nordvpn_dns_lock ], [ null, null ]);
}

// Excluded devices keep the WAN's DNS: a DHCP option 6 per MAC and a DNAT of
// their plain DNS to the WAN resolver, only while NordVPN DNS is on.
{
	let D = '4e:82:91:17:24:d5';
	let mk = function() {
		return {
			nordvpn: { main: { '.type': 'instance', interface: 'nordvpn', enabled: '1', auto_routing: '1',
				routing_table: 'nordvpn', vpn_dns: 'standard', bypass_device: [ D ] } },
			network: {
				lan: { '.type': 'interface', device: 'br-lan', proto: 'static', ipaddr: '192.168.1.1', netmask: '255.255.255.0' },
				wan: { '.type': 'interface', device: 'wan', proto: 'dhcp' },
				nordvpn: { '.type': 'interface', proto: 'wireguard', private_key: KEY, vpn_type: 'nordvpn' },
				p1: { '.type': 'wireguard_nordvpn', interface: 'nordvpn', endpoint_host: 'x.nordvpn.com' }
			},
			firewall: {
				zlan: { '.type': 'zone', name: 'lan', network: [ 'lan' ] },
				zwan: { '.type': 'zone', name: 'wan', masq: '1', network: [ 'wan' ] }
			},
			dhcp: { dm: { '.type': 'dnsmasq' } }
		};
	};
	let find = function(pkg, role) {
		let out = [];
		for (let k, v in global.MOCK_UCI[pkg])
			if (v.nordvpn_role == role)
				push(out, v);
		return out;
	};
	let o = { nftset: true, wan_dns: [ '192.168.10.166', 'fd00::1' ] };

	global.MOCK_UCI = mk();
	let res = enforce_routing(cursor(), load_settings(cursor(), 'main'), o);
	let rd = find('firewall', 'bypass_dns_redirect'), dh = find('dhcp', 'bypass_dhcp_dns');
	ok('exc dns: one DNAT for the excluded device', length(rd) == 1 && rd[0].src_mac == D &&
		rd[0].src == 'lan' && rd[0].dest == 'wan' && rd[0].target == 'DNAT' && rd[0].src_dport == '53' &&
		rd[0].dest_ip == '192.168.10.166' && rd[0].family == 'ipv4' && rd[0].proto == 'tcp udp');
	ok('exc dns: DHCP hands it the IPv4 WAN resolver under its own tag', length(dh) == 1 && dh[0].mac == D &&
		dh[0].networkid == 'nvx4e82911724d5' && sprintf('%J', dh[0].dhcp_option) == sprintf('%J', [ '6,192.168.10.166' ]));
	ok('exc dns: firewall and dnsmasq reloaded', res.changed_firewall && res.changed_dhcp);
	ok('exc dns: idempotent', (function() {
		let r = enforce_routing(cursor(), load_settings(cursor(), 'main'), o);
		return !r.changed_firewall && !r.changed_dhcp;
	})());

	// The WAN resolver changes: both follow.
	enforce_routing(cursor(), load_settings(cursor(), 'main'), { nftset: true, wan_dns: [ '192.168.10.1' ] });
	rd = find('firewall', 'bypass_dns_redirect'); dh = find('dhcp', 'bypass_dhcp_dns');
	eq('exc dns: follows a new WAN resolver', [ rd[0].dest_ip, dh[0].dhcp_option ], [ '192.168.10.1', [ '6,192.168.10.1' ] ]);

	// Un-excluding the device removes both.
	delete global.MOCK_UCI.nordvpn.main.bypass_device;
	enforce_routing(cursor(), load_settings(cursor(), 'main'), o);
	eq('exc dns: removed with the exclusion', [ length(find('firewall', 'bypass_dns_redirect')), length(find('dhcp', 'bypass_dhcp_dns')) ], [ 0, 0 ]);

	// VPN DNS off: excluded devices need nothing special.
	global.MOCK_UCI = mk();
	global.MOCK_UCI.nordvpn.main.vpn_dns = 'off';
	enforce_routing(cursor(), load_settings(cursor(), 'main'), o);
	eq('exc dns: nothing without VPN DNS', [ length(find('firewall', 'bypass_dns_redirect')), length(find('dhcp', 'bypass_dhcp_dns')) ], [ 0, 0 ]);

	// No IPv4 WAN resolver: nothing, with a note.
	global.MOCK_UCI = mk();
	res = enforce_routing(cursor(), load_settings(cursor(), 'main'), { nftset: true, wan_dns: [ 'fd00::1' ] });
	ok('exc dns: skipped without an IPv4 WAN resolver', length(find('firewall', 'bypass_dns_redirect')) == 0 &&
		index(join(' ', res.notes), 'excluded devices') >= 0);
}

// 12. Locks name their holder: a lock left by a killed worker is reclaimed at
//     once instead of after its whole age, a live holder's never is.
{
	let lp = '/tmp/nordvpn_test_' + time() + '.lock';
	let own = _cmn.self_pid();
	ok('lock: own pid known', type(own) == 'int' && own > 0);
	let t = _cmn.acquire_lock(lp, 600);
	ok('lock: taken', t != null);
	ok('lock: records time and pid', match(readfile(lp), /^[0-9]+ [0-9]+\n$/) != null);
	ok('lock: a live holder keeps it', _cmn.acquire_lock(lp, 600) == null);
	writefile(lp, sprintf('%d %d\n', time(), 1073741824));
	ok('lock: a dead holder is detected', _cmn.lock_stale(lp, 600) == true);
	ok('lock: a dead holder\'s lock is reclaimed', _cmn.acquire_lock(lp, 600) != null);
	// Locks written by older versions carry no pid: the age rule alone applies.
	writefile(lp, sprintf('%d\n', time()));
	ok('lock: a pid-less lock is not stale while young', _cmn.lock_stale(lp, 600) == false);
	ok('lock: a missing lock is not stale', _cmn.lock_stale(lp + '.none', 600) == false);
	_cmn.release_lock(lp);

	// The rotation lock's age follows the instance's worst case.
	eq('lock: default rotation ceiling', _cmn.rotation_max_runtime({ max_retries: 10, verify_timeout: 8 }), 300);
	eq('lock: slow rotation ceiling', _cmn.rotation_max_runtime({ max_retries: 50, verify_timeout: 30 }), 2060);
	eq('lock: ceiling is capped', _cmn.rotation_max_runtime({ max_retries: 500, verify_timeout: 30 }), 3600);
	eq('lock: missing settings fall back', _cmn.rotation_max_runtime(null), 300);
}

// 13. Refresh status: a 'running' record whose worker is gone must not lock
//     the refresh button (and every new refresh) forever.
{
	let FETCH_STATUS = '/tmp/nordvpn_fetch_status.json';
	let now = time();
	ok('fetch: a fresh running record is running', _cache.fetch_running({ state: 'running',
		updated_at_epoch: now, pid: _cmn.self_pid() }, now) == true);
	ok('fetch: a dead worker is not running', _cache.fetch_running({ state: 'running',
		updated_at_epoch: now, pid: 1073741824 }, now) == false);
	ok('fetch: a stalled record is not running', _cache.fetch_running({ state: 'running',
		updated_at_epoch: now - _cache.FETCH_STALL - 1 }, now) == false);
	ok('fetch: a record from the future is not running', _cache.fetch_running({ state: 'running',
		updated_at_epoch: now + 3600 }, now) == false);
	ok('fetch: a record without a stamp is not running', _cache.fetch_running({ state: 'running' }, now) == false);
	ok('fetch: a finished record is not running', _cache.fetch_running({ state: 'done',
		updated_at_epoch: now }, now) == false);

	_cache.write_fetch_status({ state: 'running', pages: 3 });
	let st = _cache.read_fetch_status();
	ok('fetch: records carry the writer and a stamp', st.pid == _cmn.self_pid() && type(st.updated_at_epoch) == 'int');
	eq('fetch: a live refresh reports running', _cache.fetch_status_report().state, 'running');
	writefile(FETCH_STATUS, sprintf('%J', { ...st, pid: 1073741824 }));
	let rep = _cache.fetch_status_report();
	eq('fetch: a dead refresh reports an error', [ rep.state, rep.stale, rep.pages ], [ 'error', true, 3 ]);
	_cache.write_fetch_status({ state: 'done' });
	eq('fetch: a finished record carries no pid', _cache.read_fetch_status().pid, null);
	unlink(FETCH_STATUS);
	eq('fetch: no record reports null', _cache.fetch_status_report(), null);
}

// 14. Staleness of a parsed cache, without reading the file again.
{
	let now = time();
	let c = { schema_version: 1, cached_at: now - 60, groups: true };
	ok('stale: a fresh cache is not stale', _cache.is_stale(c, now) == false);
	ok('stale: an old cache is stale', _cache.is_stale({ ...c, cached_at: now - 86401 }, now) == true);
	ok('stale: a cache without group flags is stale', _cache.is_stale({ ...c, groups: null }, now) == true);
	ok('stale: another schema is stale', _cache.is_stale({ ...c, schema_version: 99 }, now) == true);
	ok('stale: no cache is stale', _cache.is_stale(null, now) == true);
	ok('stale: the file check agrees', _cache.cache_is_stale(cpath) == _cache.is_stale(_cache.read_cache(cpath)));
}

unlink(cpath);
printf('\n%s\n', fails ? ('FAILURES: ' + fails) : 'ALL PHASE-3 TESTS PASSED');
exit(fails ? 1 : 0);
