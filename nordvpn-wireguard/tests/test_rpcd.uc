#!/usr/bin/ucode -S
// SPDX-License-Identifier: MIT
// Integration test for the rpcd ubus object. loadfile()s the object and calls
// its methods against the mock uci/ubus and a fixture-built cache. Globals
// `RPCD`, `fixture` and `KEY` are supplied by run.sh.

'use strict';

import { readfile, mkdir, unlink } from 'fs';
const _cache = require('nordvpn.cache');
const normalize = _cache.normalize, write_cache = _cache.write_cache;
const _common = require('nordvpn.common');
const _apply_mod = require('nordvpn.apply');
const _creds = require('nordvpn.credentials');
import { cursor } from 'uci';

// Our own pid: the one process guaranteed alive while the apply-status
// liveness check runs.
const self_pid = int(split(trim(readfile('/proc/self/stat') || '0 '), ' ')[0]);

let fails = 0;
function ok(l, c) { if (c) printf('ok   %s\n', l); else { fails++; printf('FAIL %s\n', l); } }
function eq(l, g, w) { ok(l, sprintf('%J', g) == sprintf('%J', w)); }

// Load the rpcd program; its top-level return is { nordvpn: methods }.
let obj = loadfile(RPCD)();
let m = obj ? obj.nordvpn : null;
ok('rpcd object present', m != null);
ok('read methods present', type(m.status.call) == 'function' && type(m.locations.call) == 'function' && type(m.refresh_status.call) == 'function' && type(m.instances.call) == 'function' && type(m.apply_status.call) == 'function');
ok('write methods present', type(m.set_credentials.call) == 'function' && type(m.apply.call) == 'function' && type(m.apply_start.call) == 'function' && type(m.apply_routing.call) == 'function' && type(m.rotate_now.call) == 'function' && type(m.rotate_start.call) == 'function' && type(m.refresh_locations.call) == 'function' && type(m.disconnect.call) == 'function' && type(m.clear_credentials.call) == 'function');

// Build a cache on disk.
let cache = normalize(json(readfile(fixture)));
let cdir = '/tmp/nvrpcd_' + time();
mkdir(cdir);
write_cache(cache, cdir + '/nordvpn_servers_cache.json');

// status: not configured
global.MOCK_UCI = { nordvpn: { main: { '.type': 'settings', interface: 'nordvpn', cache_dir: cdir } }, network: {} };
global.MOCK_UBUS = {};
eq('status not_configured', m.status.call().state, 'not_configured');
eq('status rejects unknown instance', m.status.call({ args: { instance: 'nope' } }).error, 'no such instance');
eq('instances lists main', length(m.instances.call().instances), 1);

// locations from cache
let loc = m.locations.call();
eq('locations available', loc.available, true);
eq('locations ready', loc.state, 'ready');
eq('locations country count', length(loc.countries), 3);

// servers: legacy city call, and the union call for a location set
let srv_legacy = m.servers.call({ args: { country: 'ee', city: 'ee-tallinn', hop_mode: 'single' } });
eq('servers legacy returns ee relays', length(srv_legacy.relays), 1);
let srv_union = m.servers.call({ args: { locations: [ 'ee', 'us' ], hop_mode: 'single' } });
eq('servers union of two countries', length(srv_union.relays), 2);
ok('servers union carries grouping fields', srv_union.relays[0].country_code != null && srv_union.relays[0].city_code != null && srv_union.relays[0].city != null);
let srv_dedup = m.servers.call({ args: { locations: [ 'nl', 'nl-amsterdam' ], hop_mode: 'multihop' } });
eq('servers union dedups city inside country', length(srv_dedup.relays), 1);
eq('servers union empty set yields nothing', length(m.servers.call({ args: { locations: [], hop_mode: 'single' } }).relays), 0);

// The tree is memoized per cache file: a repeat call answers the same, and a
// rewritten cache (a refresh) is picked up.
eq('locations memo answers the same', m.locations.call(), loc);
{
	let fewer = normalize(filter(json(readfile(fixture)), function(sv) {
		return sv.locations && sv.locations[0] && sv.locations[0].country &&
			sv.locations[0].country.code == 'EE';
	}));
	write_cache(fewer, cdir + '/nordvpn_servers_cache.json');
	eq('locations follow a rewritten cache', length(m.locations.call().countries), 1);
	write_cache(cache, cdir + '/nordvpn_servers_cache.json');
	eq('locations follow it back', length(m.locations.call().countries), 3);
}
eq('rotate_start rejects unknown instance', m.rotate_start.call({ args: { instance: 'nope' } }).error, 'no such instance');

// refresh_status idle when no job file
eq('refresh_status idle', m.refresh_status.call().state, 'idle');

// set_credentials rejects a malformed token (never reaches the network)
eq('set_credentials bad token', m.set_credentials.call({ args: { token: 'nope' } }).error, 'invalid token format');

// apply chooses a server for the configured selection
global.MOCK_UCI = { nordvpn: { main: { '.type': 'settings', interface: 'nordvpn',
	country_code: 'ee', city_code: '', hop_mode: 'single', cache_dir: cdir } },
	network: { nordvpn: { '.type': 'interface', private_key: KEY } } };
ok('apply returns a state object', m.apply.call().state != null);

// apply_start / apply_status: the pair the UI uses instead of the blocking
// `apply`. The synchronous method stays, but the page must be able to start an
// apply and poll it, and a poll must never come back null.
{
	unlink(_common.APPLY_STATUS_FILE);
	eq('apply_status idle without a job file', m.apply_status.call({}).state, 'idle');
	eq('apply_start rejects an unknown instance',
		m.apply_start.call({ args: { instance: 'nope' } }).error, 'no such instance');

	// A running apply is visible to the poller and blocks a second start —
	// two applies would rewrite the same interface and commit the same config.
	let now = time();
	_apply_mod.write_apply_status({ instance: 'main', state: 'running',
		pid: self_pid, started_at: _common.iso_ts(now), started_at_epoch: now,
		finished_at: null, result: null, error: null });
	eq('apply_status reports a running apply', m.apply_status.call({}).state, 'running');
	let busy = m.apply_start.call({ args: { instance: 'main' } });
	eq('apply_start refuses to stack applies', busy.already_running, true);
	eq('apply_start names the instance holding it', busy.apply.instance, 'main');

	// The finished record is what the UI turns into its result banner, so the
	// full apply() result has to survive the round trip through the file.
	_apply_mod.write_apply_status({ instance: 'main', state: 'failed',
		started_at: _common.iso_ts(now), started_at_epoch: now,
		finished_at: _common.iso_ts(now), pid: null,
		result: { state: 'failure', error: 'no credentials configured' },
		error: 'no credentials configured' });
	let done = m.apply_status.call({});
	eq('apply_status reports the terminal state', done.state, 'failed');
	eq('apply_status carries the apply result', done.result.state, 'failure');
	eq('apply_status carries the error', done.error, 'no credentials configured');

	unlink(_common.APPLY_STATUS_FILE);
	eq('apply_status idle again', m.apply_status.call({}).state, 'idle');
}

// rotate_now is a no-op when a fixed server is pinned
global.MOCK_UCI = { nordvpn: { main: { '.type': 'settings', interface: 'nordvpn',
	fixed_server: 'ee70.nordvpn.com', cache_dir: cdir } },
	network: { nordvpn: { '.type': 'interface', private_key: KEY } } };
ok('rotate_now skipped with fixed server', m.rotate_now.call().skipped == true);

// disconnect pauses the instance, releases managed routing objects
global.MOCK_UCI = { nordvpn: { main: { '.type': 'settings', interface: 'nordvpn', enabled: '1',
	routing_table: 'nvx', source_network: 'lan', cache_dir: cdir } },
	network: {
		nordvpn: { '.type': 'interface', private_key: KEY, auto: '1', nordvpn_managed_routing: '1',
			vpn_type: 'nordvpn' },
		steerrule: { '.type': 'rule', 'in': 'lan', lookup: 'nvx',
			nordvpn_managed: '1', nordvpn_role: 'steer_lookup', nordvpn_iface: 'nordvpn' }
	}, firewall: {} };
ok('disconnect ok', m.disconnect.call({}).ok == true);
eq('disconnect flips master switch off', global.MOCK_UCI.nordvpn.main.enabled, '0');
eq('disconnect keeps the interface down', global.MOCK_UCI.network.nordvpn.auto, '0');
ok('disconnect releases steering rules', global.MOCK_UCI.network.steerrule == null);
ok('clear_credentials ok', m.clear_credentials.call({}).ok == true);
ok('clear_credentials removes the key', global.MOCK_UCI.network.nordvpn.private_key == null);

// The `interface` option is user-writable (LuCI ACL on the nordvpn config), so
// no write method may touch a network interface the app does not own.
{
	let wan = { '.type': 'interface', proto: 'dhcp', device: 'eth1', auto: '1' };
	let wanpeer = { '.type': 'wireguard_wan', interface: 'wan', public_key: 'x' };
	global.MOCK_UCI = { nordvpn: { main: { '.type': 'instance', interface: 'wan', enabled: '1',
		cache_dir: cdir } }, network: { wan: { ...wan }, wanpeer: { ...wanpeer } }, firewall: {} };
	ok('set_credentials refuses a foreign interface',
		index(m.set_credentials.call({ args: { token: sprintf('%064d', 1) } }).error || '', 'not managed') >= 0);
	ok('apply refuses a foreign interface', index(m.apply.call().error || '', 'not managed') >= 0);
	ok('rotate_now refuses a foreign interface', index(m.rotate_now.call().error || '', 'not managed') >= 0);
	ok('disconnect refuses a foreign interface', index(m.disconnect.call({}).error || '', 'not managed') >= 0);
	ok('clear_credentials refuses a foreign interface', index(m.clear_credentials.call({}).error || '', 'not managed') >= 0);
	eq('foreign interface left untouched', global.MOCK_UCI.network.wan, wan);
	eq('foreign enabled flag untouched', global.MOCK_UCI.nordvpn.main.enabled, '1');

	global.MOCK_UCI.nordvpn.extra2 = { '.type': 'instance', interface: 'wan' };
	ok('delete_instance still removes the section', m.delete_instance.call({ args: { instance: 'extra2' } }).ok == true);
	ok('instance section gone', global.MOCK_UCI.nordvpn.extra2 == null);
	eq('delete_instance keeps the foreign interface', global.MOCK_UCI.network.wan, wan);
	eq('delete_instance keeps the foreign peer', global.MOCK_UCI.network.wanpeer, wanpeer);
}

// overview: the Status-page card's summary. Cheap (no routing detection) and,
// like every read method, free of secrets.
{
	let saved_uci = global.MOCK_UCI, saved_ubus = global.MOCK_UBUS;
	global.MOCK_UCI = { nordvpn: {
			main: { '.type': 'instance', interface: 'nordvpn', cache_dir: cdir, enabled: '1' },
			second: { '.type': 'instance', interface: 'nv_second', enabled: '0' } },
		network: {
			nordvpn: { '.type': 'interface', private_key: KEY, vpn_type: 'nordvpn',
				nordvpn_country_code: 'ee', nordvpn_location: 'ee-tallinn' },
			peer: { '.type': 'wireguard_nordvpn', interface: 'nordvpn',
				nordvpn_gateway: 'ee70.nordvpn.com', public_key: KEY } } };
	global.MOCK_UBUS = { 'network.interface.nordvpn~status': { up: true, l3_device: 'nordvpn', uptime: 42 } };
	let open_before = global.MOCK_UBUS_OPEN || 0;
	let ov = m.overview.call();
	eq('overview: one entry per instance, main first', map(ov.instances, (i) => i.instance), [ 'main', 'second' ]);
	let o = ov.instances[0];
	eq('overview: runtime fields', [ o.configured, o.enabled, o.gateway, o.uptime, o.location ],
		[ true, true, 'ee70.nordvpn.com', 42, { country: 'ee', city: 'ee-tallinn' } ]);
	eq('overview: up without a handshake reads connecting', o.state, 'connecting');
	eq('overview: unconfigured instance', [ ov.instances[1].state, ov.instances[1].configured ], [ 'not_configured', false ]);
	ok('overview: no routing detection', o.routing == null && o.rotation == null);
	ok('overview: no secret in the response', index(sprintf('%J', ov), KEY) < 0);
	eq('overview: ubus connections closed', global.MOCK_UBUS_OPEN || 0, open_before);
	global.MOCK_UCI = saved_uci;
	global.MOCK_UBUS = saved_ubus;
}

// external_ip: NordVPN's verdict through the tunnel, plus the LAN path in
// all-LAN mode. `run` is stubbed so nothing touches the network.
{
	let saved_uci = global.MOCK_UCI, real_run = _common.run;
	let urls = [];
	_common.run = function(argv) {
		if (argv[0] != 'curl')
			return real_run(argv);
		push(urls, argv[length(argv) - 1]);
		return (index(argv, '--interface') >= 0)
			? { code: 0, stdout: '{"ip":"198.51.100.7","protected":true,"city":"Frankfurt",' +
				'"country":"Germany","country_code":"DE","isp":"Exit Networks"}' }
			: { code: 0, stdout: '{"ip":"203.0.113.9","protected":false,"isp":"Home ISP"}' };
	};
	global.MOCK_UCI = { nordvpn: { main: { '.type': 'instance', interface: 'nordvpn', enabled: '1',
			auto_routing: '1', cache_dir: cdir } },
		network: { nordvpn: { '.type': 'interface', private_key: KEY, vpn_type: 'nordvpn' } },
		firewall: {} };
	let r = m.external_ip.call({});
	eq('external_ip: tunnel verdict', [ r.ip, r.protected, r.city, r.country_code, r.isp, r.interface ],
		[ '198.51.100.7', true, 'Frankfurt', 'de', 'Exit Networks', 'nordvpn' ]);
	eq('external_ip: all-LAN mode also checks the LAN path', r.lan_path,
		{ protected: false, ip: '203.0.113.9', isp: 'Home ISP' });
	eq('external_ip: only NordVPN is asked', uniq(urls), [ _common.IP_INSIGHTS_URL ]);

	// With a table the LAN is steered into it; the router's own request would
	// take the WAN and raise a false alarm, so no LAN-path probe.
	urls = [];
	global.MOCK_UCI.nordvpn.main.routing_table = '100';
	r = m.external_ip.call({});
	ok('external_ip: all-LAN with a table skips the LAN-path probe', r.lan_path == null && length(urls) == 1);
	urls = [];
	delete global.MOCK_UCI.nordvpn.main.routing_table;
	global.MOCK_UCI.nordvpn.main.bypass_device = 'aa:bb:cc:dd:ee:01';
	r = m.external_ip.call({});
	ok('external_ip: ... also with the implicit table of exceptions', r.lan_path == null && length(urls) == 1);
	delete global.MOCK_UCI.nordvpn.main.bypass_device;

	urls = [];
	global.MOCK_UCI.nordvpn.main.auto_routing = '0';
	global.MOCK_UCI.nordvpn.main.source_network = 'lan';
	global.MOCK_UCI.nordvpn.main.routing_table = '100';
	r = m.external_ip.call({});
	ok('external_ip: steered mode skips the LAN-path probe', r.lan_path == null && length(urls) == 1);

	_common.run = function(argv) { return (argv[0] == 'curl') ? { code: 7, stdout: '' } : real_run(argv); };
	eq('external_ip: unreachable', m.external_ip.call({}).error, 'could not determine the external IP');
	_common.run = real_run;
	global.MOCK_UCI = saved_uci;
}

// clients: read-only picker source; always an array (empty off-device).
ok('clients method present', type(m.clients.call) == 'function');
ok('clients returns an array', type(m.clients.call().clients) == 'array');

// instance lifecycle: create -> listed -> delete; main is protected
ok('create_instance ok', m.create_instance.call({ args: { instance: 'extra' } }).ok == true);
ok('create rejects duplicate', m.create_instance.call({ args: { instance: 'extra' } }).error != null);
ok('create rejects bad name', m.create_instance.call({ args: { instance: 'no way' } }).error != null);
eq('instances lists both', length(m.instances.call().instances), 2);
ok('delete_instance ok', m.delete_instance.call({ args: { instance: 'extra' } }).ok == true);
eq('instances back to one', length(m.instances.call().instances), 1);

// credential bank: shared 'default' key, named extras, migration, sync
{
	const _api = require('nordvpn.api');
	const real_key = _api.get_private_key;
	const KEY2 = sprintf('%042dY=', 2);
	let next_key = KEY;
	_api.get_private_key = function(token) { return { private_key: next_key }; };
	let tok = sprintf('%064d', 7);
	let saved_uci = global.MOCK_UCI;

	// An upgrade: two instances with the same key, one with its own.
	global.MOCK_UCI = {
		nordvpn: {
			main: { '.type': 'instance', interface: 'nordvpn', cache_dir: cdir },
			tv: { '.type': 'instance', interface: 'nv_tv' },
			work: { '.type': 'instance', interface: 'nv_work' }
		},
		network: {
			nordvpn: { '.type': 'interface', proto: 'wireguard', private_key: KEY, vpn_type: 'nordvpn' },
			nv_tv: { '.type': 'interface', proto: 'wireguard', private_key: KEY, vpn_type: 'nordvpn' },
			nv_work: { '.type': 'interface', proto: 'wireguard', private_key: KEY2, vpn_type: 'nordvpn' }
		}
	};
	let b = m.credentials.call().credentials;
	eq('before migration: default listed, not configured', [ b[0].id, b[0].name, b[0].configured ], [ 'default', 'Default', false ]);
	ok('migration ran', _creds.migrate(cursor()) == true);
	ok('migration is idempotent', _creds.migrate(cursor()) == false);
	eq('main key became Default', global.MOCK_UCI.nordvpn_credentials['default'].private_key, KEY);
	eq('same key shares default', global.MOCK_UCI.nordvpn.tv.credential, null);
	eq('a different key gets its own entry', global.MOCK_UCI.nordvpn.work.credential, 'work');
	eq('the entry holds that key', global.MOCK_UCI.nordvpn_credentials.work.private_key, KEY2);
	b = m.credentials.call().credentials;
	eq('bank lists default then work', map(b, (e) => e.id), [ 'default', 'work' ]);
	eq('usage per entry', map(b, (e) => e.instances), [ [ 'main', 'tv' ], [ 'work' ] ]);
	ok('the bank never returns a key', index(sprintf('%J', b), KEY) < 0 && index(sprintf('%J', b), KEY2) < 0);

	// New instances default to the shared credentials.
	let r = m.create_instance.call({ args: { instance: 'media' } });
	ok('new instance uses default and is configured', r.ok == true && r.credential == 'default' && r.configured == true);
	eq('its interface carries the default key', global.MOCK_UCI.network.nv_media.private_key, KEY);
	eq('it is a managed wireguard interface',
		[ global.MOCK_UCI.network.nv_media.proto, global.MOCK_UCI.network.nv_media.vpn_type ], [ 'wireguard', 'nordvpn' ]);
	r = m.create_instance.call({ args: { instance: 'lab', credential: 'work' } });
	ok('an instance can start on another entry', r.ok == true && global.MOCK_UCI.network.nv_lab.private_key == KEY2);
	ok('an unknown entry is refused and nothing is created',
		m.create_instance.call({ args: { instance: 'ghost', credential: 'nope' } }).error != null && global.MOCK_UCI.nordvpn.ghost == null);

	// Replacing the default key reaches every instance on it, and only those.
	next_key = sprintf('%042dZ=', 3);
	r = m.set_credentials.call({ args: { token: tok, credential: 'default' } });
	ok('replace default ok', r.ok == true && r.name == 'Default');
	eq('all default users follow',
		[ global.MOCK_UCI.network.nordvpn.private_key, global.MOCK_UCI.network.nv_tv.private_key, global.MOCK_UCI.network.nv_media.private_key ],
		[ next_key, next_key, next_key ]);
	eq('other entries are untouched', global.MOCK_UCI.network.nv_work.private_key, KEY2);

	// Adding a named entry; names are unique.
	next_key = sprintf('%042dW=', 4);
	r = m.set_credentials.call({ args: { token: tok, name: 'Family plan' } });
	ok('named entry added', r.ok == true && r.credential == 'family_plan' && r.name == 'Family plan');
	ok('a duplicate name is refused', m.set_credentials.call({ args: { token: tok, name: 'family PLAN' } }).error != null);
	ok('an unknown entry is refused', m.set_credentials.call({ args: { token: tok, credential: 'nope' } }).error != null);

	// Switching an instance to another entry takes effect on sync (apply).
	global.MOCK_UCI.nordvpn.tv.credential = 'family_plan';
	eq('sync reports the change', _creds.sync_instance(cursor(), 'tv'), 'set');
	eq('the instance now has that key', global.MOCK_UCI.network.nv_tv.private_key, next_key);

	// Removing: in-use entries are refused, unused ones go, default keeps its name.
	ok('an entry in use cannot be removed', index(m.remove_credentials.call({ args: { credential: 'family_plan' } }).error || '', 'tv') >= 0);
	delete global.MOCK_UCI.nordvpn.tv.credential;
	ok('an unused entry is removed', m.remove_credentials.call({ args: { credential: 'family_plan' } }).ok == true &&
		global.MOCK_UCI.nordvpn_credentials.family_plan == null);
	ok('removing default drops only its key', m.remove_credentials.call({ args: { credential: 'default' } }).ok == true &&
		global.MOCK_UCI.nordvpn_credentials['default'].name == 'Default' && global.MOCK_UCI.nordvpn_credentials['default'].private_key == null);
	eq('default users lose the key', [ global.MOCK_UCI.network.nordvpn.private_key, global.MOCK_UCI.network.nv_media.private_key ], [ null, null ]);
	eq('others keep theirs', global.MOCK_UCI.network.nv_work.private_key, KEY2);

	// The migration runs once. Every apply, service start and most rpcd calls
	// run migrate(); a cleared Default must stay cleared rather than being
	// refilled from another entry's key, which also moved 'work' onto it.
	ok('migration does not run again', _creds.migrate(cursor()) == false);
	eq('default stays without a key', global.MOCK_UCI.nordvpn_credentials['default'].private_key, null);
	eq('work stays on its entry', global.MOCK_UCI.nordvpn.work.credential, 'work');
	eq('main is not handed work\'s key', _creds.sync_instance(cursor(), 'main'), null);
	eq('main still has no key', global.MOCK_UCI.network.nordvpn.private_key, null);
	eq('the bank still lists both', map(m.credentials.call().credentials, (e) => [ e.id, e.configured ]),
		[ [ 'default', false ], [ 'work', true ] ]);

	// A fresh install: nothing to move, but the bank is stamped, so adding a
	// named entry first never gets folded into Default later.
	global.MOCK_UCI = {
		nordvpn: {
			main: { '.type': 'instance', interface: 'nordvpn', cache_dir: cdir },
			lab: { '.type': 'instance', interface: 'nv_lab' }
		},
		network: {}
	};
	ok('fresh install: nothing moved', _creds.migrate(cursor()) == false);
	eq('fresh install: stamped', global.MOCK_UCI.nordvpn_credentials._state.migrated, '1');
	next_key = KEY2;
	r = m.set_credentials.call({ args: { token: tok, name: 'Lab' } });
	ok('named entry first', r.ok == true && r.credential == 'lab');
	global.MOCK_UCI.nordvpn.lab.credential = 'lab';
	eq('lab gets its key', _creds.sync_instance(cursor(), 'lab'), 'set');
	ok('later calls move nothing', _creds.migrate(cursor()) == false);
	eq('default still empty', global.MOCK_UCI.nordvpn_credentials['default'], null);
	eq('lab still on its own entry', global.MOCK_UCI.nordvpn.lab.credential, 'lab');

	// A router already running the bank (from before the stamp): only stamped.
	global.MOCK_UCI = {
		nordvpn: {
			main: { '.type': 'instance', interface: 'nordvpn', cache_dir: cdir },
			work: { '.type': 'instance', interface: 'nv_work', credential: 'work' }
		},
		nordvpn_credentials: {
			'default': { '.type': 'credential', name: 'Default' },
			work: { '.type': 'credential', name: 'work', private_key: KEY2 }
		},
		network: {
			nv_work: { '.type': 'interface', proto: 'wireguard', private_key: KEY2, vpn_type: 'nordvpn' }
		}
	};
	ok('existing bank: nothing moved', _creds.migrate(cursor()) == false);
	eq('existing bank: stamped', global.MOCK_UCI.nordvpn_credentials._state.migrated, '1');
	eq('existing bank: default untouched', global.MOCK_UCI.nordvpn_credentials['default'].private_key, null);
	eq('existing bank: work untouched', global.MOCK_UCI.nordvpn.work.credential, 'work');

	_api.get_private_key = real_key;
	global.MOCK_UCI = saved_uci;
}

// deleting 'main' resets it to defaults instead of removing the section
global.MOCK_UCI = { nordvpn: { main: { '.type': 'settings', interface: 'nordvpn',
	country_code: 'de', rotation_enabled: '1', config_version: '1', cache_dir: cdir } },
	network: { nordvpn: { '.type': 'interface', private_key: KEY, vpn_type: 'nordvpn' } } };
let rr = m.delete_instance.call({ args: { instance: 'main' } });
ok('main reset ok', rr.ok == true && rr.reset == 'main');
ok('main section kept', global.MOCK_UCI.nordvpn.main != null);
ok('main options wiped', global.MOCK_UCI.nordvpn.main.country_code == null && global.MOCK_UCI.nordvpn.main.rotation_enabled == null);
eq('migration stamp kept', global.MOCK_UCI.nordvpn.main.config_version, '1');
ok('main network interface removed', global.MOCK_UCI.network.nordvpn == null);

// history: events recorded by the write methods, newest first; egress report
{
	unlink('/tmp/nordvpn_events.json');
	global.MOCK_UCI = { nordvpn: { main: { '.type': 'instance', interface: 'nordvpn', cache_dir: cdir, enabled: '1' } },
		network: { nordvpn: { '.type': 'interface', private_key: KEY, vpn_type: 'nordvpn' } } };
	global.MOCK_UBUS = {};
	eq('history: empty at first', m.history.call({ args: {} }).events, []);
	m.disconnect.call({});
	m.clear_credentials.call({});
	let h = m.history.call({ args: { instance: 'main' } });
	eq('history: write methods recorded, newest first', map(h.events, (e) => e.type), [ 'credentials_cleared', 'disabled' ]);
	eq('history: limit honoured', length(m.history.call({ args: { limit: 1 } }).events), 1);
	eq('history: unknown instance', m.history.call({ args: { instance: 'nope' } }).error, 'no such instance');

	eq('status: egress report off by default', m.status.call({}).egress, { enabled: false });
	global.MOCK_UCI.nordvpn.main.egress_probe = '1';
	let eg = m.status.call({}).egress;
	eq('status: egress report on, not yet checked', [ eg.enabled, eg.ok ], [ true, null ]);
	unlink('/tmp/nordvpn_events.json');
}

printf('\n%s\n', fails ? ('FAILURES: ' + fails) : 'ALL RPCD TESTS PASSED');
exit(fails ? 1 : 0);
