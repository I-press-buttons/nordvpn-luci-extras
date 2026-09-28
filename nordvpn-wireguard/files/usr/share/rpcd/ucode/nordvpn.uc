#!/usr/bin/env ucode
// SPDX-License-Identifier: MIT
// rpcd ubus object 'nordvpn'. Thin glue over the backend modules with a fixed
// request schema per method. Read methods never mutate; write methods delegate
// to the shared apply/rotation workers. No secret is ever returned.

'use strict';

import { cursor } from 'uci';
const _common = require('nordvpn.common');
const validate_token = _common.validate_token,
      validate_instance = _common.validate_instance,
      validate_country_code = _common.validate_country_code,
      validate_location_code = _common.validate_location_code,
      bounded_int = _common.bounded_int,
      HISTORY_MAX = _common.HISTORY_MAX,
      load_settings = _common.load_settings,
      list_instances = _common.list_instances,
      cache_file_path = _common.cache_file_path;
const status = require('nordvpn.status').status;
const _apply = require('nordvpn.apply');
const apply = _apply.apply,
      set_credentials = _apply.set_credentials,
      clear_credentials = _apply.clear_credentials,
      disconnect = _apply.disconnect,
      create_instance = _apply.create_instance,
      delete_instance = _apply.delete_instance;
const _rotate = require('nordvpn.rotate');
const rotate = _rotate.rotate,
      read_state = _rotate.read_state,
      last_attempt_ts = _rotate.last_attempt_ts;
const _service = require('nordvpn.service');
const next_rotation = _service.next_rotation,
      effective_state = _service.effective_state,
      egress_report = _service.egress_report;
const read_events = require('nordvpn.history').read_events;
const parse_insights = require('nordvpn.api').parse_insights;
const list_clients = require('nordvpn.clients').clients;
const detect_routing = require('nordvpn.routing').detect;
const _cache = require('nordvpn.cache');
const read_cache = _cache.read_cache,
      read_fetch_status = _cache.read_fetch_status,
      cache_is_stale = _cache.cache_is_stale,
      locations_tree = _cache.locations_tree,
      city_relays = _cache.city_relays,
      pool_relays = _cache.pool_relays;

const methods = {};

// Resolve and validate the requested instance name ('main' by default).
// Returns the name, or null when the section does not exist.
function req_instance(uci, request) {
	let a = (request && request.args) ? request.args : {};
	let name = (a.instance == null || a.instance == '') ? 'main' : validate_instance(a.instance);
	if (!name || uci.get('nordvpn', name) == null)
		return null;
	return name;
}

function build_status(uci, name) {
	let st = status(uci, name);
	let state = read_state(name);
	if (state && state.last_success)
		st.rotation.last_success = state.last_success;
	let s = load_settings(uci, name);
	// Fold in the daemon's egress probe: a handshake-healthy tunnel that
	// forwards nothing reads as 'no_egress', exactly as the watchdog sees it.
	st.state = effective_state(s, st.state, state, st.gateway);
	st.egress = egress_report(s, state, st.gateway);
	st.rotation.next_run = next_rotation(s, last_attempt_ts(name), time());
	st.routing = detect_routing(uci, s, true);
	return st;
}

// ── Read methods ─────────────────────────────────────────────────────

methods.status = {
	args: { instance: '' },
	call: function(request) {
		let uci = cursor();
		let name = req_instance(uci, request);
		if (!name)
			return { error: 'no such instance' };
		return build_status(uci, name);
	}
};

methods.instances = {
	call: function() {
		let uci = cursor();
		let out = [];
		for (let name in list_instances(uci))
			push(out, build_status(uci, name));
		return { instances: out };
	}
};

// Lightweight summary for the Status → Overview card, which polls every few
// seconds: each instance's runtime status without the routing detection that
// `instances` runs (ubus dumps, `ip link`, `dnsmasq --version`). Read-only; no
// network access beyond local ubus and `wg show`.
methods.overview = {
	call: function() {
		let uci = cursor();
		let out = [];
		for (let name in list_instances(uci)) {
			let st = status(uci, name);
			push(out, {
				instance: st.instance,
				state: effective_state(load_settings(uci, name), st.state, read_state(name), st.gateway),
				enabled: st.enabled,
				configured: st.configured,
				location: st.location,
				gateway: st.gateway,
				latest_handshake_seconds: st.latest_handshake_seconds,
				uptime: st.uptime,
				transfer: st.transfer
			});
		}
		return { instances: out };
	}
};

methods.locations = {
	call: function() {
		let s = load_settings(cursor());
		let path = cache_file_path(s);
		let cache = read_cache(path);
		if (!cache)
			return { available: false, state: 'missing' };
		return {
			available: true,
			state: cache_is_stale(path) ? 'stale' : 'ready',
			countries: locations_tree(cache),
			stats: cache.stats,
			cache_info: cache.cache_info,
			cached_at: cache.cached_at
		};
	}
};

methods.servers = {
	args: { country: '', city: '', hop_mode: '', locations: [], server_group: '' },
	call: function(request) {
		let a = request.args || {};
		let cache = read_cache(cache_file_path(load_settings(cursor())));
		if (!cache)
			return { relays: [] };
		// A non-empty location set returns the union (with grouping fields for
		// the UI); entries are validated, garbage is dropped. The legacy
		// country/city call is unchanged.
		if (type(a.locations) == 'array' && length(a.locations) > 0) {
			let set = [];
			for (let e in a.locations) {
				let cc = validate_country_code(e);
				if (cc) {
					push(set, cc);
					continue;
				}
				let loc = validate_location_code(e);
				if (loc && index(loc, '-') > 0)
					push(set, loc);
			}
			return { relays: pool_relays(cache, set, a.hop_mode, a.server_group) };
		}
		return { relays: city_relays(cache, a.country, a.city, a.hop_mode) };
	}
};

// Recent events of one instance (connects, rotations, watchdog recoveries,
// egress probe transitions), newest first.
methods.history = {
	args: { instance: '', limit: 0 },
	call: function(request) {
		let uci = cursor();
		let name = req_instance(uci, request);
		if (!name)
			return { error: 'no such instance' };
		let a = request.args || {};
		let limit = bounded_int(a.limit, 1, HISTORY_MAX) || HISTORY_MAX;
		return { instance: name, events: read_events(name, limit) };
	}
};

// Known LAN clients (DHCP leases, static hosts, neighbour table) for the
// per-device steering picker. Read-only; MACs/IPs validated, names sanitized.
methods.clients = {
	call: function() {
		return { clients: list_clients(cursor()) };
	}
};

methods.refresh_status = {
	call: function() {
		return read_fetch_status() || { state: 'idle' };
	}
};

// Ask NordVPN's own API how it sees a request from this router (no third-party
// IP-echo service). `extra` is prepended curl arguments. Parsed or null.
function insights(extra) {
	let r = _common.run([ 'curl', '-s', '-m', '8', ...extra,
		'-H', 'Accept: application/json', _common.IP_INSIGHTS_URL ]);
	return (r.code == 0) ? parse_insights(r.stdout) : null;
}

// Public IP, location and NordVPN's "protected" verdict as seen through the
// instance's tunnel. Bound to the interface so it reflects the VPN exit even
// with policy routing. With "Route all LAN traffic" and no routing table the
// LAN uses the main table, the same one an unbound request from the router
// takes, so ask again without binding: `lan_path.protected == false` means
// LAN traffic leaves outside the VPN although the tunnel itself is up. With
// a table (set, or implied by exceptions) the LAN is steered into it, which
// the router's own traffic cannot reproduce, as for steered clients.
// Read-only network probe.
methods.external_ip = {
	args: { instance: '' },
	call: function(request) {
		let uci = cursor();
		let name = req_instance(uci, request);
		if (!name)
			return { error: 'no such instance' };
		let s = load_settings(uci, name);
		let res = insights([ '--interface', s.interface ]);
		if (!res)
			return { error: 'could not determine the external IP' };
		res.interface = s.interface;
		if (s.enabled && s.routing_table == '' && detect_routing(uci, s, false).mode == 'auto') {
			let lan = insights([]);
			res.lan_path = lan ? { protected: lan.protected, ip: lan.ip, isp: lan.isp } : null;
		}
		return res;
	}
};

// ── Write methods ────────────────────────────────────────────────────

methods.set_credentials = {
	args: { token: '', instance: '' },
	call: function(request) {
		let token = request.args ? request.args.token : null;
		if (!validate_token(token))
			return { error: 'invalid token format' };
		let uci = cursor();
		let name = req_instance(uci, request);
		if (!name)
			return { error: 'no such instance' };
		return set_credentials(uci, token, name);
	}
};

methods.apply = {
	args: { instance: '' },
	call: function(request) {
		let uci = cursor();
		let name = req_instance(uci, request);
		if (!name)
			return { error: 'no such instance' };
		return apply(uci, name);
	}
};

// Asynchronous apply for the UI. `apply` above stays synchronous for scripts
// and the CLI, but verifying a handshake costs verify_timeout seconds per
// candidate and rpcd answers one call at a time — long enough that the
// browser's own rollback confirmation went unserved and the config was
// reverted underneath the user. Same shape as refresh_locations/
// refresh_status: start, then poll.
methods.apply_start = {
	args: { instance: '' },
	call: function(request) {
		let uci = cursor();
		let name = req_instance(uci, request);
		if (!name)
			return { error: 'no such instance' };
		return _apply.start_apply(name);
	}
};

// Apply progress/outcome for the UI.
methods.apply_status = {
	call: function(request) {
		return _apply.apply_status_report() || { state: 'idle' };
	}
};

methods.refresh_locations = {
	call: function() {
		let running = read_fetch_status();
		if (running && running.state == 'running')
			return { job: running.started_at, already_running: true };
		// Detached one-shot worker; fixed command, no user input, no shell injection.
		system('/usr/bin/nordvpn-cache-update >/dev/null 2>&1 &');
		return { job: '' + time(), started: true };
	}
};

methods.disconnect = {
	args: { instance: '' },
	call: function(request) {
		let uci = cursor();
		let name = req_instance(uci, request);
		if (!name)
			return { error: 'no such instance' };
		return disconnect(uci, name);
	}
};

methods.clear_credentials = {
	args: { instance: '' },
	call: function(request) {
		let uci = cursor();
		let name = req_instance(uci, request);
		if (!name)
			return { error: 'no such instance' };
		return clear_credentials(uci, name);
	}
};

methods.create_instance = {
	args: { instance: '' },
	call: function(request) {
		let a = request.args || {};
		return create_instance(cursor(), a.instance);
	}
};

methods.delete_instance = {
	args: { instance: '' },
	call: function(request) {
		let uci = cursor();
		let name = req_instance(uci, request);
		if (!name)
			return { error: 'no such instance' };
		return delete_instance(uci, name);
	}
};

methods.rotate_now = {
	args: { instance: '' },
	call: function(request) {
		let uci = cursor();
		let name = req_instance(uci, request);
		if (!name)
			return { error: 'no such instance' };
		return rotate(uci, name, 'manual');
	}
};

return { nordvpn: methods };
