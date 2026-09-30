// SPDX-License-Identifier: MIT
// Credential storage and transactional WireGuard apply. Shared by the rpcd
// `apply`/`set_credentials` methods and the procd reload path.

'use strict';

import { srand } from 'math';
import { readfile, unlink, stat } from 'fs';
import { cursor } from 'uci';
const _common = require('nordvpn.common');
const FIXED_ADDRESS = _common.FIXED_ADDRESS,
      DEFAULT_PORT = _common.DEFAULT_PORT,
      DEFAULT_KEEPALIVE = _common.DEFAULT_KEEPALIVE,
      APPLY_STATUS_FILE = _common.APPLY_STATUS_FILE,
      APPLY_LOCK_FILE = _common.APPLY_LOCK_FILE,
      APPLY_MAX_RUNTIME = _common.APPLY_MAX_RUNTIME,
      load_settings = _common.load_settings,
      cache_file_path = _common.cache_file_path,
      validate_interface = _common.validate_interface,
      validate_instance = _common.validate_instance,
      validate_wg_key = _common.validate_wg_key,
      validate_nordvpn_host = _common.validate_nordvpn_host,
      validate_port = _common.validate_port,
      managed_interface = _common.managed_interface,
      iso_ts = _common.iso_ts,
      run = _common.run;
const _cache = require('nordvpn.cache');
const read_cache = _cache.read_cache;
const _select = require('nordvpn.select');
const selection_candidates = _select.selection_candidates,
      by_hostname = _select.by_hostname,
      pick = _select.pick,
      order_candidates = _select.order_candidates;
const _routing = require('nordvpn.routing');
const enforce_routing = _routing.enforce;
const _history = require('nordvpn.history');
const record_event = _history.record_event;
const _creds = require('nordvpn.credentials');

// Locate the managed peer section (type wireguard_<iface>, interface=<iface>).
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

// Store credentials for `instance` (its bank entry; see nordvpn.credentials)
// and push them to every instance sharing that entry. Kept for scripts that
// set credentials per instance. Returns { ok, credential, name } or { error }.
function set_credentials(uci, token, instance) {
	let iface = validate_interface(load_settings(uci, instance).interface);
	if (!iface)
		return { error: 'invalid interface name' };
	if (!managed_interface(uci, iface))
		return { error: 'interface ' + iface + ' is not managed by nordvpn' };
	_creds.migrate(uci);
	return _creds.set(uci, token, null, null, instance);
}

// Snapshot the current peer so a failed rotation can be rolled back.
function current_peer(uci, iface) {
	let peer = find_peer(uci, iface);
	if (!peer)
		return null;
	return {
		public_key: uci.get('network', peer, 'public_key'),
		endpoint_host: uci.get('network', peer, 'endpoint_host'),
		endpoint_port: uci.get('network', peer, 'endpoint_port'),
		gateway: uci.get('network', peer, 'nordvpn_gateway')
	};
}

// Restore a peer snapshot taken by current_peer() (no commit).
function restore_peer(uci, iface, saved) {
	if (!saved)
		return;
	let peer = find_peer(uci, iface);
	if (!peer)
		peer = uci.add('network', 'wireguard_' + iface);
	uci.set('network', peer, 'interface', iface);
	if (saved.public_key)
		uci.set('network', peer, 'public_key', saved.public_key);
	if (saved.endpoint_host)
		uci.set('network', peer, 'endpoint_host', saved.endpoint_host);
	if (saved.endpoint_port)
		uci.set('network', peer, 'endpoint_port', saved.endpoint_port);
	if (saved.gateway)
		uci.set('network', peer, 'nordvpn_gateway', saved.gateway);
}

// Write the interface + peer for the chosen relay (no commit). The relay comes
// from the cache file, so its endpoint and key are re-validated here before
// they reach /etc/config/network; the endpoint must be a NordVPN host. Returns
// false (nothing written) if invalid.
function write_relay(uci, iface, relay, s) {
	if (!relay || !validate_nordvpn_host(relay.hostname) || !validate_wg_key(relay.public_key) ||
	    (relay.port != null && !validate_port(relay.port)))
		return false;

	uci.set('network', iface, 'proto', 'wireguard');
	uci.set('network', iface, 'vpn_type', 'nordvpn');
	uci.set('network', iface, 'auto', '1');
	uci.set('network', iface, 'addresses', [ FIXED_ADDRESS ]);

	if (s.routing_table && s.routing_table != '') {
		uci.set('network', iface, 'ip4table', s.routing_table);
		uci.set('network', iface, 'ip6table', s.routing_table);
	} else {
		uci.delete('network', iface, 'ip4table');
		uci.delete('network', iface, 'ip6table');
	}

	// Optional MTU override; empty falls back to netifd's WireGuard default.
	if (s.mtu)
		uci.set('network', iface, 'mtu', '' + s.mtu);
	else
		uci.delete('network', iface, 'mtu');

	uci.set('network', iface, 'nordvpn_location', relay.location);
	// Stamp the ACTUAL server's country/city: with a location set the
	// connected relay may sit in any of the set's countries, and the status
	// must reflect where the tunnel really exits (exit country for multihop).
	uci.set('network', iface, 'nordvpn_country_code', relay.exit_country_code || s.country_code);
	uci.set('network', iface, 'nordvpn_city_code', relay.location || s.city_code);
	uci.set('network', iface, 'nordvpn_last_applied', iso_ts());

	let peer = find_peer(uci, iface);
	if (!peer)
		peer = uci.add('network', 'wireguard_' + iface);
	uci.set('network', peer, 'interface', iface);
	// Managed routing stamps the interface; the peer's allowed-IPs routes
	// (netifd-installed, into ip4table when set) follow it.
	if (uci.get('network', iface, 'nordvpn_managed_routing') == '1')
		uci.set('network', peer, 'route_allowed_ips', '1');
	uci.set('network', peer, 'public_key', relay.public_key);
	uci.set('network', peer, 'endpoint_host', relay.hostname);
	uci.set('network', peer, 'endpoint_port', '' + (relay.port || DEFAULT_PORT));
	uci.set('network', peer, 'persistent_keepalive', '' + DEFAULT_KEEPALIVE);
	uci.set('network', peer, 'allowed_ips', [ '0.0.0.0/0', '::/0' ]);
	uci.set('network', peer, 'nordvpn_gateway', relay.hostname);
	return true;
}

// Bring the managed interface up. iface is whitelist-validated, so the argv is
// injection-safe (no shell).
function bring_up(iface) {
	return run([ 'ifup', iface ]).code == 0;
}

// Newest WireGuard handshake age (seconds) for the interface. Returns -1 when
// the wg binary is absent (off-device: exit 127 from the shell), null when
// there is no handshake — including when the device does not exist, which is
// a failed connection, not a pass.
function handshake_age(iface) {
	let res = run([ 'wg', 'show', iface, 'latest-handshakes' ], true);
	if (res.code == 127)
		return -1;
	if (res.code != 0)
		return null;
	let best = 0;
	for (let line in split(trim(res.stdout || ''), '\n')) {
		let parts = split(line, '\t');
		if (length(parts) >= 2) {
			let t = int(parts[1]);
			if (t > best)
				best = t;
		}
	}
	if (best == 0)
		return null;
	let age = time() - best;
	return age < 0 ? 0 : age;
}

// Wait up to `seconds` for a fresh handshake. True when connected — or when wg
// is unavailable (off-device), so the apply logic is not blocked in tests.
// Sleeps in-process: spawning `sleep` through a shell every second only adds
// two process starts per second of waiting.
function verify_handshake(iface, seconds) {
	for (let i = 0; i < seconds; i++) {
		sleep(1000);
		let age = handshake_age(iface);
		if (age == -1)
			return true;
		if (age != null && age < 180)
			return true;
	}
	return false;
}

// Why netifd could not create the tunnel device, as a user-facing hint, or
// null. `st` is the interface's netifd status object. A WireGuard section
// that netifd reports as proto 'none' means its wireguard protocol handler is
// not loaded: netifd reads handlers only at startup, so installing
// wireguard-tools without restarting it leaves every tunnel down while
// `ifup` still succeeds. Pure.
function netifd_hint(st) {
	if (type(st) != 'object' || st.up)
		return null;
	if (st.proto == 'none')
		return 'netifd has not loaded the WireGuard protocol handler; run /etc/init.d/network restart (or reboot) after installing the packages';
	for (let e in (st.errors || []))
		if (e && e.code == 'NO_DEVICE')
			return 'netifd could not create the WireGuard device; check that kmod-wireguard matches the running kernel (lsmod | grep wireguard)';
	return null;
}

// netifd_hint() for the live interface, or null when it cannot be read.
function tunnel_hint(iface) {
	let r = run([ 'ubus', 'call', 'network.interface.' + iface, 'status' ]);
	if (r.code != 0)
		return null;
	try {
		return netifd_hint(json(r.stdout));
	} catch (e) {
		return null;
	}
}

// Commit and reload whatever an enforce_routing() pass changed. The firewall
// goes first so the domain nft set exists before dnsmasq is restarted to fill
// it; a firewall reload also empties that set, so dnsmasq is restarted then
// too (flushing its cache makes clients' next lookups repopulate the set).
// Steering/prohibit rules are plain netifd config; a reload makes netifd apply
// the delta (unchanged interfaces are left alone). True when anything was
// committed.
function commit_routing(uci, routing) {
	if (routing.changed_firewall) {
		uci.commit('firewall');
		run([ '/etc/init.d/firewall', 'reload' ]);
	}
	if (routing.changed_network) {
		uci.commit('network');
		run([ 'ubus', 'call', 'network', 'reload' ]);
	}
	if (routing.changed_dhcp)
		uci.commit('dhcp');
	if (routing.changed_dhcp || (routing.changed_firewall && routing.domains_active))
		run([ '/etc/init.d/dnsmasq', 'restart' ]);
	return !!(routing.changed_firewall || routing.changed_network || routing.changed_dhcp);
}

function connect_one(uci, iface, relay, s) {
	if (!write_relay(uci, iface, relay, s))
		return false;
	uci.commit('network');
	return bring_up(iface);
}

// A global netifd reload has been observed (OpenWrt 24.10) to remove the
// kernel's main IPv4 default route while netifd still reports it as
// installed, cutting WAN connectivity. Self-heal: when the kernel lost the
// default but netifd claims a gateway route on an up interface, re-add it.
function restore_wan_default() {
	// The reload applies asynchronously; the route can disappear a moment
	// after an immediate check passes, so probe a few times.
	for (let attempt = 0; attempt < 3; attempt++) {
		sleep(2000);
		let r = run([ 'ip', '-4', 'route', 'show', 'default' ]);
		if (r.code != 0)
			return false;
		if (length(trim(r.stdout || '')) > 0)
			continue;
		let d = run([ 'ubus', 'call', 'network.interface', 'dump' ]);
		if (d.code != 0)
			return false;
		let data;
		try {
			data = json(d.stdout);
		} catch (e) {
			return false;
		}
		for (let ifc in ((data ? data.interface : null) || [])) {
			if (!ifc.up || !ifc.l3_device)
				continue;
			for (let rt in (ifc.route || [])) {
				if (rt.target == '0.0.0.0' && rt.mask == 0 && rt.nexthop && rt.nexthop != '0.0.0.0') {
					let res = run([ 'ip', 'route', 'add', 'default', 'via', rt.nexthop, 'dev', ifc.l3_device ]);
					if (res.code != 0)
						return false;
					// Only claim success once the route really went in.
					_common.log('restored missing WAN default route via ' + rt.nexthop +
						' on ' + ifc.l3_device);
				}
			}
		}
	}
	return true;
}

// Apply the persisted configuration. A fixed server is applied once; an
// automatic selection tries several candidates until one completes a handshake
// (NordVPN publishes dead endpoints), rolling back to the previous working peer
// if none do. Bounded so the rpc call stays within timeout.
function apply_inner(uci, instance) {
	let s = load_settings(uci, instance);
	let iface = validate_interface(s.interface);
	if (!iface)
		return { state: 'failure', error: 'invalid interface name' };
	if (!managed_interface(uci, iface))
		return { state: 'failure', error: 'interface ' + iface + ' is not managed by nordvpn' };
	// The instance's credentials may have changed in the bank or been switched
	// to another entry since the last apply: bring the interface key in line.
	_creds.migrate(uci);
	if (_creds.sync_instance(uci, instance))
		uci.commit('network');
	if (!validate_wg_key(uci.get('network', iface, 'private_key')))
		return { state: 'failure', error: 'no credentials configured' };

	let cache = read_cache(cache_file_path(s));
	if (!cache)
		return { state: 'failure', error: 'server list not available; refresh the cache first' };

	// Applying implies the user wants the instance on — undo a disable, both
	// in the config and in the already-loaded settings the enforcement uses.
	if (!s.enabled) {
		uci.set('nordvpn', s.name, 'enabled', '1');
		uci.commit('nordvpn');
		s.enabled = true;
	}

	// Reconcile the managed routing/firewall objects with the settings. Only
	// stamped objects are ever touched; a detected manual scheme is left alone.
	let routing = enforce_routing(uci, s);
	if (commit_routing(uci, routing)) {
		// Committing deletions invalidates the cursor's section iteration
		// state (find_peer silently missed sections) — start fresh.
		uci = cursor();
	}
	for (let note in routing.notes)
		_common.log('routing: ' + note);

	srand(time());
	let saved = current_peer(uci, iface);

	if (s.fixed_server && s.fixed_server != '') {
		let relay = by_hostname(cache, s.fixed_server);
		if (!relay)
			return { state: 'failure', error: 'configured server not found in cache' };
		let up = connect_one(uci, iface, relay, s);
		let ok = up && verify_handshake(iface, s.verify_timeout);
		return {
			state: ok ? 'success' : (up ? 'partial_failure' : 'failure'),
			interface: iface, gateway: relay.hostname,
			endpoint: relay.hostname + ':' + (relay.port || DEFAULT_PORT),
			restarted: up,
			error: ok ? null : (tunnel_hint(iface) || 'the selected server did not respond')
		};
	}

	let list = selection_candidates(cache, s);
	if (length(list) == 0)
		return { state: 'failure', error: 'no matching server found for the current selection' };
	list = order_candidates(list, s.selection);

	let tries = length(list);
	if (tries > 4)
		tries = 4;
	for (let i = 0; i < tries; i++) {
		let relay = list[i];
		if (!connect_one(uci, iface, relay, s))
			continue;
		if (verify_handshake(iface, s.verify_timeout))
			return {
				state: 'success', interface: iface, gateway: relay.hostname,
				endpoint: relay.hostname + ':' + (relay.port || DEFAULT_PORT),
				restarted: true
			};
	}

	let hint = tunnel_hint(iface);
	if (saved) {
		restore_peer(uci, iface, saved);
		uci.commit('network');
		bring_up(iface);
	}
	return { state: 'failure', restored: saved != null,
		error: hint || 'could not reach any server for the current selection; restored the previous connection' };
}

// History entry for an apply outcome. Pure/testable.
function apply_event(res) {
	if (res && res.state == 'success')
		return { type: 'connect', fields: { server: res.gateway } };
	return { type: 'connect_failed', fields: {
		server: res ? res.gateway : null,
		error: (res && res.error) ? res.error : 'unknown error',
		detail: (res && res.restored) ? 'restored the previous server' : null
	} };
}

function apply(uci, instance) {
	let res = apply_inner(uci, instance);
	restore_wan_default();
	let ev = apply_event(res);
	record_event(instance, ev.type, ev.fields);
	return res;
}

// ── Asynchronous jobs (worker + status file) ─────────────────────────
// apply() is slow by nature: it reads the multi-megabyte server cache and then
// waits verify_timeout seconds per candidate for a handshake — NordVPN
// publishes dead endpoints, so two silent candidates alone cost 16 s at the
// default. rpcd serves ubus calls one at a time, so running that inside the
// call starved everything else, including the `uci confirm` the browser sends
// to keep its own changes: the router hit the rollback timer and reverted
// /etc/config/nordvpn underneath the user. The UI therefore spawns
// /usr/bin/nordvpn-apply and polls the status file written here, exactly like
// the cache refresh does with nordvpn.cache's fetch status. A manual rotation
// is slower still (up to max_retries candidates) and runs the same way, as a
// job of kind 'rotate' (see nordvpn.rotate.run_job). One job runs at a time.
// The synchronous apply() and rotate() stay as-is for scripts and the CLI.

// Worker command per job kind; the instance name is appended.
const JOB_WORKERS = {
	apply: '/usr/bin/nordvpn-apply ',
	rotate: '/usr/bin/nordvpn-rotate --job '
};

// Stamp `updated_at` and atomically write the apply-status file.
function write_apply_status(status) {
	if (type(status) != 'object')
		return false;
	status.updated_at = iso_ts();
	return _common.atomic_write(APPLY_STATUS_FILE, sprintf('%J', status));
}

// Parsed apply-status object or null.
function read_apply_status() {
	let raw = readfile(APPLY_STATUS_FILE);
	if (!raw)
		return null;
	try {
		return json(raw);
	} catch (e) {
		return null;
	}
}

// Own pid (see nordvpn.common.self_pid()). Recorded with a 'running' record
// so a dead worker is detectable; null when /proc is unavailable, in which
// case only the runtime ceiling applies.
function self_pid() {
	return _common.self_pid();
}

// Runtime ceiling of a job: an apply's is fixed, a rotation's follows the
// instance's max_retries and verify_timeout.
function job_max_runtime(kind, instance) {
	if (kind != 'rotate')
		return APPLY_MAX_RUNTIME;
	return _common.rotation_max_runtime(load_settings(cursor(), instance));
}

// The ceiling a record states, within [APPLY_MAX_RUNTIME, JOB_MAX_RUNTIME_CAP];
// the apply ceiling for anything else, including records of older versions.
function job_ceiling(st) {
	let m = (type(st) == 'object') ? st.max_runtime : null;
	return (type(m) == 'int' && m >= APPLY_MAX_RUNTIME && m <= _common.JOB_MAX_RUNTIME_CAP)
		? m : APPLY_MAX_RUNTIME;
}

// Is this record a believable 'running' one? A worker can die mid-apply (a
// reboot, the OOM killer, a stray `killall ucode`) and what it left behind
// must not wedge the instance forever: an apply whose process is gone, or one
// past the runtime ceiling, is not running whatever the file says. `now` is
// injectable so the recovery rules stay testable.
function apply_running(st, now) {
	if (type(st) != 'object' || st.state != 'running')
		return false;
	now = now || time();
	let started = (type(st.started_at_epoch) == 'int') ? st.started_at_epoch : 0;
	// No start stamp, or one older than a whole job could take: abandoned.
	// A stamp in the future is just as implausible — routers have no RTC and
	// the clock jumps the moment NTP lands, which must not freeze the record.
	if (!started || (now - started) > job_ceiling(st) || started > (now + 60))
		return false;
	if (type(st.pid) == 'int' && st.pid > 0 && !stat('/proc/' + st.pid))
		return false;
	return true;
}

// The record the UI polls. A 'running' record whose worker is gone is turned
// into a terminal 'failed' — and rewritten as such — so the page shows an
// error instead of spinning forever and the next job start is allowed.
function apply_status_report(now) {
	let st = read_apply_status();
	if (!st)
		return null;
	if (st.state == 'running' && !apply_running(st, now)) {
		st.state = 'failed';
		st.stale = true;
		st.pid = null;
		st.finished_at = iso_ts(now);
		st.error = (st.kind == 'rotate') ? 'the rotation worker stopped unexpectedly'
			: 'the apply worker stopped unexpectedly';
		write_apply_status(st);
	}
	return st;
}

// Did a job end the way the user asked for? A rotation that was skipped (a
// pinned server, nothing else to rotate to) finished as a no-op, not a fault.
function job_succeeded(kind, res) {
	if (kind == 'rotate')
		return !!(res && (res.ok || res.skipped));
	return !!(res && res.state == 'success');
}

// Run one job of `kind` for one instance and record the outcome: the whole
// body of the detached worker. `work(name)` does the job and returns its
// result. The lock is what actually prevents two overlapping jobs (the status
// file is only what the UI reads), and its own stale reclamation is the
// second recovery path for a killed worker.
function run_job(instance, kind, work) {
	let name = validate_instance(instance) || 'main';
	let busy = (kind == 'apply') ? 'apply already running' : 'an apply or rotation is already running';
	let max = job_max_runtime(kind, name);
	let lock = _common.acquire_lock(APPLY_LOCK_FILE, max);
	if (!lock) {
		// The lock ages out on its own, but the status record knows sooner: a
		// 'running' record whose worker is gone means this lock is orphaned, and
		// honouring it would block the user's retry for minutes. Reclaim it only
		// on that evidence — a missing or terminal record is exactly what a
		// worker that took the lock a millisecond ago also looks like, and
		// stealing the lock from it would run two jobs at once.
		let st = read_apply_status();
		if (!st || st.state != 'running' || apply_running(st))
			// Leave the status file alone: it belongs to the running job.
			return { skipped: true, reason: busy };
		unlink(APPLY_LOCK_FILE);
		lock = _common.acquire_lock(APPLY_LOCK_FILE, max);
		if (!lock)
			return { skipped: true, reason: busy };
		_common.log('reclaimed the job lock of a worker that never finished');
	}

	let started = time();
	let base = { kind: kind, instance: name, started_at: iso_ts(started),
		started_at_epoch: started, max_runtime: max };
	write_apply_status({ ...base, state: 'running', pid: self_pid(),
		finished_at: null, result: null, error: null });

	let res;
	try {
		res = work(name);
	} catch (e) {
		// A throw must not leave the record on 'running' — the UI would wait out
		// the whole ceiling for a job that is already over.
		res = (kind == 'apply') ? { state: 'failure', error: 'apply error: ' + e }
			: { error: kind + ' error: ' + e };
	}
	_common.release_lock(lock);

	let finished = time();
	write_apply_status({ ...base, pid: null,
		state: job_succeeded(kind, res) ? 'done' : 'failed',
		finished_at: iso_ts(finished), finished_at_epoch: finished,
		result: res, error: (res && res.error) ? res.error : null });
	return res;
}

// Apply one instance as a job (the nordvpn-apply worker).
function run_apply(instance) {
	return run_job(instance, 'apply', function(name) { return apply(cursor(), name); });
}

// Spawn the detached worker for one job and pre-record the 'running' state, so
// a poll landing between the spawn and the worker's own first write reads
// 'running' rather than the previous run's result. `echo $!` hands back the
// worker's pid, which makes a worker that dies on the spot recoverable on the
// next poll instead of only after the runtime ceiling.
function start_job(instance, kind) {
	let name = validate_instance(instance);
	if (!name)
		return { error: 'invalid instance name' };
	if (!JOB_WORKERS[kind])
		return { error: 'unknown job' };

	let st = apply_status_report();
	if (apply_running(st)) {
		// The very job asked for is already in flight: that is the one the
		// caller wants. Any other must finish first — waiting on it would
		// report its outcome as the caller's.
		if ((st.kind || 'apply') == kind && st.instance == name)
			return { already_running: true, apply: st };
		return { busy: true, error: sprintf('%s of instance %s is still running; try again when it finishes',
			(st.kind == 'rotate') ? 'a rotation' : 'an apply', st.instance) };
	}

	// `name` is restricted to [A-Za-z0-9_], so it cannot break out of the
	// sh -c string; quoting it here would only fight the outer sh_quote().
	let r = run([ 'sh', '-c', JOB_WORKERS[kind] + name +
		' >/dev/null 2>&1 & echo $!' ]);
	if (r.code != 0)
		return { error: 'could not start the ' + kind + ' worker' };

	let out = trim(r.stdout || '');
	let started = time();
	let rec = { kind: kind, instance: name, state: 'running',
		pid: _common.full_match(out, /^[0-9]+$/) ? int(out) : null,
		started_at: iso_ts(started), started_at_epoch: started,
		max_runtime: job_max_runtime(kind, name),
		finished_at: null, result: null, error: null };
	// The worker writes its own 'running' record before it does any work and
	// cannot have finished yet, so this write cannot clobber a real result.
	write_apply_status(rec);
	return { started: true, instance: name, apply: rec };
}

// start_job() for an apply.
function start_apply(instance) {
	return start_job(instance, 'apply');
}

// Disable the instance: tunnel down and kept down (auto '0'), scheduled
// rotation stopped, and every managed routing/firewall object released so the
// steered networks return to normal networking — IPv6 included. The next
// apply re-enables and recreates everything.
function disconnect(uci, instance) {
	let s = load_settings(uci, instance);
	let iface = validate_interface(s.interface);
	if (!iface)
		return { error: 'invalid interface name' };
	if (!managed_interface(uci, iface))
		return { error: 'interface ' + iface + ' is not managed by nordvpn' };
	uci.set('nordvpn', s.name, 'enabled', '0');
	uci.commit('nordvpn');

	s.enabled = false;
	let routing = enforce_routing(uci, s);
	if (commit_routing(uci, routing))
		uci = cursor();

	if (uci.get('network', iface) != null) {
		uci.set('network', iface, 'auto', '0');
		uci.commit('network');
	}
	run([ 'ifdown', iface ]);
	restore_wan_default();
	record_event(instance, 'disabled');
	return { ok: true, interface: iface };
}

// Remove the key of the bank entry `instance` uses. The entry is shared, so
// every instance on it goes down (see nordvpn.credentials.clear_key()).
function clear_credentials(uci, instance) {
	let iface = validate_interface(load_settings(uci, instance).interface);
	if (!iface)
		return { error: 'invalid interface name' };
	if (!managed_interface(uci, iface))
		return { error: 'interface ' + iface + ' is not managed by nordvpn' };
	_creds.migrate(uci);
	let res = _creds.clear_key(uci, _creds.instance_credential(uci, instance));
	if (res.ok)
		res.interface = iface;
	return res;
}

// Create a new VPN instance section with its own interface. Committed
// atomically here (not via the UI's staged-apply machinery, whose rollback
// window makes programmatic section creation fragile).
function create_instance(uci, name, credential) {
	let valid = _common.validate_instance(name);
	if (!valid || valid != name)
		return { error: 'invalid instance name' };
	if (name == 'globals')
		return { error: 'this name is reserved' };
	if (uci.get('nordvpn', name) != null)
		return { error: 'an instance with this name already exists' };

	let iface = validate_interface('nv_' + name);
	if (!iface)
		return { error: 'instance name is too long for an interface name' };
	let taken = false;
	for (let other in _common.list_instances(uci))
		if (load_settings(uci, other).interface == iface)
			taken = true;
	if (taken || uci.get('network', iface) != null)
		return { error: 'interface ' + iface + ' already exists' };

	// New instances share the 'default' credentials unless told otherwise.
	_creds.migrate(uci);
	let cred = (credential == null || credential == '') ? _creds.DEFAULT_ID : credential;
	if (!_creds.exists(uci, cred))
		return { error: 'no such credentials' };

	uci.set('nordvpn', name, 'instance');
	uci.set('nordvpn', name, 'interface', iface);
	uci.set('nordvpn', name, 'enabled', '1');
	if (cred != _creds.DEFAULT_ID)
		uci.set('nordvpn', name, 'credential', cred);
	uci.commit('nordvpn');

	let key = _creds.sync_instance(uci, name) == 'set';
	if (key) {
		uci.commit('network');
		record_event(name, 'credentials_set');
	}
	return { ok: true, instance: name, interface: iface, credential: cred, configured: key };
}

// Tear down a VPN instance: stamped routing/firewall objects, the netifd
// interface + peer, and the config section. 'main' is special — it anchors
// the shared cache options and the UI, so instead of deleting the section its
// options are reset to the shipped defaults (the migration stamp is kept).
function delete_instance(uci, name) {
	if (uci.get('nordvpn', name) == null)
		return { error: 'no such instance' };

	let s = load_settings(uci, name);
	let iface = validate_interface(s.interface);
	if (!iface)
		return { error: 'invalid interface name' };

	// Remove stamped artifacts by enforcing the all-off state.
	s.auto_routing = false;
	s.killswitch = false;
	s.block_ipv6 = false;
	s.vpn_dns = 'off';
	s.use_vpn_dns = false;
	s.source_networks = [];
	s.source_devices = [];
	s.source_domains = [];
	s.bypass_devices = [];
	s.bypass_domains = [];
	let routing = enforce_routing(uci, s);
	if (commit_routing(uci, routing))
		uci = cursor(); // see apply(): committed deletions break iteration

	// The instance section goes either way, but a foreign interface it merely
	// pointed at (wan, a user tunnel) is never taken down or stripped.
	if (managed_interface(uci, iface)) {
		run([ 'ifdown', iface ]);
		let peer = find_peer(uci, iface);
		if (peer)
			uci.delete('network', peer);
		if (uci.get('network', iface) != null)
			uci.delete('network', iface);
		uci.commit('network');
	}

	if (name == 'main') {
		let all = uci.get_all('nordvpn', 'main');
		for (let k in all) {
			if (substr(k, 0, 1) == '.' || k == 'config_version')
				continue;
			uci.delete('nordvpn', 'main', k);
		}
		uci.commit('nordvpn');
		restore_wan_default();
		_history.clear_events(name);
		return { ok: true, reset: name, interface: iface };
	}

	uci.delete('nordvpn', name);
	uci.commit('nordvpn');
	restore_wan_default();
	_history.clear_events(name);
	return { ok: true, deleted: name, interface: iface };
}

return { set_credentials, clear_credentials, current_peer, restore_peer, write_relay, bring_up, verify_handshake, netifd_hint, tunnel_hint, connect_one, apply_event, apply, disconnect, create_instance, delete_instance, restore_wan_default,
	write_apply_status, read_apply_status, apply_running, apply_status_report, run_job, run_apply, start_job, start_apply };
