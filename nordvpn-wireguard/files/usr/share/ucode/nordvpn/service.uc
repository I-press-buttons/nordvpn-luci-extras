// SPDX-License-Identifier: MIT
// Pure scheduling decisions for the nordvpn procd daemon. Kept separate from
// the uloop event loop so the timing logic can be unit-tested offline.

'use strict';

const _common = require('nordvpn.common');
const WATCHDOG_GRACE = _common.WATCHDOG_GRACE,
      WATCHDOG_COOLDOWN_BASE = _common.WATCHDOG_COOLDOWN_BASE,
      WATCHDOG_COOLDOWN_MAX = _common.WATCHDOG_COOLDOWN_MAX,
      PROBE_FAIL_THRESHOLD = _common.PROBE_FAIL_THRESHOLD;

// Refresh when the interval elapsed, or on first tick if the cache is stale.
function should_refresh(settings, last_cache, now, cache_stale) {
	if (last_cache == 0 && cache_stale)
		return true;
	return (now - last_cache) >= settings.cache_refresh_interval;
}

// `hm` is the current local time as "HH:MM". Rotation only runs when enabled,
// rotation is on, and no fixed server is pinned.
function should_rotate(settings, last_rotate, now, hm) {
	if (!settings.enabled || !settings.rotation_enabled)
		return false;
	if (settings.fixed_server && settings.fixed_server != '')
		return false;
	if (settings.rotation_mode == 'time')
		return (hm == settings.rotation_time && (now - last_rotate) > 90);
	return (now - last_rotate) >= (settings.rotation_interval * 60);
}

// Epoch seconds of the next scheduled rotation, or null when rotation cannot
// run (master switch off, rotation disabled, or a fixed server pinned).
// `last_rotate` is the persisted last-attempt epoch, 0 when unknown. Mirrors
// the gating of should_rotate() so the UI never announces a rotation that the
// daemon would refuse to perform.
function next_rotation(settings, last_rotate, now) {
	if (!settings.enabled || !settings.rotation_enabled)
		return null;
	if (settings.fixed_server && settings.fixed_server != '')
		return null;
	if (settings.rotation_mode == 'time') {
		let hm = split(settings.rotation_time, ':');
		let tm = localtime(now);
		tm.hour = int(hm[0]);
		tm.min = int(hm[1]);
		tm.sec = 0;
		let t = timelocal(tm);
		if (t <= now) {
			tm.mday += 1; // timelocal() normalizes month/year overflow
			t = timelocal(tm);
		}
		return t;
	}
	let base = (last_rotate && last_rotate > 0) ? last_rotate : now;
	let t = base + settings.rotation_interval * 60;
	return t < now ? now : t;
}

// States that may trigger a watchdog recovery. The grace period gives a fresh
// connection time to complete its first handshake. 'no_egress' is a tunnel
// whose handshake is fresh but whose egress probe keeps failing.
function is_unhealthy(state) {
	return state == 'connecting' || state == 'degraded' ||
		state == 'disconnected' || state == 'no_egress';
}

// ── Egress probe ────────────────────────────────────────────────────
// status() judges a tunnel by its WireGuard handshake alone, which proves the
// server answers but not that it forwards. The optional probe pings through
// the tunnel; its result is kept in the per-instance rotate state as
// { probe_fails, probe_at, probe_ok_at, probe_target, probe_server } and
// folded into the state here.

// Probe on this tick? Only a handshake-healthy tunnel is worth probing: any
// other state is already unhealthy on its own.
function should_probe(settings, state) {
	return settings.enabled && settings.egress_probe && state == 'connected';
}

// The state as the watchdog and the UI should see it: 'connected' becomes
// 'no_egress' once the probe failed PROBE_FAIL_THRESHOLD times in a row
// against the server the tunnel is on now. Failures recorded against a
// previous server (a rotation happened since) do not count.
function effective_state(settings, state, st, gateway) {
	if (state != 'connected' || !settings.egress_probe || !st)
		return state;
	if (!gateway || st.probe_server != gateway)
		return state;
	let fails = (type(st.probe_fails) == 'int') ? st.probe_fails : 0;
	return (fails >= PROBE_FAIL_THRESHOLD) ? 'no_egress' : state;
}

// Fold one probe result ({ ok, target }) into the persisted probe fields.
// Returns { fields, event } where `event` is 'egress_lost' when this result
// crossed the threshold, 'egress_restored' when it ended a lost episode, else
// null — so the history records transitions, not every tick.
function probe_update(st, result, gateway, now) {
	let same = st && gateway && st.probe_server == gateway;
	let prev = (same && type(st.probe_fails) == 'int') ? st.probe_fails : 0;
	let ok = (result && result.ok) ? true : false;
	let fields = {
		probe_at: now,
		probe_server: gateway || null,
		probe_fails: ok ? 0 : prev + 1,
		probe_ok_at: ok ? now : ((same && type(st.probe_ok_at) == 'int') ? st.probe_ok_at : 0),
		probe_target: ok ? result.target : null
	};
	let event = null;
	if (ok && prev >= PROBE_FAIL_THRESHOLD)
		event = 'egress_restored';
	else if (!ok && fields.probe_fails == PROBE_FAIL_THRESHOLD)
		event = 'egress_lost';
	return { fields, event };
}

// Probe fields to write when the probe is off, so a stale failure count never
// resurfaces when it is turned back on. null when there is nothing to clear.
function probe_clear(st) {
	if (!st || (!st.probe_at && !st.probe_fails && !st.probe_server))
		return null;
	return { probe_at: 0, probe_server: null, probe_fails: 0, probe_ok_at: 0, probe_target: null };
}

// The probe summary the status API reports, or { enabled: false }.
function egress_report(settings, st, gateway) {
	if (!settings.egress_probe)
		return { enabled: false };
	let same = st && gateway && st.probe_server == gateway && type(st.probe_at) == 'int' && st.probe_at > 0;
	if (!same)
		return { enabled: true, ok: null, fails: 0, checked_at: null, ok_at: null, target: null };
	let fails = (type(st.probe_fails) == 'int') ? st.probe_fails : 0;
	return {
		enabled: true,
		ok: fails == 0,
		fails: fails,
		checked_at: st.probe_at,
		ok_at: (type(st.probe_ok_at) == 'int' && st.probe_ok_at > 0) ? st.probe_ok_at : null,
		target: st.probe_target || null
	};
}

// Watchdog decision: recover a persistently unhealthy instance by rotating
// away from the dead server. Requires the master switch and the per-instance
// watchdog option; a pinned server disables it (mirrors should_rotate). The
// grace period absorbs transient rekeys and the post-apply connecting window;
// the cooldown backs off exponentially per failed attempt so a dead pool is
// not hammered. All timers come from the persisted per-instance state:
// `degraded_since` (0 = healthy), `last_recover` (0 = never), `fails`.
function should_recover(settings, state, degraded_since, last_recover, fails, now) {
	if (!settings.enabled || !settings.watchdog)
		return false;
	if (settings.fixed_server && settings.fixed_server != '')
		return false;
	if (!is_unhealthy(state))
		return false;
	if (!degraded_since || now - degraded_since < WATCHDOG_GRACE)
		return false;
	// Clamp the shift so a long-dead instance cannot overflow it.
	let shift = fails > 0 ? fails - 1 : 0;
	if (shift > 20)
		shift = 20;
	let cooldown = WATCHDOG_COOLDOWN_BASE * (1 << shift);
	if (cooldown > WATCHDOG_COOLDOWN_MAX)
		cooldown = WATCHDOG_COOLDOWN_MAX;
	return last_recover == 0 || now - last_recover >= cooldown;
}

// Next watchdog timers from the observed state transition. Inactive,
// unconfigured, and connected instances start with a clean recovery episode.
// `st` is { degraded_since, last_recover, recover_fails } from persisted state.
function watchdog_update(state, st, now, active) {
	let ds = (st && st.degraded_since > 0) ? st.degraded_since : 0;
	let last = (st && st.last_recover > 0) ? st.last_recover : 0;
	let fails = (st && st.recover_fails > 0) ? st.recover_fails : 0;
	if (!active || state == 'connected' || state == 'not_configured')
		return { degraded_since: 0, last_recover: 0, recover_fails: 0 };
	if (is_unhealthy(state) && ds == 0)
		ds = now;
	return { degraded_since: ds, last_recover: last, recover_fails: fails };
}

// Fold a completed recovery worker result into the failure counter. Losing the
// rotation-lock race is not a recovery failure; the active worker owns it.
function watchdog_result_update(result, fails) {
	let n = (type(fails) == 'int' && fails > 0) ? fails : 0;
	if (result && result.ok)
		return n;
	if (result && result.skipped && result.reason == 'rotation already running')
		return n;
	return n + 1;
}

return {
	should_refresh, should_rotate, next_rotation, should_recover,
	watchdog_update, watchdog_result_update,
	should_probe, effective_state, probe_update, probe_clear, egress_report
};
