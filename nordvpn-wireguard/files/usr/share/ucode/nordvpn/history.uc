// SPDX-License-Identifier: MIT
// Per-instance event history: a small capped log of what the backend did to a
// tunnel (connects, rotations, watchdog recoveries, egress probe transitions)
// so the UI can answer "what happened overnight?" without digging through
// logread. Runtime state in /tmp like the rotation state; lost on reboot.
// Best-effort by design: a history write never fails the operation it records.

'use strict';

import { readfile, unlink } from 'fs';
const _common = require('nordvpn.common');
const HISTORY_MAX = _common.HISTORY_MAX,
      validate_instance = _common.validate_instance,
      atomic_write = _common.atomic_write,
      acquire_lock = _common.acquire_lock,
      release_lock = _common.release_lock,
      redact = _common.redact,
      log = _common.log;

// Event types the backend emits. Anything else is refused so a typo cannot
// quietly create an event the UI does not know how to show.
const EVENT_TYPES = [
	'connect', 'connect_failed',
	'rotate', 'rotate_failed', 'rotate_skipped',
	'watchdog',
	'egress_lost', 'egress_restored',
	'disabled', 'credentials_set', 'credentials_cleared'
];

// Fields an event may carry besides `ts` and `type`; all short strings.
const EVENT_FIELDS = [ 'server', 'from', 'reason', 'error', 'detail' ];

function history_path(instance) {
	let n = validate_instance(instance) || 'main';
	return (n == 'main') ? '/tmp/nordvpn_events.json' : '/tmp/nordvpn_events_' + n + '.json';
}

function history_lock_path(instance) {
	return history_path(instance) + '.lock';
}

// Normalize one event: known type, integer timestamp, whitelisted string
// fields clipped to a sane length (and scrubbed of anything token-shaped,
// like the log). null for an unknown type. Pure/testable.
function make_event(type_, fields, now) {
	if (index(EVENT_TYPES, type_) < 0)
		return null;
	let ev = { ts: (type(now) == 'int') ? now : time(), type: type_ };
	for (let k in EVENT_FIELDS) {
		let v = fields ? fields[k] : null;
		if (v == null || v == '')
			continue;
		v = redact('' + v);
		ev[k] = (length(v) > 160) ? substr(v, 0, 160) : v;
	}
	return ev;
}

// Append to a list and keep only the newest `cap` entries (oldest first, the
// on-disk order). Tolerates a missing or corrupt list. Pure/testable.
function append_capped(list, ev, cap) {
	let out = [];
	if (type(list) == 'array')
		for (let e in list)
			if (type(e) == 'object')
				push(out, e);
	push(out, ev);
	cap = (type(cap) == 'int' && cap > 0) ? cap : HISTORY_MAX;
	if (length(out) > cap)
		out = slice(out, length(out) - cap);
	return out;
}

function read_list(instance) {
	let raw = readfile(history_path(instance));
	if (!raw)
		return [];
	try {
		let l = json(raw);
		return (type(l) == 'array') ? l : [];
	} catch (e) {
		return [];
	}
}

// Record one event for an instance. Serialized with a short lock so the
// daemon, rotation worker and rpcd never lose each other's entries; gives up
// (with a log line) rather than stall the caller when the lock stays busy.
// Returns the stored event or null.
function record_event(instance, type_, fields, now) {
	let ev = make_event(type_, fields, now);
	if (!ev)
		return null;
	let lock = null;
	for (let i = 0; i < 100 && !lock; i++) {
		lock = acquire_lock(history_lock_path(instance), 30);
		if (!lock)
			sleep(20);
	}
	if (!lock) {
		log('could not lock the event history of ' + (validate_instance(instance) || 'main'));
		return null;
	}
	let ok = atomic_write(history_path(instance),
		sprintf('%J', append_capped(read_list(instance), ev, HISTORY_MAX)));
	release_lock(lock);
	return ok ? ev : null;
}

// Events of one instance, newest first, at most `limit` (default: all kept).
function read_events(instance, limit) {
	let list = read_list(instance);
	let out = [];
	for (let i = length(list) - 1; i >= 0; i--) {
		if (type(list[i]) != 'object')
			continue;
		push(out, list[i]);
		if (type(limit) == 'int' && limit > 0 && length(out) >= limit)
			break;
	}
	return out;
}

// Forget an instance's history (instance deleted or reset).
function clear_events(instance) {
	unlink(history_path(instance));
}

return { EVENT_TYPES, history_path, make_event, append_capped, record_event, read_events, clear_events };
