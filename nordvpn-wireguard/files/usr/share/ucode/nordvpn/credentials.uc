// SPDX-License-Identifier: MIT
// Credential bank: named NordVPN credentials shared by the VPN instances. Each
// entry holds only the WireGuard private key its access token was exchanged
// for (the token is never stored). Every instance uses 'default' unless it
// names another entry. The bank lives in its own root-only UCI package, apart
// from /etc/config/nordvpn which the browser loads; netifd still needs the key
// on each interface, so it is copied there and kept in sync from here.

'use strict';

import { stat, writefile, chmod } from 'fs';
const _common = require('nordvpn.common');
const FIXED_ADDRESS = _common.FIXED_ADDRESS,
      load_settings = _common.load_settings,
      list_instances = _common.list_instances,
      validate_interface = _common.validate_interface,
      validate_instance = _common.validate_instance,
      validate_wg_key = _common.validate_wg_key,
      managed_interface = _common.managed_interface,
      clean_label = _common.clean_label,
      run = _common.run;
// Called through the module so offline tests can stand in for the API.
const _api = require('nordvpn.api');
const record_event = require('nordvpn.history').record_event;

const PKG = 'nordvpn_credentials';
const PKG_FILE = '/etc/config/' + PKG;
const DEFAULT_ID = 'default';
const DEFAULT_NAME = 'Default';
const MAX_NAME = 32;

// uci cannot write a package whose file does not exist; create it root-only.
function ensure_file() {
	if (stat(PKG_FILE) || !stat('/etc/config'))
		return;
	writefile(PKG_FILE, '');
	chmod(PKG_FILE, 0600);
}

// Display name: cleaned like every other label, 1..MAX_NAME chars, or null.
// Pure.
function validate_name(n) {
	n = clean_label(n, null);
	return (n != null && length(n) <= MAX_NAME) ? n : null;
}

// Section id for a new entry named `name`, unique among `taken`. Pure.
function make_id(name, taken) {
	let base = substr(replace(lc(name || ''), /[^a-z0-9_]+/g, '_'), 0, 24);
	base = replace(base, /^_+|_+$/g, '');
	if (base == '' || base == DEFAULT_ID)
		base = 'cred';
	let id = base, n = 2;
	while (index(taken, id) >= 0)
		id = base + '_' + n++;
	return id;
}

function entry_ids(uci) {
	let ids = [];
	uci.foreach(PKG, 'credential', function(sec) { push(ids, sec['.name']); });
	return ids;
}

function exists(uci, id) {
	return id == DEFAULT_ID || uci.get(PKG, id) == 'credential';
}

function key_of(uci, id) {
	return validate_wg_key(uci.get(PKG, id, 'private_key'));
}

// The bank entry an instance uses: its `credential` option when that entry
// exists, else 'default'.
function instance_credential(uci, instance) {
	let id = load_settings(uci, instance).credential;
	return exists(uci, id) ? id : DEFAULT_ID;
}

function users(uci, id) {
	let out = [];
	for (let name in list_instances(uci))
		if (instance_credential(uci, name) == id)
			push(out, name);
	return out;
}

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

// The bank, without any key: [{ id, name, configured, instances }], 'default'
// first and always present.
function list(uci) {
	let out = [];
	let ids = [ DEFAULT_ID ];
	for (let id in entry_ids(uci))
		if (id != DEFAULT_ID)
			push(ids, id);
	for (let id in ids)
		push(out, {
			id: id,
			name: uci.get(PKG, id, 'name') || (id == DEFAULT_ID ? DEFAULT_NAME : id),
			configured: key_of(uci, id) != null,
			instances: users(uci, id)
		});
	return out;
}

// Copy the instance's bank key onto its interface (no commit). Without a key
// the interface is stripped and taken down, exactly like removing its
// credentials. Returns 'set', 'cleared' or null when nothing changed.
function sync_instance(uci, instance) {
	let iface = validate_interface(load_settings(uci, instance).interface);
	if (!iface || !managed_interface(uci, iface))
		return null;
	let key = key_of(uci, instance_credential(uci, instance));
	let cur = validate_wg_key(uci.get('network', iface, 'private_key'));
	if (key && key == cur)
		return null;
	if (key) {
		if (!uci.get('network', iface))
			uci.set('network', iface, 'interface');
		uci.set('network', iface, 'proto', 'wireguard');
		uci.set('network', iface, 'vpn_type', 'nordvpn');
		uci.set('network', iface, 'private_key', key);
		uci.set('network', iface, 'addresses', [ FIXED_ADDRESS ]);
		uci.delete('network', iface, 'nordvpn_token');
		return 'set';
	}
	if (cur == null)
		return null;
	run([ 'ifdown', iface ]);
	let peer = find_peer(uci, iface);
	if (peer)
		uci.delete('network', peer);
	uci.delete('network', iface, 'private_key');
	uci.set('network', iface, 'auto', '0');
	return 'cleared';
}

// Sync every instance on entry `id` and commit. A live tunnel whose key
// changed is restarted so netifd loads it. Records one event per instance.
function sync_users(uci, id) {
	let changed = false;
	for (let name in users(uci, id)) {
		let r = sync_instance(uci, name);
		if (!r)
			continue;
		changed = true;
		uci.commit('network');
		// Only a tunnel that already had a server needs restarting; a fresh
		// interface waits for its first apply.
		let st = load_settings(uci, name);
		if (r == 'set' && st.enabled && find_peer(uci, st.interface))
			run([ 'ifup', st.interface ]);
		record_event(name, r == 'set' ? 'credentials_set' : 'credentials_cleared');
	}
	return changed;
}

// Resolve which entry a set request targets. `credential` names an existing
// entry (or 'default'); `name` alone creates a new one; `instance` alone means
// the entry that instance uses; nothing means 'default'.
function target(uci, credential, name, instance) {
	if (credential != null && credential != '') {
		let id = validate_instance(credential);
		if (!id || !exists(uci, id))
			return { error: 'no such credentials' };
		return { id: id, create: false };
	}
	if (name != null && name != '') {
		for (let e in list(uci))
			if (lc(e.name) == lc(name))
				return { error: 'credentials named "' + e.name + '" already exist' };
		return { id: make_id(name, entry_ids(uci)), create: true };
	}
	if (instance != null && instance != '')
		return { id: instance_credential(uci, instance), create: false };
	return { id: DEFAULT_ID, create: false };
}

// Exchange `token` for the account key and store it in the bank entry chosen
// by target(), then push it to every instance on that entry. Returns
// { ok, credential, name } or { error }.
function set(uci, token, credential, name, instance) {
	if (name != null && name != '') {
		name = validate_name(name);
		if (!name)
			return { error: 'invalid name' };
	}
	let t = target(uci, credential, name, instance);
	if (t.error)
		return t;
	let res = _api.get_private_key(token);
	if (res.error)
		return res;

	ensure_file();
	uci.set(PKG, t.id, 'credential');
	if (t.create || name)
		uci.set(PKG, t.id, 'name', name);
	else if (t.id == DEFAULT_ID && !uci.get(PKG, t.id, 'name'))
		uci.set(PKG, t.id, 'name', DEFAULT_NAME);
	uci.set(PKG, t.id, 'private_key', res.private_key);
	uci.commit(PKG);
	sync_users(uci, t.id);
	return { ok: true, credential: t.id, name: uci.get(PKG, t.id, 'name') };
}

// Drop the key of bank entry `id` but keep the entry; every instance on it
// goes down until a new token is stored.
function clear_key(uci, id) {
	id = validate_instance(id);
	if (!id || !exists(uci, id))
		return { error: 'no such credentials' };
	if (uci.get(PKG, id) != null) {
		uci.delete(PKG, id, 'private_key');
		uci.commit(PKG);
	}
	sync_users(uci, id);
	return { ok: true, credential: id };
}

// Remove bank entry `id`. 'default' cannot go, so it only loses its key; any
// other entry must not be in use.
function remove(uci, id) {
	id = validate_instance(id);
	if (!id || !exists(uci, id))
		return { error: 'no such credentials' };
	if (id == DEFAULT_ID)
		return clear_key(uci, id);
	let used = users(uci, id);
	if (length(used))
		return { error: 'still used by ' + join(', ', used) + '; switch them to other credentials first' };
	uci.delete(PKG, id);
	uci.commit(PKG);
	return { ok: true, credential: id };
}

// One-time move from per-interface keys to the bank. The first configured
// instance (main first) seeds 'default'; an instance holding a different key
// gets its own entry named after it. Idempotent: does nothing once 'default'
// has a key. Returns true when it changed anything.
function migrate(uci) {
	if (key_of(uci, DEFAULT_ID))
		return false;
	let def = null, changed = false;
	for (let name in list_instances(uci)) {
		let iface = validate_interface(load_settings(uci, name).interface);
		let key = (iface && managed_interface(uci, iface)) ?
			validate_wg_key(uci.get('network', iface, 'private_key')) : null;
		if (!key)
			continue;
		ensure_file();
		if (def == null || key == def) {
			if (def == null) {
				def = key;
				uci.set(PKG, DEFAULT_ID, 'credential');
				uci.set(PKG, DEFAULT_ID, 'name', DEFAULT_NAME);
				uci.set(PKG, DEFAULT_ID, 'private_key', key);
			}
			uci.delete('nordvpn', name, 'credential');
		} else {
			let id = make_id(name, entry_ids(uci));
			uci.set(PKG, id, 'credential');
			uci.set(PKG, id, 'name', clean_label(name) || name);
			uci.set(PKG, id, 'private_key', key);
			uci.set('nordvpn', name, 'credential', id);
		}
		changed = true;
	}
	if (changed) {
		uci.commit(PKG);
		uci.commit('nordvpn');
	}
	return changed;
}

return {
	PKG, DEFAULT_ID, DEFAULT_NAME,
	validate_name, make_id, list, instance_credential, exists,
	sync_instance, sync_users, set, clear_key, remove, migrate
};
