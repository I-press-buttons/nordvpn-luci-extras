'use strict';
'require baseclass';
'require dom';
'require rpc';

/* SPDX-License-Identifier: MIT
 * Status → Overview card: one row per NordVPN instance. Uses the backend's
 * lightweight `overview` method (no routing detection, no network access) on
 * every poll, and the cached location list once per page for display names.
 */

// LuCI's E() hands a bare string child to innerHTML; route every string
// through a text node instead (same helper as view/nordvpn/overview.js).
var E = function(html, attr, data) {
	if (!(attr instanceof Object) || Array.isArray(attr))
		data = attr, attr = null;
	if (data != null && typeof(data) !== 'function' && !Array.isArray(data) && !dom.elem(data))
		data = [ '' + data ];
	return dom.create(html, attr || {}, data);
};

// A missing backend or ACL answers with an error status; `expect` turns that
// into an empty list, so the card simply stays hidden.
var callOverview = rpc.declare({ object: 'nordvpn', method: 'overview', expect: { instances: [] } });
var callLocations = rpc.declare({ object: 'nordvpn', method: 'locations', expect: { countries: [] } });

var STATES = {
	connected:      [ _('Connected'),      'var(--success-color,#2d8f4e)' ],
	connecting:     [ _('Connecting'),     'var(--warning-color,#b8860b)' ],
	degraded:       [ _('Degraded'),       'var(--warning-color,#b8860b)' ],
	no_egress:      [ _('No internet'),    'var(--warning-color,#b8860b)' ],
	disconnected:   [ _('Disconnected'),   'var(--error-color,#c0392b)' ],
	disabled:       [ _('Disabled'),       'var(--text-color-medium,#666)' ],
	not_configured: [ _('Not configured'), 'var(--text-color-medium,#666)' ]
};

function fmtBytes(n) {
	var units = [ 'B', 'KB', 'MB', 'GB', 'TB' ];
	var i = 0;
	n = Math.max(0, n || 0);
	while (n >= 1024 && i < units.length - 1) {
		n /= 1024;
		i++;
	}
	return (i ? n.toFixed(n < 10 ? 1 : 0) : '' + Math.round(n)) + ' ' + units[i];
}

function fmtDuration(sec) {
	sec = Math.max(0, Math.floor(sec));
	if (sec < 60)
		return _('%d s').format(sec);
	if (sec < 3600)
		return _('%d min').format(Math.floor(sec / 60));
	if (sec < 86400)
		return _('%d h %d min').format(Math.floor(sec / 3600), Math.floor(sec % 3600 / 60));
	return _('%d d %d h').format(Math.floor(sec / 86400), Math.floor(sec % 86400 / 3600));
}

function countryFlag(code) {
	if (typeof code !== 'string' || !/^[A-Za-z]{2}$/.test(code))
		return '';
	var c = code.toLowerCase();
	return String.fromCodePoint(0x1F1E6 + (c.charCodeAt(0) - 97), 0x1F1E6 + (c.charCodeAt(1) - 97));
}

return baseclass.extend({
	title: _('NordVPN'),

	__init__: function() {
		// Location display names ({ cc: { name, cities: { slug: name } } }),
		// fetched once: the list comes from the multi-megabyte server cache.
		this.names = null;
		// Previous byte counters per instance, for the throughput column.
		this.samples = {};
		this.shown = false;
	},

	load: function() {
		var names = this.names ? Promise.resolve(this.names) :
			L.resolveDefault(callLocations(), []).then(L.bind(function(countries) {
				var map = {};
				(Array.isArray(countries) ? countries : []).forEach(function(c) {
					var cities = {};
					(c.cities || []).forEach(function(ct) { cities[ct.code] = ct.name; });
					map[c.code] = { name: c.name, cities: cities };
				});
				return (this.names = map);
			}, this));
		return Promise.all([ L.resolveDefault(callOverview(), []), names ]);
	},

	// Byte rate since the previous poll, or null. A new server, a restarted
	// interface (counters went backwards) or a long gap starts over.
	rate: function(st) {
		var x = st.transfer, now = Date.now();
		var prev = this.samples[st.instance];
		if (!x) {
			delete this.samples[st.instance];
			return null;
		}
		this.samples[st.instance] = { t: now, gw: st.gateway, rx: x.rx_bytes, tx: x.tx_bytes };
		var dt = prev ? (now - prev.t) / 1000 : 0;
		if (!prev || prev.gw !== st.gateway || dt < 1 || dt > 60 ||
		    x.rx_bytes < prev.rx || x.tx_bytes < prev.tx)
			return null;
		return { rx: (x.rx_bytes - prev.rx) / dt, tx: (x.tx_bytes - prev.tx) / dt };
	},

	place: function(loc) {
		loc = loc || {};
		var c = (this.names || {})[loc.country] || {};
		var city = (c.cities || {})[loc.city];
		var parts = [ city, c.name || (loc.country ? loc.country.toUpperCase() : null) ].filter(Boolean);
		var flag = countryFlag(loc.country);
		return parts.length ? (flag ? flag + ' ' : '') + parts.join(', ') : '—';
	},

	render: function(data) {
		var list = (data && Array.isArray(data[0])) ? data[0] : [];
		var configured = list.filter(function(st) { return st.configured; });

		// The page never re-hides a card it has shown, so once visible say
		// so instead of leaving stale rows behind.
		if (!configured.length) {
			if (!this.shown)
				return null;
			return E('p', {}, E('em', {}, _('No NordVPN instance is configured.')));
		}
		this.shown = true;

		var multi = list.length > 1;
		var head = [ _('Status'), _('Location'), _('Server'), _('Up'), _('Traffic') ];
		if (multi)
			head.unshift(_('Instance'));

		var rows = configured.map(L.bind(function(st) {
			var key = (st.enabled === false) ? 'disabled' : (st.state || 'not_configured');
			var info = STATES[key] || [ _('Unknown'), 'var(--text-color-medium,#666)' ];
			var live = (st.enabled !== false && st.state !== 'disconnected');
			var traffic = '—';
			var r = this.rate(st);
			if (st.transfer) {
				traffic = '↓ %s ↑ %s'.format(fmtBytes(st.transfer.rx_bytes), fmtBytes(st.transfer.tx_bytes));
				if (r && (r.rx >= 1 || r.tx >= 1))
					traffic += ' (↓ %s/s ↑ %s/s)'.format(fmtBytes(r.rx), fmtBytes(r.tx));
			}
			var cells = [
				E('td', { 'class': 'td', 'data-title': _('Status') },
					E('span', { style: 'color:' + info[1] + ';font-weight:600' }, info[0])),
				E('td', { 'class': 'td', 'data-title': _('Location') }, live ? this.place(st.location) : '—'),
				E('td', { 'class': 'td', 'data-title': _('Server') }, (live && st.gateway) || '—'),
				E('td', { 'class': 'td', 'data-title': _('Up') },
					(live && st.uptime != null) ? fmtDuration(st.uptime) : '—'),
				E('td', { 'class': 'td', 'data-title': _('Traffic') }, live ? traffic : '—')
			];
			if (multi)
				cells.unshift(E('td', { 'class': 'td', 'data-title': _('Instance') }, st.instance));
			return E('tr', { 'class': 'tr' }, cells);
		}, this));

		return E([], [
			E('table', { 'class': 'table' }, [
				E('tr', { 'class': 'tr table-titles' }, head.map(function(h) {
					return E('th', { 'class': 'th' }, h);
				}))
			].concat(rows)),
			E('div', { 'class': 'right', style: 'margin-top:.4em' },
				E('a', { href: L.url('admin', 'vpn', 'nordvpn') }, _('Manage NordVPN') + ' →'))
		]);
	}
});
