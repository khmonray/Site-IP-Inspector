'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, '../popup.js'), 'utf8');

// Minimal DOM contract, not a browser emulator. Exercise the actual init flow.
function harness(url, fetchImpl) {
  const nodes = new Map();
  let ready;
  const document = {
    addEventListener(type, handler) { ready = handler; },
    getElementById(id) {
      if (!nodes.has(id)) nodes.set(id, {
        textContent: '', hidden: true, listeners: new Set(),
        addEventListener(type, handler) { this.listeners.add(handler); },
        removeEventListener(type, handler) { this.listeners.delete(handler); },
        click() { for (const handler of [...this.listeners]) handler(); },
      });
      return nodes.get(id);
    },
  };
  const calls = [];
  const context = vm.createContext({ document, URL, AbortController, setTimeout, clearTimeout,
    chrome: { tabs: { query: async () => [{ url }] } },
    fetch: async (target, options) => {
      calls.push(target);
      assert.equal(options.credentials, 'omit');
      assert.equal(options.referrerPolicy, 'no-referrer');
      return fetchImpl(target, options);
    },
  });
  vm.runInContext(source, context);
  ready();
  return { nodes, calls, context, node: (id) => document.getElementById(id) };
}
const tick = () => new Promise((resolve) => setImmediate(resolve));
const response = (data) => ({ ok: true, json: async () => data });
const dns = (type, data) => response({ Status: 0, Answer: data.map((ip) => ({ type, data: ip })) });

test('protocol allowlist and blocked names suppress all network traffic', async () => {
  for (const url of ['chrome://extensions', 'file:///tmp/a', 'ftp://public.com',
    'data:text/plain,hi', 'http://router', 'https://secret.onion', 'http://name.alt',
    'http://home.arpa', 'http://10.0.0.1', 'http://[::ffff:8.8.8.8]']) {
    const h = harness(url, () => { throw new Error('Unexpected network'); });
    await tick();
    assert.equal(h.calls.length, 0, url);
    assert.equal(h.node('error').hidden, false, url);
  }
});

test('unknown corporate names require explicit consent; partial failure remains useful', async () => {
  const h = harness('https://secret.company.com/path', (url) => {
    if (url.includes('type=AAAA')) throw new TypeError('offline');
    if (url.includes('type=A')) return dns(1, ['8.8.8.8']);
    return response({ success: true, country: 'Example' });
  });
  await tick();
  assert.equal(h.calls.length, 0);
  assert.equal(h.node('consent').hidden, false);
  h.node('confirm').click();
  await tick();
  assert.equal(h.calls.length, 3);
  assert.equal(h.node('fact-ipv4').textContent, '8.8.8.8');
  assert.equal(h.node('fact-ipv6').textContent, 'DNS request failed');
  assert.equal(h.node('result').hidden, false);
});

test('no-record, filtering, malformed data and NXDOMAIN have distinct presentation', async () => {
  for (const [reply, expected] of [
    [() => dns(28, []), 'No record'],
    [() => dns(28, ['3fff::1', '::ffff:8.8.8.8']), 'No usable public address (filtered)'],
    [() => dns(28, ['2606:4700::1%eth0']), 'No usable public address (filtered)'],
    [() => response({ Status: 3 }), 'No record (NXDOMAIN)'],
  ]) {
    const h = harness('https://www.google.com', (url) => {
      if (url.includes('type=AAAA')) return reply();
      if (url.includes('type=A')) return dns(1, ['8.8.8.8', '10.0.0.1']);
      return response({ success: true, country: 'Example' });
    });
    await tick(); h.node('confirm').click(); await tick();
    assert.equal(h.node('fact-ipv6').textContent, expected);
    assert.match(h.node('address-note').textContent, /non-public/);
    assert.equal(h.calls.filter((url) => url.startsWith('https://ipwho.is/')).length, 1);
  }
});

test('no usable family still displays both outcomes without metadata', async () => {
  const h = harness('https://www.google.com', (url) => url.includes('type=AAAA')
    ? Promise.reject(new Error('failure')) : dns(1, ['10.0.0.1']));
  await tick(); h.node('confirm').click(); await tick();
  assert.equal(h.calls.length, 2);
  assert.match(h.node('fact-ipv4').textContent, /filtered/);
  assert.match(h.node('fact-ipv6').textContent, /failed/);
  assert.match(h.node('metadata-note').textContent, /No public address/);
});

test('public IP literal skips DNS and has honest source presentation', async () => {
  const h = harness('https://[2606:4700:0:0:0:0:0:1111]/', () => response({ success: true }));
  await tick();
  assert.deepEqual(h.calls, ['https://ipwho.is/2606%3A4700%3A%3A1111']);
  assert.match(h.node('source-note').textContent, /DNS was not queried/);
  assert.match(h.node('fact-ipv4').textContent, /Not applicable/);
});

test('retry aborts pending fetch and stale metadata failure cannot overwrite new UI', async () => {
  let rejectOld;
  let oldSignal;
  const h = harness('https://8.8.8.8', (url, options) => {
    if (!rejectOld) {
      oldSignal = options.signal;
      return new Promise((resolve, reject) => { rejectOld = reject; });
    }
    return response({ success: true, country: 'New result' });
  });
  await tick();
  await vm.runInContext('init()', h.context);
  assert.equal(oldSignal.aborted, true);
  rejectOld(new Error('Stale network failure'));
  await tick();
  assert.equal(h.node('fact-country').textContent, 'New result');
  assert.match(h.node('metadata-note').textContent, /Public metadata describes/);
});

test('retry while awaiting consent removes stale click handler', async () => {
  const h = harness('https://www.google.com', (url) => url.includes('dns.google') ? dns(1, []) : response({ success: true }));
  await tick();
  vm.runInContext('init()', h.context);
  await tick();
  assert.equal(h.node('confirm').listeners.size, 1);
  h.node('confirm').click(); await tick();
  assert.equal(h.calls.length, 2);
});

test('valid metadata requires success:true and renders every consumed field', async () => {
  const h = harness('https://8.8.8.8', () => response({
    success: true,
    country: 'United States',
    country_code: 'US',
    region: 'California',
    city: 'Mountain View',
    connection: { isp: 'Google LLC', org: 'Google LLC', asn: 15169 },
    timezone: { id: 'America/Los_Angeles', utc: '-07:00' },
  }));
  await tick();
  assert.equal(h.calls.length, 1);
  assert.equal(h.node('result').hidden, false);
  assert.equal(h.node('fact-country').textContent, 'United States (US)');
  assert.equal(h.node('fact-region').textContent, 'California');
  assert.equal(h.node('fact-city').textContent, 'Mountain View');
  assert.equal(h.node('fact-isp').textContent, 'Google LLC');
  assert.equal(h.node('fact-asn').textContent, 'AS15169');
  assert.equal(h.node('fact-timezone').textContent, 'America/Los_Angeles (UTC-07:00)');
  assert.match(h.node('metadata-note').textContent, /Public metadata describes/);
});

test('optional metadata fields may be missing or null', async () => {
  const h = harness('https://8.8.8.8', () => response({
    success: true,
    country: null,
    country_code: null,
    region: null,
    city: null,
    connection: null,
    timezone: null,
  }));
  await tick();
  assert.equal(h.node('result').hidden, false);
  assert.equal(h.node('fact-country').textContent, '\u2014');
  assert.equal(h.node('fact-isp').textContent, '\u2014');
  assert.equal(h.node('fact-timezone').textContent, '\u2014');
  assert.match(h.node('metadata-note').textContent, /Public metadata describes/);
});

test('malformed or unsuccessful metadata preserves the resolved IP', async () => {
  const cases = [
    [{}, /unexpected response/i],
    [{ success: 'false' }, /unexpected response/i],
    [{ success: false }, /No public metadata is available/i],
    [{ success: false, message: 'Reserved range.' }, /Reserved range/],
    [{ success: true, country: 123 }, /invalid response/i],
    [{ success: true, country_code: 42 }, /invalid response/i],
    [{ success: true, region: {} }, /invalid response/i],
    [{ success: true, city: ['Mountain View'] }, /invalid response/i],
    [{ success: true, connection: 'nope' }, /invalid response/i],
    [{ success: true, connection: [] }, /invalid response/i],
    [{ success: true, connection: { isp: 5 } }, /invalid response/i],
    [{ success: true, connection: { org: false } }, /invalid response/i],
    [{ success: true, connection: { asn: {} } }, /invalid response/i],
    [{ success: true, timezone: 'nope' }, /invalid response/i],
    [{ success: true, timezone: [] }, /invalid response/i],
    [{ success: true, timezone: { id: 5 } }, /invalid response/i],
    [{ success: true, timezone: { utc: [] } }, /invalid response/i],
  ];
  for (const [payload, expected] of cases) {
    const h = harness('https://8.8.8.8', () => response(payload));
    await tick();
    const label = JSON.stringify(payload);
    assert.equal(h.calls.length, 1, label);
    assert.equal(h.node('result').hidden, false, label);
    assert.equal(h.node('fact-ipv4').textContent, '8.8.8.8', label);
    assert.match(h.node('metadata-note').textContent, expected, label);
    assert.doesNotMatch(h.node('metadata-note').textContent, /Public metadata describes/, label);
  }
});

test('static manifest and DOM contract stay minimal', () => {
  const root = path.join(__dirname, '..');
  const manifest = JSON.parse(fs.readFileSync(path.join(root, 'manifest.json'), 'utf8'));
  assert.equal(manifest.manifest_version, 3);
  assert.deepEqual(manifest.permissions, ['activeTab']);
  assert.equal(manifest.host_permissions, undefined);
  const html = fs.readFileSync(path.join(root, 'popup.html'), 'utf8');
  const ids = [...html.matchAll(/\bid="([^"]+)"/g)].map((match) => match[1]);
  assert.equal(new Set(ids).size, ids.length);
  for (const match of source.matchAll(/getElementById\('([^']+)'\)/g)) assert.ok(ids.includes(match[1]), match[1]);
});
