'use strict';

/**
 * Focused unit tests for the pure parsing/classification logic in popup.js.
 * Run with: node --test tests
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  parseIpv4,
  parseIpv6,
  classifyAddress,
  isInternalHostname,
  isIpLiteral,
  normalizeHostname,
  dnsStatusMessage,
  parseDnsResponse,
  AppError,
} = require('../popup.js');

test('parseIpv4 accepts valid addresses and rejects invalid ones', () => {
  assert.deepEqual(parseIpv4('1.2.3.4'), [1, 2, 3, 4]);
  assert.deepEqual(parseIpv4('255.255.255.255'), [255, 255, 255, 255]);
  assert.equal(parseIpv4('256.1.1.1'), null);
  assert.equal(parseIpv4('1.2.3'), null);
  assert.equal(parseIpv4('1.2.3.4.5'), null);
  assert.equal(parseIpv4('example.com'), null);
  assert.equal(parseIpv4(''), null);
  assert.equal(parseIpv4(null), null);
});

test('parseIpv6 accepts valid forms and rejects invalid ones', () => {
  assert.deepEqual(parseIpv6('::'), [0, 0, 0, 0, 0, 0, 0, 0]);
  assert.deepEqual(parseIpv6('::1'), [0, 0, 0, 0, 0, 0, 0, 1]);
  assert.deepEqual(
    parseIpv6('2001:db8::1'),
    [0x2001, 0x0db8, 0, 0, 0, 0, 0, 1]
  );
  assert.deepEqual(
    parseIpv6('2606:4700:4700::1111'),
    [0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111]
  );
  assert.deepEqual(
    parseIpv6('::ffff:192.168.0.1'),
    [0, 0, 0, 0, 0, 0xffff, 0xc0a8, 0x0001]
  );
  assert.equal(parseIpv6('2001:db8::1::2'), null);
  assert.equal(parseIpv6('2001:db8:1'), null);
  assert.equal(parseIpv6('gggg::1'), null);
  assert.equal(parseIpv6('example.com'), null);
  assert.equal(parseIpv6(null), null);
});

test('classifyAddress marks public IPv4 as public', () => {
  for (const ip of ['1.1.1.1', '8.8.8.8', '93.184.216.34']) {
    const result = classifyAddress(ip);
    assert.equal(result.valid, true, ip);
    assert.equal(result.family, 4, ip);
    assert.equal(result.isPublic, true, ip);
  }
});

test('classifyAddress rejects private and special-use IPv4', () => {
  const blocked = [
    '0.0.0.0',
    '10.0.0.1',
    '100.64.0.1',
    '127.0.0.1',
    '169.254.1.1',
    '172.16.0.1',
    '172.31.255.255',
    '192.0.0.1',
    '192.0.2.1',
    '192.88.99.1',
    '192.168.1.1',
    '198.18.0.1',
    '198.19.255.255',
    '198.51.100.1',
    '203.0.113.1',
    '224.0.0.1',
    '239.255.255.255',
    '240.0.0.1',
    '255.255.255.255',
  ];
  for (const ip of blocked) {
    const result = classifyAddress(ip);
    assert.equal(result.valid, true, ip);
    assert.equal(result.isPublic, false, ip);
    assert.notEqual(result.reason, '', ip);
  }
  // 172.32.x.x is outside the private /12 and remains public.
  assert.equal(classifyAddress('172.32.0.1').isPublic, true);
});

test('classifyAddress marks public IPv6 as public', () => {
  for (const ip of ['2606:4700:4700::1111', '2001:4860:4860::8888', '2a00:1450:4001::1']) {
    const result = classifyAddress(ip);
    assert.equal(result.valid, true, ip);
    assert.equal(result.family, 6, ip);
    assert.equal(result.isPublic, true, ip);
  }
});

test('classifyAddress rejects special-use IPv6', () => {
  const blocked = [
    '::',
    '::1',
    '64:ff9b::1',
    '100::1',
    '2001::1',
    '2001:2::1',
    '2001:db8::1',
    '2001:10::1',
    '2001:20::1',
    'fc00::1',
    'fd12:3456::1',
    'fe80::1',
    'ff02::1',
  ];
  for (const ip of blocked) {
    const result = classifyAddress(ip);
    assert.equal(result.valid, true, ip);
    assert.equal(result.isPublic, false, ip);
    assert.notEqual(result.reason, '', ip);
  }
});

test('classifyAddress labels unspecified and loopback IPv6 precisely', () => {
  assert.equal(classifyAddress('::').reason, 'unspecified');
  assert.equal(classifyAddress('::1').reason, 'loopback');
});

test('mapped and compatible addresses are never native public IPv6 targets', () => {
  const mappedPrivate = classifyAddress('::ffff:192.168.1.1');
  assert.equal(mappedPrivate.valid, true);
  assert.equal(mappedPrivate.family, 6);
  assert.equal(mappedPrivate.isPublic, false);
  assert.equal(mappedPrivate.embeddedIpv4, '192.168.1.1');

  const mappedPublic = classifyAddress('::ffff:8.8.8.8');
  assert.equal(mappedPublic.isPublic, false);
  assert.equal(mappedPublic.embeddedIpv4, '8.8.8.8');

  const compatibleLoopback = classifyAddress('::127.0.0.1');
  assert.equal(compatibleLoopback.isPublic, false);
});

test('strict address parsing rejects ambiguous and malformed input', () => {
  for (const ip of ['01.2.3.4', '1.2.3.4 ', ' 1.2.3.4', '1.2.3.4\n',
    '2606:4700::1%eth0', '2606:4700::1%25eth0', '2606:4700::1 ',
    '1:2:3:4::5:6:7:8', '::1:2:3:4:5:6:7:8', '::ffff:008.8.8.8']) {
    assert.equal(classifyAddress(ip).valid, false, ip);
  }
});

test('IPv6 policy covers prefix boundaries and unallocated space', () => {
  for (const ip of ['64:ff9b:1::', '64:ff9b:1:ffff:ffff:ffff:ffff:ffff',
    '3fff::', '3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff', '4000::1',
    'fec0::1', '2002:808:808::1', '::8.8.8.8', '::ffff:808:808']) {
    assert.equal(classifyAddress(ip).isPublic, false, ip);
  }
  assert.equal(classifyAddress('3ffe:ffff::1').isPublic, true);
  assert.equal(classifyAddress('3fff:1000::1').isPublic, true);
});

test('special-use names are blocked on label boundaries', () => {
  for (const host of ['hidden.onion', 'name.alt', 'ONION.', 'home.arpa', 'x.home.arpa.', 'x.in-addr.arpa']) {
    assert.equal(isInternalHostname(host), true, host);
  }
  for (const host of ['notonion.com', 'onion.example.org', 'secret.company.com']) {
    assert.equal(isInternalHostname(host), false, host);
  }
});

test('DNS returns canonical addresses and counts malformed records', () => {
  const result = parseDnsResponse({ Status: 0, Answer: [
    { type: 28, data: '2606:4700:0000:0:0:0:0:ABCD' },
    { type: 28, data: '2606:4700::abcd' },
    { type: 28, data: '2606:4700::1%eth0' },
  ] }, 'AAAA');
  assert.deepEqual(result.addresses, ['2606:4700::abcd']);
  assert.equal(result.invalid, 1);
});

test('classifyAddress rejects non-addresses', () => {
  for (const value of ['example.com', '', 'not an ip', '1.2.3.4.5', null, undefined]) {
    const result = classifyAddress(value);
    assert.equal(result.valid, false, String(value));
    assert.equal(result.isPublic, false, String(value));
  }
});

test('isIpLiteral recognises literals only', () => {
  assert.equal(isIpLiteral('1.2.3.4'), true);
  assert.equal(isIpLiteral('2606:4700::1111'), true);
  assert.equal(isIpLiteral('example.com'), false);
  assert.equal(isIpLiteral('localhost'), false);
  assert.equal(isIpLiteral('999.1.1.1'), false);
});

test('isInternalHostname blocks localhost, single-label and internal names', () => {
  const blocked = [
    'localhost',
    'router',
    'printer.local',
    'gateway.localdomain',
    'intranet',
    'server.internal',
    'wiki.intranet',
    'nas.lan',
    'host.home',
    'vpn.corp',
    'db.private',
    'app.test',
    'bad.invalid',
    'docs.example',
  ];
  for (const host of blocked) {
    assert.equal(isInternalHostname(host), true, host);
  }
});

test('isInternalHostname allows public hostnames and IP literals', () => {
  for (const host of ['example.com', 'www.google.com', 'sub.domain.co.uk']) {
    assert.equal(isInternalHostname(host), false, host);
  }
  assert.equal(isInternalHostname('1.2.3.4'), false);
  assert.equal(isInternalHostname('2606:4700::1111'), false);
  assert.equal(isInternalHostname(''), false);
});

test('normalizeHostname strips brackets and trailing dot', () => {
  assert.equal(normalizeHostname('[2606:4700::1111]'), '2606:4700::1111');
  assert.equal(normalizeHostname('example.com.'), 'example.com');
  assert.equal(normalizeHostname(''), '');
  assert.equal(normalizeHostname(undefined), '');
});

test('dnsStatusMessage covers known RCODEs', () => {
  assert.match(dnsStatusMessage(1), /FORMERR/);
  assert.match(dnsStatusMessage(2), /SERVFAIL/);
  assert.match(dnsStatusMessage(4), /NOTIMP/);
  assert.match(dnsStatusMessage(5), /REFUSED/);
  assert.match(dnsStatusMessage(99), /status 99/);
});

test('parseDnsResponse extracts valid A records and filters the rest', () => {
  const result = parseDnsResponse(
    {
      Status: 0,
      Answer: [
        { name: 'example.com', type: 5, data: 'example.com' }, // CNAME ignored
        { name: 'example.com', type: 1, data: '93.184.216.34' },
        { name: 'example.com', type: 1, data: '93.184.216.34' }, // duplicate
        { name: 'example.com', type: 28, data: '2606:2800:220:1:248:1893:25c8:1946' }, // family mismatch
        { name: 'example.com', type: 1, data: 'not-an-ip' }, // invalid address
        { name: 'example.com', type: 1, data: 42 }, // non-string data
      ],
    },
    'A'
  );
  assert.equal(result.status, 'NOERROR');
  assert.deepEqual(result.addresses, ['93.184.216.34']);
});

test('parseDnsResponse extracts valid AAAA records', () => {
  const result = parseDnsResponse(
    {
      Status: 0,
      Answer: [
        { type: 1, data: '93.184.216.34' }, // family mismatch
        { type: 28, data: '2606:2800:220:1:248:1893:25c8:1946' },
      ],
    },
    'AAAA'
  );
  assert.deepEqual(result.addresses, ['2606:2800:220:1:248:1893:25c8:1946']);
});

test('parseDnsResponse maps NXDOMAIN to a coded AppError', () => {
  assert.throws(
    () => parseDnsResponse({ Status: 3 }, 'A'),
    (error) => error instanceof AppError && error.code === 'NXDOMAIN' && /does not exist/.test(error.message)
  );
});

test('parseDnsResponse surfaces SERVFAIL and REFUSED as AppErrors', () => {
  assert.throws(() => parseDnsResponse({ Status: 2 }, 'A'), /SERVFAIL/);
  assert.throws(() => parseDnsResponse({ Status: 5 }, 'A'), /REFUSED/);
});

test('parseDnsResponse rejects malformed responses', () => {
  assert.throws(() => parseDnsResponse(null, 'A'), AppError);
  assert.throws(() => parseDnsResponse([], 'A'), AppError);
  assert.throws(() => parseDnsResponse({}, 'A'), /status code/);
  assert.throws(() => parseDnsResponse({ Status: '0' }, 'A'), /status code/);
  assert.throws(() => parseDnsResponse({ Status: 0, TC: true }, 'A'), /truncated/);
  assert.throws(
    () => parseDnsResponse({ Status: 0, Answer: 'nope' }, 'A'),
    /malformed answer list/
  );
});

test('parseDnsResponse treats NOERROR/NODATA as an empty result', () => {
  assert.deepEqual(parseDnsResponse({ Status: 0 }, 'A').addresses, []);
  assert.deepEqual(parseDnsResponse({ Status: 0, Answer: [] }, 'A').addresses, []);
});
