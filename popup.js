'use strict';

/**
 * Site IP Inspector - popup logic.
 *
 * Flow:
 *   1. Read the active tab and its URL (allowed by the activeTab permission).
 *   2. Reject anything that is not an http(s) page and anything that looks
 *      special-use; ask before sending other names (a heuristic is not proof).
 *   3. Resolve the hostname with Google Public DNS over HTTPS, querying A and
 *      AAAA independently and in parallel.
 *   4. Look up public metadata for one *public* address with the keyless
 *      ipwho.is API.
 *
 * Both APIs are public, HTTPS-only, keyless and CORS-enabled
 * (Access-Control-Allow-Origin: *), so the extension needs no host permissions.
 *
 * Privacy model:
 *   - Only public (global unicast) addresses are ever sent to ipwho.is.
 *   - Localhost, single-label hostnames and obvious internal names are never
 *     sent to Google Public DNS.
 *   - Requests omit credentials and the referrer.
 */

const DNS_ENDPOINT = 'https://dns.google/resolve';
const GEO_ENDPOINT = 'https://ipwho.is/';
const REQUEST_TIMEOUT_MS = 10000;

/** Only regular web pages can be inspected. */
const ALLOWED_PROTOCOLS = new Set(['http:', 'https:']);

/** DNS record type numbers returned by the Google Public DNS JSON API. */
const DNS_RECORD_TYPES = { A: 1, AAAA: 28 };

/** Suffixes that identify obviously local/internal names (never sent to DNS). */
const INTERNAL_SUFFIXES = [
  '.localhost',
  '.local',
  '.localdomain',
  '.internal',
  '.intranet',
  '.lan',
  '.home',
  '.home.arpa',
  '.corp',
  '.private',
  '.test',
  '.invalid',
  '.example',
  '.onion',
  '.alt',
  '.arpa', // Infrastructure/reverse DNS, not ordinary website names.
];

/**
 * IPv6 special-use prefixes (RFC 6890 / IANA registry) that must never be sent
 * to a public metadata provider. `bits` is the prefix length.
 */
const IPV6_SPECIAL_PREFIXES = [
  { address: '::', bits: 128, label: 'unspecified' },
  { address: '::1', bits: 128, label: 'loopback' },
  { address: '64:ff9b::', bits: 96, label: 'IPv4/IPv6 translation' },
  { address: '64:ff9b:1::', bits: 48, label: 'local-use translation' },
  { address: '100::', bits: 64, label: 'discard-only' },
  { address: '2001::', bits: 32, label: 'Teredo' },
  { address: '2001::', bits: 23, label: 'IETF protocol assignments (conservative policy)' },
  { address: '2002::', bits: 16, label: '6to4 transition' },
  { address: '3fff::', bits: 20, label: 'documentation' },
  { address: '2001:2::', bits: 48, label: 'benchmarking' },
  { address: '2001:db8::', bits: 32, label: 'documentation' },
  { address: '2001:10::', bits: 28, label: 'ORCHID' },
  { address: '2001:20::', bits: 28, label: 'ORCHIDv2' },
  { address: 'fc00::', bits: 7, label: 'unique local' },
  { address: 'fe80::', bits: 10, label: 'link-local' },
  { address: 'ff00::', bits: 8, label: 'multicast' },
].map((entry) => ({
  ...entry,
  value: ipv6GroupsToBigInt(parseIpv6(entry.address)),
}));

/** Error type for expected, user-friendly failures. */
class AppError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'AppError';
    this.code = code || '';
  }
}

/** Cached DOM references. */
const el = {};

/** Currently active lookup. Used to cancel stale work on Retry. */
let activeRun = null;

if (typeof document !== 'undefined') {
  document.addEventListener('DOMContentLoaded', () => {
    el.hostname = document.getElementById('site-hostname');
    el.status = document.getElementById('status');
    el.statusText = document.getElementById('status-text');
    el.result = document.getElementById('result');
    el.factHostname = document.getElementById('fact-hostname');
    el.factIpv4 = document.getElementById('fact-ipv4');
    el.factIpv6 = document.getElementById('fact-ipv6');
    el.factCountry = document.getElementById('fact-country');
    el.factRegion = document.getElementById('fact-region');
    el.factCity = document.getElementById('fact-city');
    el.factIsp = document.getElementById('fact-isp');
    el.factAsn = document.getElementById('fact-asn');
    el.factTimezone = document.getElementById('fact-timezone');
    el.addressNote = document.getElementById('address-note');
    el.metadataNote = document.getElementById('metadata-note');
    el.error = document.getElementById('error');
    el.errorText = document.getElementById('error-text');
    el.retry = document.getElementById('retry');
    el.confirm = document.getElementById('confirm');
    el.consent = document.getElementById('consent');
    el.sourceNote = document.getElementById('source-note');

    el.retry.addEventListener('click', init);
    init();
  });
}

/** Main entry point. Also used by the "Try again" button. */
async function init() {
  // Abort any in-flight lookup so Retry never leaves overlapping work.
  if (activeRun) {
    activeRun.controller.abort();
  }
  const run = { controller: new AbortController() };
  activeRun = run;

  setBusy('Reading the active tab\u2026');
  el.consent.hidden = true;
  fillMetadata({});
  try {
    const tab = await getActiveTab();
    ensureCurrent(run);

    const rawUrl = tab ? tab.url || tab.pendingUrl || '' : '';
    if (!rawUrl) {
      throw new AppError(
        'This page cannot be inspected. Open a regular http(s) website and try again.'
      );
    }

    const parsed = parseUrl(rawUrl);
    if (!parsed) {
      throw new AppError('The active tab does not have a valid URL.');
    }

    if (!ALLOWED_PROTOCOLS.has(parsed.protocol)) {
      throw new AppError(
        'Only http:// and https:// pages can be inspected. Open a regular website and try again.'
      );
    }

    const hostname = normalizeHostname(parsed.hostname);
    if (!hostname) {
      throw new AppError('The active tab has no hostname to look up.');
    }

    el.hostname.textContent = hostname;

    // Never leak localhost, single-label or obvious internal names to DNS.
    if (!isIpLiteral(hostname) && isInternalHostname(hostname)) {
      throw new AppError(
        '"' +
          hostname +
          '" looks like a local or internal address. It is not sent to public DNS, ' +
          'and no public metadata is available for it.'
      );
    }

    if (!isIpLiteral(hostname)) {
      await requestConsent(run);
      ensureCurrent(run);
    }
    setBusy(isIpLiteral(hostname) ? 'Checking IP literal\u2026' : 'Resolving IP address\u2026');
    const resolution = await resolveHostname(hostname, run);
    ensureCurrent(run);

    showResult();
    fillBasic(hostname, resolution);

    if (!resolution.primary) {
      setMetadataNote('No public address available for metadata.');
      return;
    }

    setMetadataNote('Loading public IP metadata\u2026');
    try {
      const metadata = await lookupIpMetadata(resolution.primary, run);
      ensureCurrent(run);
      fillMetadata(metadata);
      setMetadataNote(
        'Public metadata describes ' +
          resolution.primary +
          ' (IPv' +
          resolution.primaryFamily +
          ').'
      );
    } catch (metadataError) {
      ensureCurrent(run);
      if (isAbortError(metadataError)) {
        throw metadataError;
      }
      // The IP is still useful, so keep it and only flag missing metadata.
      setMetadataNote(friendlyMessage(metadataError));
    }
  } catch (error) {
    if (isAbortError(error) || activeRun !== run) {
      return; // Superseded by a newer run; nothing to render.
    }
    showError(friendlyMessage(error));
  } finally {
    if (activeRun === run) {
      activeRun = null;
    }
  }
}

/** Returns the active tab of the current window. */
async function getActiveTab() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  return tabs && tabs[0] ? tabs[0] : null;
}

/**
 * Resolves a hostname to public IPv4 and IPv6 addresses.
 * A and AAAA are queried independently and in parallel.
 */
async function resolveHostname(hostname, run) {
  ensureCurrent(run);
  hostname = normalizeHostname(hostname);
  if (!isIpLiteral(hostname) && isInternalHostname(hostname)) {
    throw new AppError('This special-use or local hostname is not sent to public DNS.');
  }
  if (isIpLiteral(hostname)) {
    const classification = classifyAddress(hostname);
    if (!classification.isPublic) {
      throw new AppError(
        hostname +
          ' is a ' +
          classification.reason +
          ' address. Public metadata is not available for local, private or ' +
          'special-use addresses.'
      );
    }
    return {
      source: 'literal',
      families: {},
      ipv4: classification.family === 4 ? [classification.normalized] : [],
      ipv6: classification.family === 6 ? [classification.normalized] : [],
      primary: classification.normalized,
      primaryFamily: classification.family,
      blocked: [],
    };
  }

  const [aResult, aaaaResult] = await Promise.allSettled([
    queryDns(hostname, 'A', run),
    queryDns(hostname, 'AAAA', run),
  ]);
  ensureCurrent(run);

  const ipv4 = [];
  const ipv6 = [];
  const blocked = [];
  const families = {};

  const collect = (settled, family) => {
    const state = families[family] = { status: 'no-record', filtered: 0, invalid: 0 };
    if (settled.status === 'rejected') {
      const reason = settled.reason;
      if (isAbortError(reason)) {
        throw reason;
      }
      if (reason instanceof AppError && reason.code === 'NXDOMAIN') {
        state.status = 'nxdomain';
        return;
      }
      state.status = 'error';
      state.message = friendlyMessage(reason);
      return;
    }
    state.invalid = settled.value.invalid;
    for (const address of settled.value.addresses) {
      const classification = classifyAddress(address);
      if (!classification.valid) {
        continue;
      }
      if (!classification.isPublic) {
        blocked.push(address);
        state.filtered += 1;
        continue;
      }
      if (family === 4) {
        ipv4.push(address);
      } else {
        ipv6.push(address);
      }
      state.status = 'ok';
    }
    if (state.status !== 'ok' && (state.filtered || state.invalid)) state.status = 'filtered';
  };

  collect(aResult, 4);
  collect(aaaaResult, 6);

  const uniqueV4 = [...new Set(ipv4)];
  const uniqueV6 = [...new Set(ipv6)];

  const primaryFamily = uniqueV4.length > 0 ? 4 : 6;
  return {
    source: 'dns',
    families,
    ipv4: uniqueV4,
    ipv6: uniqueV6,
    primary: primaryFamily === 4 ? uniqueV4[0] : uniqueV6[0],
    primaryFamily,
    blocked,
  };
}

/** Queries Google Public DNS (JSON API) for one record type. */
async function queryDns(name, type, run) {
  const url = DNS_ENDPOINT + '?name=' + encodeURIComponent(name) + '&type=' + type;
  const response = await fetchWithTimeout(
    url,
    { headers: { Accept: 'application/dns-json' } },
    run
  );
  if (!response.ok) {
    throw new AppError(
      'The ' + type + ' DNS lookup failed (HTTP ' + response.status + ').'
    );
  }

  let data;
  try {
    data = await response.json();
  } catch (error) {
    throw new AppError('The DNS service returned a response that could not be parsed.');
  }

  return parseDnsResponse(data, type);
}

/**
 * Validates and normalizes a Google Public DNS JSON response for one record
 * type. Throws AppError with a clear message for malformed or failed responses.
 */
function parseDnsResponse(data, type) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    throw new AppError('The DNS service returned an unexpected response.');
  }
  if (typeof data.Status !== 'number') {
    throw new AppError('The DNS service response is missing a valid status code.');
  }

  if (data.Status === 3) {
    throw new AppError('The domain name does not exist (NXDOMAIN).', 'NXDOMAIN');
  }
  if (data.Status !== 0) {
    throw new AppError(dnsStatusMessage(data.Status), 'DNS_STATUS_' + data.Status);
  }
  if (data.TC === true) {
    throw new AppError(
      'The DNS response was truncated (TC flag set). Please try again.'
    );
  }
  if (data.Answer !== undefined && !Array.isArray(data.Answer)) {
    throw new AppError('The DNS service returned a malformed answer list.');
  }

  const expectedType = DNS_RECORD_TYPES[type];
  const addresses = [];
  let invalid = 0;
  for (const answer of data.Answer || []) {
    if (!answer || typeof answer !== 'object' || Array.isArray(answer)) {
      continue;
    }
    if (answer.type !== expectedType) {
      continue; // Ignore CNAME/other records and mismatched record types.
    }
    if (typeof answer.data !== 'string') {
      invalid += 1;
      continue;
    }
    const classification = classifyAddress(answer.data);
    if (!classification.valid || classification.family !== (type === 'A' ? 4 : 6)) {
      invalid += 1;
      continue; // Ignore records that do not hold a valid address of this family.
    }
    addresses.push(classification.normalized);
  }

  return { status: 'NOERROR', addresses: [...new Set(addresses)], invalid };
}

/** Maps a non-zero DNS RCODE to a readable message. */
function dnsStatusMessage(status) {
  switch (status) {
    case 1:
      return 'The DNS service reported a format error (FORMERR).';
    case 2:
      return 'The DNS service could not complete the lookup (SERVFAIL). Please try again.';
    case 4:
      return 'The DNS service does not support this query (NOTIMP).';
    case 5:
      return 'The DNS service refused the lookup (REFUSED).';
    default:
      return 'The DNS lookup failed with status ' + status + '.';
  }
}

/**
 * Looks up public geolocation/ISP metadata for an IP address.
 * Refuses to send anything that is not a public global-unicast address.
 */
async function lookupIpMetadata(ip, run) {
  const classification = classifyAddress(ip);
  if (!classification.valid || !classification.isPublic) {
    throw new AppError(
      'The address is not public, so it was not sent to the metadata provider.'
    );
  }

  const response = await fetchWithTimeout(
    GEO_ENDPOINT + encodeURIComponent(classification.normalized),
    { headers: { Accept: 'application/json' } },
    run
  );
  if (!response.ok) {
    throw new AppError('The IP metadata request failed (HTTP ' + response.status + ').');
  }

  let data;
  try {
    data = await response.json();
  } catch (error) {
    throw new AppError(
      'The IP metadata service returned a response that could not be parsed.'
    );
  }
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    throw new AppError('The IP metadata service returned an unexpected response.');
  }
  if (data.success !== true) {
    if (data.success === false) {
      throw new AppError(
        typeof data.message === 'string' && data.message
          ? data.message
          : 'No public metadata is available for this IP address.'
      );
    }
    throw new AppError('The IP metadata service returned an unexpected response.');
  }
  validateMetadataFields(data);
  return data;
}

/**
 * Validates the shape of a successful ipwho.is response. Only the fields that
 * rendering consumes are checked, and documented optional fields may be absent
 * or null. Throws AppError when a field has the wrong type or shape.
 */
function validateMetadataFields(data) {
  const invalid = () =>
    new AppError('The IP metadata service returned an invalid response.');
  const isOptionalString = (value) =>
    value === undefined || value === null || typeof value === 'string';
  const isOptionalAsn = (value) =>
    value === undefined ||
    value === null ||
    typeof value === 'string' ||
    (typeof value === 'number' && Number.isFinite(value));

  for (const key of ['country', 'country_code', 'region', 'city']) {
    if (!isOptionalString(data[key])) {
      throw invalid();
    }
  }

  if (data.connection !== undefined && data.connection !== null) {
    if (typeof data.connection !== 'object' || Array.isArray(data.connection)) {
      throw invalid();
    }
    if (
      !isOptionalString(data.connection.isp) ||
      !isOptionalString(data.connection.org) ||
      !isOptionalAsn(data.connection.asn)
    ) {
      throw invalid();
    }
  }

  if (data.timezone !== undefined && data.timezone !== null) {
    if (typeof data.timezone !== 'object' || Array.isArray(data.timezone)) {
      throw invalid();
    }
    if (!isOptionalString(data.timezone.id) || !isOptionalString(data.timezone.utc)) {
      throw invalid();
    }
  }
}

/**
 * fetch() with a per-request timeout that is also linked to the shared run
 * cancellation signal. A run abort (Retry) propagates as AbortError and is
 * ignored by the caller; a timeout becomes a friendly AppError.
 */
async function fetchWithTimeout(url, options, run) {
  const controller = new AbortController();
  const runSignal = run ? run.controller.signal : null;

  const abortFromRun = () => controller.abort();
  if (runSignal) {
    if (runSignal.aborted) {
      controller.abort();
    } else {
      runSignal.addEventListener('abort', abortFromRun, { once: true });
    }
  }

  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    return await fetch(url, {
      ...options,
      signal: controller.signal,
      cache: 'no-store',
      credentials: 'omit',
      referrerPolicy: 'no-referrer',
    });
  } catch (error) {
    if (error && error.name === 'AbortError') {
      if (runSignal && runSignal.aborted) {
        throw error; // Superseded run; let the caller discard it.
      }
      throw new AppError('The request timed out. Please try again.');
    }
    throw error;
  } finally {
    clearTimeout(timer);
    if (runSignal) {
      runSignal.removeEventListener('abort', abortFromRun);
    }
  }
}

/** Renders the hostname and the resolved IPv4/IPv6 addresses. */
function fillBasic(hostname, resolution) {
  setText(el.factHostname, hostname);
  setText(el.factIpv4, familyText(resolution, 4));
  setText(el.factIpv6, familyText(resolution, 6));
  el.sourceNote.textContent = resolution.source === 'literal'
    ? 'IP literal from the page URL. DNS was not queried.'
    : 'Addresses from Google Public DNS, not the browser connection. VPN, proxy, CDN or corporate DNS results may differ.';

  const extras = [];
  for (const family of [4, 6]) {
    const state = resolution.families[family];
    if (!state) continue;
    if (state.filtered) extras.push('IPv' + family + ': ' + state.filtered + ' non-public/special-use address(es) filtered');
    if (state.invalid) extras.push('IPv' + family + ': ' + state.invalid + ' malformed record(s) ignored');
    if (state.message) extras.push('IPv' + family + ': ' + state.message);
  }
  if (resolution.ipv4.length > 1) {
    extras.push('IPv4: ' + resolution.ipv4.slice(1).join(', '));
  }
  if (resolution.ipv6.length > 1) {
    extras.push('IPv6: ' + resolution.ipv6.slice(1).join(', '));
  }

  if (extras.length > 0) {
    el.addressNote.hidden = false;
    el.addressNote.textContent = extras.join(' \u00b7 ');
  } else {
    el.addressNote.hidden = true;
    el.addressNote.textContent = '';
  }
}

/** Renders the public metadata returned by ipwho.is. */
function fillMetadata(metadata) {
  setText(el.factCountry, formatCountry(metadata.country, metadata.country_code));
  setText(el.factRegion, metadata.region);
  setText(el.factCity, metadata.city);

  const connection = metadata.connection || {};
  setText(el.factIsp, connection.isp || connection.org);
  setText(el.factAsn, connection.asn ? 'AS' + connection.asn : '');

  const timezone = metadata.timezone || {};
  let timezoneText = timezone.id || '';
  if (timezone.id && timezone.utc) {
    timezoneText = timezone.id + ' (UTC' + timezone.utc + ')';
  }
  setText(el.factTimezone, timezoneText);
}

/* ------------------------------- UI helpers ------------------------------- */

function setBusy(message) {
  el.result.hidden = true;
  el.error.hidden = true;
  el.status.hidden = false;
  el.statusText.textContent = message;
}

function showResult() {
  el.status.hidden = true;
  el.result.hidden = false;
  el.error.hidden = true;
}

function showError(message) {
  el.status.hidden = true;
  el.result.hidden = true;
  el.error.hidden = false;
  el.errorText.textContent = message;
}

function setMetadataNote(message) {
  el.metadataNote.hidden = false;
  el.metadataNote.textContent = message;
}

function setText(node, value) {
  node.textContent =
    value === undefined || value === null || value === '' ? '\u2014' : String(value);
}

function formatCountry(country, code) {
  if (country && code) {
    return country + ' (' + code + ')';
  }
  return country || code || '';
}

/** Throws an AbortError-like error if this run is no longer the active one. */
function ensureCurrent(run) {
  if (activeRun !== run || run.controller.signal.aborted) {
    const error = new Error('The lookup was cancelled.');
    error.name = 'AbortError';
    throw error;
  }
}

function isAbortError(error) {
  return Boolean(error) && error.name === 'AbortError';
}

/* ------------------------------ Parsing utils ----------------------------- */

function parseUrl(value) {
  try {
    return new URL(value);
  } catch (error) {
    return null;
  }
}

/** Removes IPv6 brackets and a trailing dot from a URL hostname. */
function normalizeHostname(hostname) {
  if (!hostname) {
    return '';
  }
  return hostname.replace(/^\[/, '').replace(/\]$/, '').replace(/\.$/, '');
}

/** True for a valid IPv4 or IPv6 literal. */
function isIpLiteral(hostname) {
  return classifyAddress(hostname).valid;
}

/**
 * True for hostnames that must never be sent to public DNS: localhost,
 * single-label names and obvious internal/reserved suffixes.
 */
function isInternalHostname(hostname) {
  if (!hostname || isIpLiteral(hostname)) {
    return false;
  }
  const lower = normalizeHostname(hostname).toLowerCase();
  if (lower === 'localhost') {
    return true;
  }
  if (!lower.includes('.')) {
    return true; // Single-label hostnames resolve via local search domains.
  }
  return INTERNAL_SUFFIXES.some((suffix) => lower === suffix.slice(1) || lower.endsWith(suffix));
}

/* --------------------------- IP address handling -------------------------- */

/** Parses a dotted-quad IPv4 address into four octets, or null. */
function parseIpv4(value) {
  if (typeof value !== 'string') {
    return null;
  }
  if (/\s/.test(value)) return null;
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(value);
  if (!match) {
    return null;
  }
  if (match.slice(1).some((part) => part.length > 1 && part[0] === '0')) return null;
  const octets = match.slice(1).map((part) => Number(part));
  if (octets.some((octet) => octet > 255)) {
    return null;
  }
  return octets;
}

/** Parses an IPv6 address (including embedded IPv4) into eight 16-bit groups. */
function parseIpv6(value) {
  if (typeof value !== 'string') {
    return null;
  }
  if (/[\s%]/.test(value)) return null;
  let text = value;
  if (!text.includes(':')) {
    return null;
  }

  // Convert an embedded IPv4 tail (e.g. ::ffff:192.168.0.1) to two hex groups.
  const lastColon = text.lastIndexOf(':');
  const tail = text.slice(lastColon + 1);
  if (tail.includes('.')) {
    const v4 = parseIpv4(tail);
    if (!v4) {
      return null;
    }
    const high = ((v4[0] << 8) | v4[1]).toString(16);
    const low = ((v4[2] << 8) | v4[3]).toString(16);
    text = text.slice(0, lastColon + 1) + high + ':' + low;
  }

  const parts = text.split('::');
  if (parts.length > 2) {
    return null;
  }

  const parseGroups = (part) => {
    if (part === '') {
      return [];
    }
    const groups = [];
    for (const group of part.split(':')) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(group)) {
        return null;
      }
      groups.push(parseInt(group, 16));
    }
    return groups;
  };

  const head = parseGroups(parts[0]);
  if (head === null) {
    return null;
  }

  if (parts.length === 1) {
    return head.length === 8 ? head : null;
  }

  const tailGroups = parseGroups(parts[1]);
  if (tailGroups === null) {
    return null;
  }
  const missing = 8 - head.length - tailGroups.length;
  if (missing < 1) {
    return null;
  }
  return [...head, ...new Array(missing).fill(0), ...tailGroups];
}

function ipv6GroupsToBigInt(groups) {
  let value = 0n;
  for (const group of groups) {
    value = (value << 16n) | BigInt(group);
  }
  return value;
}

function matchesIpv6Prefix(value, prefixValue, prefixBits) {
  const shift = BigInt(128 - prefixBits);
  return value >> shift === prefixValue >> shift;
}

/** Returns a human-readable reason for a non-public IPv4 address, else ''. */
function ipv4SpecialReason(octets) {
  const [a, b, c] = octets;
  if (a === 0) return 'reserved (0.0.0.0/8)';
  if (a === 10) return 'private (10.0.0.0/8)';
  if (a === 100 && b >= 64 && b <= 127) return 'carrier-grade NAT (100.64.0.0/10)';
  if (a === 127) return 'loopback (127.0.0.0/8)';
  if (a === 169 && b === 254) return 'link-local (169.254.0.0/16)';
  if (a === 172 && b >= 16 && b <= 31) return 'private (172.16.0.0/12)';
  if (a === 192 && b === 0 && c === 0) return 'IETF protocol assignment (192.0.0.0/24)';
  if (a === 192 && b === 0 && c === 2) return 'documentation (192.0.2.0/24)';
  if (a === 192 && b === 88 && c === 99) return '6to4 relay anycast (192.88.99.0/24)';
  if (a === 192 && b === 168) return 'private (192.168.0.0/16)';
  if (a === 198 && (b === 18 || b === 19)) return 'benchmarking (198.18.0.0/15)';
  if (a === 198 && b === 51 && c === 100) return 'documentation (198.51.100.0/24)';
  if (a === 203 && b === 0 && c === 113) return 'documentation (203.0.113.0/24)';
  if (a >= 224) return 'multicast or reserved (224.0.0.0/4)';
  return '';
}

/**
 * Classifies an IPv4/IPv6 literal.
 * Returns { valid, family, isPublic, reason, embeddedIpv4? }.
 */
function classifyAddress(value) {
  const v4 = parseIpv4(value);
  if (v4) {
    const reason = ipv4SpecialReason(v4);
    return { valid: true, family: 4, isPublic: !reason, reason, normalized: v4.join('.') };
  }

  const groups = parseIpv6(value);
  if (!groups) {
    return { valid: false, family: 0, isPublic: false, reason: '' };
  }

  // Handle the unspecified and loopback addresses explicitly so they are not
  // mistaken for deprecated IPv4-compatible addresses.
  if (groups.every((group) => group === 0)) {
    return { valid: true, family: 6, isPublic: false, reason: 'unspecified', normalized: '::' };
  }
  if (groups.slice(0, 7).every((group) => group === 0) && groups[7] === 1) {
    return { valid: true, family: 6, isPublic: false, reason: 'loopback', normalized: '::1' };
  }

  const isMapped =
    groups[0] === 0 &&
    groups[1] === 0 &&
    groups[2] === 0 &&
    groups[3] === 0 &&
    groups[4] === 0 &&
    groups[5] === 0xffff;
  const isCompatible =
    groups[0] === 0 &&
    groups[1] === 0 &&
    groups[2] === 0 &&
    groups[3] === 0 &&
    groups[4] === 0 &&
    groups[5] === 0;

  if (isMapped || isCompatible) {
    const embedded = [
      (groups[6] >> 8) & 0xff,
      groups[6] & 0xff,
      (groups[7] >> 8) & 0xff,
      groups[7] & 0xff,
    ];
    const embeddedIpv4 = embedded.join('.');
    const reason = ipv4SpecialReason(embedded);
    const prefix = isMapped ? 'IPv4-mapped ' : 'IPv4-compatible ';
    return {
      valid: true,
      family: 6,
      isPublic: false,
      normalized: normalizeIpv6(groups),
      reason: prefix + (reason || 'not a native IPv6 metadata target'),
      embeddedIpv4,
    };
  }

  const value128 = ipv6GroupsToBigInt(groups);
  for (const prefix of IPV6_SPECIAL_PREFIXES) {
    if (matchesIpv6Prefix(value128, prefix.value, prefix.bits)) {
      return { valid: true, family: 6, isPublic: false, reason: prefix.label, normalized: normalizeIpv6(groups) };
    }
  }

  // Current ordinary global-unicast allocation. Fail closed for other space.
  const isPublic = (groups[0] & 0xe000) === 0x2000;
  return { valid: true, family: 6, isPublic, normalized: normalizeIpv6(groups),
    reason: isPublic ? '' : 'outside ordinary global-unicast allocation' };
}

function normalizeIpv6(groups) {
  return new URL('http://[' + groups.map((group) => group.toString(16)).join(':') + ']/').hostname.slice(1, -1);
}

function familyText(resolution, family) {
  const addresses = family === 4 ? resolution.ipv4 : resolution.ipv6;
  if (addresses.length) return addresses[0];
  if (resolution.source === 'literal') return 'Not applicable (IP literal)';
  return { 'no-record': 'No record', nxdomain: 'No record (NXDOMAIN)',
    error: 'DNS request failed', filtered: 'No usable public address (filtered)' }[resolution.families[family].status];
}

/** Consent is per popup lookup, never remembered for unknown corporate names. */
function requestConsent(run) {
  el.status.hidden = true;
  el.consent.hidden = false;
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      el.confirm.removeEventListener('click', accept);
      run.controller.signal.removeEventListener('abort', cancel);
    };
    const accept = () => { cleanup(); el.consent.hidden = true; resolve(); };
    const cancel = () => { cleanup(); reject(Object.assign(new Error('Cancelled'), { name: 'AbortError' })); };
    el.confirm.addEventListener('click', accept);
    run.controller.signal.addEventListener('abort', cancel, { once: true });
  });
}

/* ------------------------------- Error utils ------------------------------ */

function friendlyMessage(error) {
  if (error instanceof AppError) {
    return error.message;
  }
  if (error instanceof TypeError) {
    return 'Network request failed. Check your internet connection and try again.';
  }
  return 'Something went wrong while loading the IP information.';
}

/* ------------------------- Node test-only exports ------------------------- */

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    AppError,
    parseIpv4,
    parseIpv6,
    classifyAddress,
    isInternalHostname,
    isIpLiteral,
    normalizeHostname,
    dnsStatusMessage,
    parseDnsResponse,
  };
}
