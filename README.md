# Site IP Inspector (Chrome Extension)

A tiny Manifest V3 Chrome extension. Click the toolbar icon and the popup shows
information about the website in the currently active tab:

- site hostname
- IPv4 address (queried independently from IPv6)
- IPv6 address (queried independently from IPv4)
- public IP metadata for one public address: country, region, city, ISP, ASN and
  timezone

The UI has explicit loading, success and error states, so restricted pages,
missing hostnames and network/API failures produce readable messages instead of
a blank popup.

> **Accuracy note:** the addresses are resolved through **Google Public DNS**,
> not observed from the browser's own connection. They are *not* necessarily the
> endpoint the browser actually connects to. A VPN, proxy, split-horizon or
> system/corporate DNS resolver, a different DNS server, CDN anycast and DNS
> load balancing can all make the displayed addresses differ from the real
> connection. The popup repeats this note.

## Files

| File | Purpose |
| --- | --- |
| `manifest.json` | Manifest V3 definition and permissions. |
| `popup.html` | Popup markup (loading / result / error sections). |
| `popup.css` | Small, dependency-free, light/dark aware styles. |
| `popup.js` | Active-tab lookup, DNS resolution, IP classification, metadata lookup, rendering. |
| `tests/ip.test.js` | Node unit tests for the pure IP/hostname parsing logic. |
| `tests/orchestration.test.js` | Node integration tests for the popup flow, including strict metadata validation. |
| `README.md` | This document. |

## Install (unpacked)

1. Open `chrome://extensions` in Chrome (or any Chromium browser).
2. Enable **Developer mode** (top-right toggle).
3. Click **Load unpacked** and select the unpacked project folder that contains
   `manifest.json` and `icon.jpg`.
4. Pin the **Site IP Inspector** extension to the toolbar (puzzle-piece menu).

## Test

1. Open any regular website, for example `https://example.com`.
2. Click the **Site IP Inspector** icon.
3. The popup should show the hostname, IPv4 and/or IPv6 address, and metadata
   such as country/city/ISP/timezone.
4. Verify the error paths:
   - Open a `chrome://` page (e.g. `chrome://extensions`) and click the icon.
     A message explains that only `http://` and `https://` pages are inspected.
   - Disconnect the network and click the icon. A network error is shown.
   - Open an internal/intranet hostname (for example `http://router` or
     `http://printer.local`). A local/internal-address message is shown and the
     name is **not** sent to public DNS.
   - Open a page whose host is a private IP literal (for example
     `http://192.168.1.1`). A local/private-address message is shown and the
     address is **not** sent to ipwho.is.
5. Click **Try again** to re-run the lookup. Any in-flight lookup is cancelled
   first, so retries never overlap.

Run the automated checks:

```sh
node --check popup.js
node --test tests/ip.test.js tests/orchestration.test.js
```

Reload the extension from `chrome://extensions` after editing any file.

## Architecture and data sources

The popup is plain HTML/CSS/JS with no build step, no bundler and no remote
code. Logic lives in `popup.js`:

1. `chrome.tabs.query({ active: true, currentWindow: true })` reads the active
   tab. The `activeTab` permission grants temporary access to that tab's URL
   when the user clicks the action.
2. Only `http:` and `https:` URLs are inspected. Every other scheme
   (`chrome:`, `file:`, `data:`, `view-source:`, …) is rejected with a clear
   message.
3. Obvious local/internal names are rejected before any network call:
   `localhost`, any single-label hostname (for example `router`), and names
   ending in `.local`, `.localhost`, `.localdomain`, `.internal`, `.intranet`,
   `.lan`, `.home`, `.home.arpa`, `.corp`, `.private`, `.test`, `.invalid` or
   `.example`.
4. For public hostnames, the A and AAAA records are queried **independently and
   in parallel** against **Google Public DNS over HTTPS (JSON API)**:
   `https://dns.google/resolve?name=<hostname>&type=A` and `…&type=AAAA`.
   The DNS response is validated before use: the JSON object, the DNS `Status`
   code (`0` NOERROR, `2` SERVFAIL, `3` NXDOMAIN, `5` REFUSED and other
   non-zero codes), the `TC` truncation flag, the `Answer` array shape, each
   record's `type`, and the returned address itself. Malformed JSON or API
   responses become clear, user-facing errors. The endpoint is keyless and
   returns `Access-Control-Allow-Origin: *`.
5. Every returned address is parsed and classified as public (global unicast)
   or as loopback/private/link-local/CGNAT/documentation/benchmarking/
   multicast/reserved/special-use (IPv4 and IPv6, including IPv4-mapped and
   IPv4-compatible forms). **Only public addresses are kept.**
6. One public address (IPv4 preferred, otherwise IPv6) is enriched with
   **ipwho.is**: `https://ipwho.is/<ip>`. This is keyless, HTTPS-only and
   CORS-enabled. The JSON response is validated strictly before rendering: the
   object shape and `success === true` are required, and the types of every
   rendered field (`country`, `country_code`, `region`, `city`,
   `connection.isp`/`org`/`asn`, `timezone.id`/`utc`) are checked while
   documented optional fields may be missing or `null`. A malformed or
   unsuccessful response keeps the resolved hostname and addresses on screen
   and shows a metadata-unavailable/invalid note instead of claiming success.

Both endpoints were verified to return `Access-Control-Allow-Origin: *`, so the
extension needs **no host permissions** and keeps its permission list to a
single `activeTab` entry.

If the hostname is already a public IP literal, the DNS step is skipped and the
literal is classified directly. If DNS returns several addresses, the first of
each family is shown and the rest are listed as "Other addresses". If the
metadata lookup fails, the hostname and addresses are still shown with a note
explaining that metadata is unavailable.

## Permissions

- `activeTab` only. It is granted when the user clicks the extension icon and
  allows reading the active tab's URL. The extension does not request `tabs`,
  read browsing history, or inject scripts.

## Privacy and limits

The suffix checks are standards-oriented heuristics, not a complete detector for
corporate or split-horizon DNS. Standardized `.onion`, `.alt` and `.arpa` names are
blocked; unknown multi-label names require confirmation before public DNS is used.
The UI distinguishes no record, request failure and filtered non-public addresses,
and states explicitly when an IP literal bypasses DNS.

Data that leaves your machine:

- **Google Public DNS** (`dns.google`) receives the active tab's **hostname**
  (for public hostnames only) and the requested record type. Google therefore
  sees the query and your **public source IP address** (plus ordinary HTTP
  request metadata such as your browser/OS user agent, which the browser sends).
- **ipwho.is** receives the **public IP address** that was resolved. ipwho.is
  therefore also sees your **public source IP address** and request metadata.

Internal-host safeguards:

- `localhost`, single-label hostnames and the obvious internal suffixes listed
  above are never sent to Google Public DNS. The popup shows a local/internal
  message instead.
- Private, loopback, link-local, CGNAT, documentation, benchmarking, multicast,
  reserved and other special-use addresses are never sent to ipwho.is. The
  extension classifies every resolved address and refuses non-public ones.

Other notes:

- Requests are sent with `credentials: 'omit'`, `cache: 'no-store'` and
  `referrerPolicy: 'no-referrer'`. No cookies, credentials or page content are
  sent.
- Google Public DNS and ipwho.is are third-party public APIs. They can be rate
  limited, change their terms, or become unavailable; failures are surfaced in
  the popup rather than swallowed.
- The displayed address is what Google Public DNS returns, which for sites
  behind a CDN is a CDN edge address; the geolocation then describes the CDN,
  not the origin server. See the accuracy note at the top.
- `file://` pages and browser-internal pages (`chrome://`, `edge://`, etc.)
  cannot be inspected; the popup reports this clearly.

## Publishing to the Chrome Web Store

If you publish this extension, the Chrome Web Store requires:

- a **privacy policy** URL that discloses that the extension sends the active
  tab's hostname to Google Public DNS and a resolved public IP to ipwho.is, and
  that those providers can see the user's public IP address;
- an accurate **data-usage / permissions justification** (only `activeTab` is
  requested, and it is used solely to read the active tab's URL);
- the **limited use** certification, confirming the data is used only to
  provide the extension's single purpose;
- an accurate **single-purpose** description.

Review these requirements before publishing; they are the publisher's
responsibility.

## Static validation performed

- `manifest.json` parsed as valid JSON (manifest_version 3).
- `popup.js` and the test files checked with `node --check`.
- `node --test tests/ip.test.js tests/orchestration.test.js` passes (IPv4/IPv6
  parsing, public/special-use classification, internal-hostname detection,
  hostname normalisation, DNS status messages, and the popup orchestration flow
  including strict `success === true` metadata validation).
- `popup.html` DOM ids cross-checked against the ids referenced in `popup.js`.
- API endpoints checked for HTTPS and CORS (`Access-Control-Allow-Origin: *`).
