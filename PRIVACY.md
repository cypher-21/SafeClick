# SafeClick Privacy Policy

# SafeClick Privacy Policy

Last updated: 2026-09-14

SafeClick 2.0 is an open-source, local-first browser security engine designed to analyze websites directly on your device to protect against phishing, credential harvesting, malware downloads, and brand impersonation. We adhere to a strict zero-telemetry, zero-cloud-cost privacy architecture.

## What data we access
- Active tab URLs and domain structures (for local lexical, entropy, and trust scoring)
- Page DOM structures (for detecting insecure password submission forms, cross-origin targets, and fake Browser-in-Browser dialogs)
- Locally stored extension preferences, user allowlist, and site security history (saved strictly in `chrome.storage.local`)

## What we do NOT collect or transmit
- **Zero Browsing Telemetry**: We do not collect, log, sell, or transmit your visited URLs, search queries, or browsing history to any server. There are no SafeClick backend analytics servers.
- **Zero Form or Credential Access**: Passwords and keystrokes are never read, copied, or transmitted. Credential monitors operate locally solely to detect if a password input is submitting to an unencrypted or cross-origin destination.
- **100% Local Processing**: URL lexical parsing, machine learning inference (24-feature logistic model), Bloom filter threat matching, and brand lookalike detection run exclusively on your CPU.

## AI Advisory Privacy Guarantees
- **Chrome Built-in AI (Gemini Nano)**: Runs 100% locally on-device inside your browser process via Chrome's Prompt API. No network requests are made; prompts and telemetry never leave your machine.
- **Bring Your Own Key (BYOK) Cloud AI**: If you optionally choose to provide your own Google Gemini API key, it is encrypted and saved strictly in your private local storage (`chrome.storage.local`). When consulted, only sanitized security indicators (never raw webpage HTML or DOM content) are sent directly to Google's official API endpoint.
- **Local Synthesis Fallback**: When offline or if no AI engine is configured, SafeClick uses a local deterministic rule-synthesis engine with zero network calls.

## Permissions justification
- `tabs`, `activeTab`: Used to inspect the current tab's security posture and display status badges.
- `storage`, `unlimitedStorage`: Used to store local settings, threat feed Bloom filters, and local history.
- `scripting`: Injects DOM security analyzers and SERP enhancement badges into webpages.
- `webRequest`, `webNavigation`: Used to track redirect chains and present the warning interstitial before malicious navigation completes.
- `alarms`: Used to periodically stream and update open-source threat feeds (URLhaus, OpenPhish) directly from authoritative sources.
- `host_permissions` (`http://*/*`, `https://*/*`): Required to inspect URLs and inject protection content scripts across web destinations.

## Data retention
- Security scan history is stored exclusively on your device in `chrome.storage.local`.
- You can review, export, or permanently delete your security history at any time through the SafeClick dashboard.

## Third parties
- **Zero Third-Party Analytics**: No Google Analytics, no tracking pixels, no advertising frameworks.
- **Public Threat Intelligence Feeds**: SafeClick directly fetches open threat feeds (URLhaus, OpenPhish) to hydrate local Bloom filters. No user-specific data or queries are transmitted during feed downloads.

## Contact & Open Source
SafeClick is open-source under the Apache 2.0 License. Issues and inquiries can be submitted at:
https://github.com/cypher-21/SafeClick
