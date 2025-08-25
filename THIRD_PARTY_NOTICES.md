# SafeClick – Third-Party Notices and Attributions

This document lists third‑party materials included with, or referenced by, the SafeClick extension, along with their respective licenses and required attributions.

- Project: SafeClick – Website Trust Scanner (`manifest.json` name: "SafeClick - Website Trust Scanner")
- Homepage: https://github.com/cypher-21/SafeClick
- License: MIT (see `LICENSE`)

## Included/Referenced Data Sources

The extension ships with curated, offline threat‑intelligence bundles in `data/` (production) and uses parsing logic in `reputation-db.js` and `phishtank.js`.

Important: Sample/fixture files under `tests/fixtures/` are for development only and are not included in production builds.

### 1) OISD Blocklist
- Website: https://oisd.nl/
- Files: `data/oisd_big_abp.txt` (Adblock Plus syntax)
- Terms (summary): Free to use with attribution; the author notes non‑commercial restrictions and specific usage guidance on the site. Please consult the OISD web page for the latest terms before distribution or commercial use.
- Attribution: "This product includes data from the OISD blocklist (https://oisd.nl/)."
- Notes: The file uses Adblock Plus (ABP) network filter syntax; only network rules are parsed, not cosmetic/exception rules.

### 2) URLhaus (abuse.ch)
- Website: https://urlhaus.abuse.ch/
- Typical download page: https://urlhaus.abuse.ch/downloads/
- Files (by format): bundled via `data/csv.txt` when curated from URLhaus exports (see `data/README.txt` for format guidance)
- License: CC0 1.0 (public domain) as documented by URLhaus
- Attribution (requested): "This product uses data from URLhaus (abuse.ch)."
- Notes: Even though CC0 does not require attribution, attribution is appreciated. Ensure the dataset timestamp/source URL is recorded during updates.

### 3) PhishTank
- Website: https://www.phishtank.com/
- Files: `phishtank-seed.csv` (bundled seed for offline phishing host detection), used by `phishtank.js`
- Terms: Please review the PhishTank Terms of Use for data redistribution requirements and attribution language. Historically, PhishTank data usage required attribution; verify current terms before distribution.
- Attribution (example): "This product includes data derived from PhishTank (www.phishtank.com)."

## Formats and Standards Referenced

### Adblock Plus Syntax
- The OISD list is provided in Adblock Plus (ABP) network filter syntax. "Adblock Plus" is a trademark of eyeo GmbH. Reference: https://help.eyeo.com/adblockplus/how-to-write-filters

## Icons, Trademarks, and Branding
- SafeClick icons under `icons/` are part of this project unless otherwise noted. Trademarks and logos are not covered by the MIT license; do not imply endorsement by third parties.

## Update Procedure (Maintainers)
- Record for each dataset update:
  - Source URL(s)
  - Fetch date/time (UTC)
  - Applied filters/curation steps
  - Resulting file name(s) in `data/`
- Re‑validate the license/terms at the data source prior to publishing updates.
- Update this file accordingly.

## Distribution Note
- Production builds include only curated bundles in `data/`. Sample/fixture data resides under `tests/fixtures/` and is not shipped.

## Contact
For questions about third‑party attributions, please open an issue at the project homepage.
