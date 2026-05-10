# [<img src="https://ipinfo.io/static/ipinfo-small.svg" alt="IPinfo" width="24"/>](https://ipinfo.io/lite.) IPinfo Lite PowerShell Module

This is an open-source PowerShell module for interacting with the [IPinfo Lite API](https://ipinfo.io/developers/lite-api). IPinfo Lite provides free, unlimited access to accurate, daily-updated country-level geolocation and ASN data for both IPv4 and IPv6 addresses. This module is independently developed and not officially affiliated with IPinfo.

## Features
- Retrieve geolocation and ASN info for any IP address
- Batch query multiple IP addresses
- Export data in LLM-optimized JSONL format for AI analysis
- Enhanced Data Validation
- In-memory query cache for performance
- Structured output enabling seamless integration into scripting environments, automation frameworks, and reporting systems

## Getting Started

You will need an IPinfo Lite API access token, which you can get by signing up for a free account at [https://ipinfo.io/signup](https://ipinfo.io/signup).

## Installation
This module has been tested on PowerShell 7 (Core) and Windows PowerShell 5.1 (Desktop) across ARM and Intel architectures.


The latest version is published on the Microsoft PowerShell Gallery:  
[https://www.powershellgallery.com/packages/IPInfoLite](https://www.powershellgallery.com/packages/IPInfoLite)


### Install the Module
Install using the default command provided by the Microsoft PowerShell Gallery:
```powershell
Install-Module -Name IPInfoLite
```

If you encounter permission or policy-related issues, install the module for the current user:
```powershell
Install-Module -Name IPInfoLite -Scope CurrentUser -Force
```

### PowerShell 7 installation help

If you need assistance installing PowerShell 7 on Windows, refer to Microsoft’s official documentation [Microsoft Learn: Installing PowerShell on Windows](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows?view=powershell-7.5)

## Supply Chain Security

This project includes a Software Bill of Materials (SBOM) to support supply chain transparency and integrity verification. An SBOM is a structured inventory of all components, files, and metadata that make up a software package, enabling users to verify exactly what is included in the software they install.

The SBOM is published in [SPDX 2.3](https://spdx.dev/) format, an open standard recognized as ISO/IEC 5962:2021. SPDX is maintained by the Linux Foundation and is the SBOM format natively supported by GitHub. It is widely used across government, enterprise, and open source ecosystems for license compliance, vulnerability tracking, and supply chain risk management.

The SBOM file (`IPInfoLite-3.1.0.spdx.json`) is located in the repository root and covers all files included in the distribution package published to the PowerShell Gallery. Each file entry includes a SHA256 checksum that can be used to verify the integrity of installed module files against the published SBOM.


## What’s New in v3.2.0

### Added
- Added a progress bar to `Get-IPInfoLiteBatch` using `Write-Progress`, showing chunk progress, IP totals, and completion percentage. The display is automatically disabled in non-interactive sessions and is safe for pipeline operations.

### Changed
- `Get-IPInfoLiteEntry` Both the `/me` endpoint and standard IP lookup paths now route through `Invoke-RestRequest` rather than calling `Invoke-RestMethod` directly, bringing them in line with `Get-IPInfoLiteBatch` with full retry logic, exponential backoff with jitter, `Retry-After` handling, and timeout protection via `apiTimeoutSec`.

- `Invoke-RestRequest` Broadened the success response check from a strict `-eq 200` comparison to the HTTP-compliant `-ge 200 -and -lt 300` range check, and updated the returned object to reflect the actual status code rather than a hardcoded `200`. The IPinfo Lite API currently returns `200` for all successful responses so there is no behavioural change, but this ensures correctness as the API evolves.

- `Bogon Detection` Expanded the bogon range file from 20 to 56 ranges, aligned with
  [IPinfo's bogon definitions](https://ipinfo.io/bogon) for consistent filtering behaviour. IPv4 coverage grew from 14 to 16 ranges, adding `127.0.53.53/32` (name collision) and `192.0.0.0/24` (IETF assignments). IPv6 coverage grew from 6 to 40 ranges, adding 7 core reserved ranges plus 6to4 and Teredo tunnel representations of all IPv4 bogon ranges. The file was also restructured with a metadata section (version, date, and source references) and each range now includes `AddressFamily`, `Description`, and `RFC` fields, making it self-documenting.

- `Test-BogonIP` Refactored to accept a pre-parsed `[System.Net.IPAddress]` object rather than a string, giving it a single responsibility of bogon determination. The internal `TryParse` call and invalid-format `Write-Warning` were removed, with format validation moved to each calling function. `Get-IPInfoLiteEntry` gained explicit `TryParse` validation that throws a structured terminating error on invalid format or bogon input. `Get-IPInfoLiteBatch` was updated to pass its already-parsed `$ipObj` directly, eliminating a redundant `TryParse` call per IP across every batch run. Error handling in both functions follows the module pattern: terminating for single entry, non-terminating for batch.

- `Test-IPInCIDR` Added `[CmdletBinding()]` for consistency with `Test-BogonIP` and to enable `-Verbose` and `-Debug` support, `[Parameter(Mandatory)]` on all three parameters to make the function contract explicit, and `[ValidateRange(0, 128)]` on `$PrefixLength` to reject out-of-bounds values before they reach the bitwise calculation. Explanatory comments were added to the byte length mismatch check and bitwise mask calculation for maintainability.

- `Initialize-BogonRanges` / `Test-BogonIP` Updated `Initialize-BogonRanges` to read the new bogon file structure and split ranges into `$Script:BogonRangesIPv4` and `$Script:BogonRangesIPv6` at load time using the `AddressFamily` field, eliminating runtime address family determination. `Test-BogonIP` now selects the appropriate pre-split list based on the input IP's address family, eliminating iteration over non-matching ranges. The plain string `throw` in `Initialize-BogonRanges` was replaced with a typed `ErrorRecord`, consistent with the module error handling pattern.

- `Initialize-CountryFlagTable` Replaced the plain string `throw` with a typed `New-ErrorRecord` using `ERR_FLAGS_FILE_NOT_FOUND` and `ResourceUnavailable` category. Added a guard after `ConvertFrom-Json` for the case where the file exists but is empty or unparseable, producing a clear `ERR_FLAGS_FILE_EMPTY` error with `InvalidData` category rather than failing silently or surfacing a confusing runtime error downstream.

- `Cache Storage` Changed the backing store from `[Hashtable]` to
  `[System.Collections.Generic.Dictionary[string,object]]`, bringing three improvements: strong typing on string keys consistent with the generic collections used elsewhere in the module; improved string key lookup performance; and native `TryGetValue` support, eliminating the double lookup pattern in `Get()` where `ContainsKey` was followed by a redundant index access. The class comment claimed `TryGetValue` was already in use. This change makes that accurate.

- `Cache` `Get-IPInfoLiteBatch` and `Get-IPInfoLiteEntry` were updated to use the single `Get()` and `$null` check pattern, replacing the previous `ContainsKey` + `Get()` double lookup. Cache hit object handling was also improved, replacing the `Select-Object *` full object rebuild and reflection-based `Add-Member` call with `PSObject.Copy()` and direct property assignment.

### Fixed
- `Invoke-RestRequest` Fixed `Retry-After` header extraction, which was unconditionally using the PS 5.1 string indexer pattern against `$resp.Headers`. On PS 7+ this silently returned `$null` because `HttpResponseHeaders` does not support string indexer access, causing the server's requested delay to be ignored and exponential backoff to proceed with a misleading "no Retry-After" warning. Extraction is now handled per version branch: `TryGetValues` on `HttpResponseHeaders` for PS 7+ and the string indexer on `WebHeaderCollection` for PS 5.1 and plain `WebException` paths ensuring the server-requested delay is correctly honoured on both PS versions.

- `Invoke-RestRequest` `$resp`, `$statusCode`, and `$retryAfter` are now explicitly reset at the top of each retry iteration to prevent stale values leaking between attempts. Previously, a response object from one iteration could be consumed by the `switch` statement on the next, a stale `$retryAfter` could carry over to a subsequent 429 where no header was present, and `$statusCode` had a type inconsistency between its pre-loop initialisation (`0`) and its in-catch reset (`$null`). All three are now reset to consistent typed values at the start of each iteration.

- `Invoke-RestRequest` Added `apiTimeoutSec` to `$script:config.apiRetry` (default: `30`) and applied it to `Invoke-WebRequest` via `-TimeoutSec`, using the parameter alias that works correctly across PS 5.1 and PS 7.4+. Previously, `Invoke-WebRequest` had no timeout, so a hung connection could block indefinitely regardless of retry configuration, rendering the retry logic ineffective.

- `Invoke-RestRequest` Fixed a backoff delay bug where `[math]::Pow()` and `[math]::Min()` return `Double`, causing three related issues: fractional seconds were passed to `Start-Sleep` despite the backoff being designed for whole-second intervals; when `$maxDelay` reached `$HardMaxBackoff` the `+1` added for `Get-Random` could push the value one second over the hard cap; and `Start-Sleep` handles fractional values inconsistently across PS versions; PS 5.1 silently truncates while PS 7+ honours them, producing different sleep durations for the same calculation. An `[int]` cast after `[math]::Min()` resolves all three simultaneously. Applied to all three backoff paths: network failure, 429 with no `Retry-After`, and 502/503/504.

- `QueryCache` Refactored `$Records` and `$KeyOrder` from static to instance members. Previously all instances silently shared the same storage, making multi-instance behaviour unpredictable and causing `Clear()` to wipe shared data while only resetting stats on the calling instance. Each instance now owns its data and stats exclusively, making `Clear()` fully self-contained. The static reference `[QueryCache]::Records.Count` in `Get-IPInfoLiteCache` was updated to `$script:QueryCache.Count` to reflect the change.

- `Get-IPInfoLiteBatch` Fixed a logic ordering issue where `ProcessedCacheIPs` was checked after the cache lookup rather than before it, causing duplicate IPs to generate unnecessary cache operations and inflate hit and miss counters. The `HashSet` check now occurs first, a cheaper operation, before the cache is touched. `ProcessedCacheIPs.Add()` was also extended to cover both cache hit and cache miss paths, ensuring every first-occurrence valid IP is tracked and all subsequent duplicates are suppressed before reaching the cache or incrementing any counter. Stats from `Get-IPInfoLiteCache` now accurately reflect unique IP lookups only.


## Usage

| Function | Description | Example | 
| ----------- | ----------- | ----------- |
| Get-IPInfoLiteEntry | Retrieves country-level geolocation and ASN details for a single IP via the IPinfo Lite API. | `Get-IPInfoLiteEntry -token "your_token_here" -ip "8.8.8.8"` |
| Get-IPInfoLiteBatch | Retrieves country-level geolocation and ASN details for multiple IP addresses using the IPinfo Batch API. | `Get-IPInfoLiteBatch -Token "your_token_here" -ips @("8.8.8.8", "1.1.1.1") -ErrorVariable ipInfoErrors` |
| Export-IPInfoLiteLLM  | Exports IP data in JSONL format optimized for Large Language Model (LLM) analysis. Supports LLM driven threat detection and pattern recognition. | `Get-IPInfoLiteBatch -Token $token -IPs $ips \| Export-IPInfoLiteLLM -Path "analysis.jsonl"` |
| Get-IPInfoLiteCache |  Returns current statistics from the IPInfoLite query cache including entry count, cache hits, and evictions. | `Get-IPInfoLiteCache` |
| Clear-IPInfoLiteCache | Clears all cached query results. Use this function to resolve issues caused by stale or incorrect data. Supports the standard PowerShell `WhatIf` and `Confirm` parameters. | `Clear-IPInfoLiteCache` |

## LLM Driven Analysis

The IPInfoLite PowerShell module supports exporting query results in JSONL format designed for analysis with Large Language Models such as Claude, ChatGPT, and Gemini. This supports LLM-assisted workflows for security analysis, threat investigation, and pattern identification.

### Quick Start

#### 1. Query IP addresses from your logs
```powershell
$suspiciousIPs = Get-Content "firewall_blocks.txt"
$ipData = Get-IPInfoLiteBatch -Token $token -IPs $suspiciousIPs
```

#### 2. Export for LLM analysis
```powershell
$ipData | Export-IPInfoLiteLLM -Path "threat_analysis.jsonl"
```

#### 3. Upload threat_analysis.jsonl to your LLM platform:
- Claude: https://claude.ai
- ChatGPT: https://chat.openai.com
- Gemini: https://gemini.google.com

#### 4. Ask Questions

Example prompts to try:
- "Which countries account for the highest volume of observed activity?"
- "Are there observable patterns in the ASNs associated with these IPs?"

### Why Use LLM Analysis?

Traditional analysis typically requires writing a new query or script for each question, filtering, pivoting, and formatting results as an investigation evolves. LLM analysis provides a natural-language interface for exploratory analysis and reporting, enabling faster iteration and easier generation of narrative summaries. For high-confidence results, validate key findings using your preferred analytical tools and repeatable queries.


**Advantages of LLM Analysis:**
- Upload once per session and perform iterative natural-language analysis  
- Generate narrative threat intelligence reports  
- No coding required for ad-hoc analysis  
- Contextual anomaly identification and correlation analysis  


### Supported LLM Platforms

- **[Claude](https://claude.ai)** (Anthropic) - Upload via Claude chat or Projects  
- **[ChatGPT](https://chat.openai.com)** (OpenAI) - Upload via web interface or API 
- **[Gemini](https://gemini.google.com)** (Google) - Google AI Studio or Vertex AI
- **Custom RAG Systems** - Any system capable of consuming JSONL-formatted data

*JSONL data is analyzed as structured text and is subject to session and context size limits.*


## Output Structure
Queries return a `[PSCustomObject]` with the following fields:

- `IP`
- `ASN`
- `ASN_Name`
- `ASN_Domain`
- `Country`
- `Country_Code`
- `Country_Flag_Emoji`
- `Country_Flag_Unicode`
- `Continent`
- `Continent_Code`
- `CacheHit` *(Boolean)*


## IPInfoLiteBatchParallel
`Get-IPInfoLiteBatchParallel` has been deprecated as of version 2.0.0. With the introduction of the official [IPinfo Batch API](https://ipinfo.io/developers/advanced-usage), performing parallel requests sequentially no longer provides meaningful performance gains. Version 1.3.0 of the module will remain available indefinitely for users who have integrated it into existing workflows; however, transitioning to `Get-IPInfoLiteBatch` is strongly recommended to take full advantage of the Batch API’s native performance and efficiency.

## Caching

The IPInfoLite module includes a built-in caching system that minimizes redundant API calls and improves performance. When an IP address is queried, its geolocation and ASN data are stored in an in-memory cache. Subsequent lookups for the same IP within the current session are served directly from the cache, reducing API load and improving response time.

The cache can be managed using the following commands:

- `Get-IPInfoLiteCache` - Returns current statistics about the query cache.
- `Clear-IPInfoLiteCache` - Removes all previously cached query results.

 Caching behavior is fully automatic and requires no configuration.


## License
This module is released under the [MIT License](https://opensource.org/licenses/MIT). You may use, modify, and distribute it freely.

## Author
Ryan Terp
📧 ryan.terp@gmail.com
