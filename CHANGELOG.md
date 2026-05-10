# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [3.2.0] - 2026-05-09
### Added
- `Get-IPInfoLiteBatch` Added `Write-Progress` to display a live progress bar during batch processing, showing chunk position, IP counts, and percentage complete. Invisible in non-interactive hosts and pipeline-safe.
  

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



## [3.1.0] - 2026-03-08
### Added
- An SPDX 2.3 SBOM (`IPInfoLite-3.1.0.spdx.json`) is now included with the module, providing a complete inventory of distributed files with SHA256 checksums for integrity verification.
  

### Changed
- API authentication has been migrated from URL query parameters to HTTP Bearer token headers. Tokens are no longer embedded in request URLs, preventing potential exposure through proxy logs, server access logs, or PowerShell verbose output. This change improves credential handling while requiring no action from users.

- `Export-IPInfoLiteLLM` ASN values are now exported as numeric identifiers (`8075` instead of `AS8075`) to reduce token usage and improve consistency for analytical queries.


### Fixed
- `$attempt`, `$statusCode`, and `$lastErrorMessage` were inadvertently initialized twice in consecutive blocks. The second initialization reset `$statusCode` from `0` to `$null`, altering downstream behavior. The final return evaluates `$statusCode -ne 0` as its guard condition, which could be satisfied unexpectedly when `$statusCode` was `$null`. The duplicate initialization block has been removed to ensure a consistent variable state and correct evaluation of the return condition.

- The `Test-BogonIP` function declared its parameter as `-IPAddress`, but callers invoked it using `-ip`. Callers have been updated to use `-IPAddress` to match the function definition and ensure consistent parameter usage.

- The `Export-IPInfoLiteLLM` `begin` block, validation failures (nonexistent directory or pre-existing output file) called `$PSCmdlet.WriteError()` followed by `return`. In advanced functions, `return` inside a `begin` block only exits the `begin` block; the `process` block will still execute for each pipeline item. This allowed the function to continue attempting to write records even after validation failed. The code has been updated to use `$PSCmdlet.ThrowTerminatingError($errorRecord)` to ensure the function terminates immediately when validation fails.


## [3.0.1] - 2026-01-19
### Fixed
- Fixed a packaging/documentation oversight from v3.0.0.


## [3.0.0] - 2026-01-19
### Added
- `Export-IPInfoLiteLLM` exports IP geolocation data in JSONL format optimized for analysis with Large Language Models (Claude, ChatGPT, Gemini). This supports LLM driven threat detection, pattern recognition, and security analysis workflows.
  
### Fixed
- Fixed boolean return values from `HashSet.Add()` leaking into results by adding `[void]` cast to suppress output during cache processing in `Get-IPInfoLiteBatch`.


## [2.0.0] - 2025-10-05
### Added
- `Get-IPInfoLiteBatch` Now uses the [IPinfo Batch API Endpoint](https://ipinfo.io/developers/batch-enrichment-api), significantly improving performance when querying large sets of IP addresses.

### Changed
- For IPinfo Batch API calls, the module now implements robust retry logic that automatically retries transient network and service errors (502, 503, 504) using exponential backoff with jitter to prevent retry storms, respects HTTP 429 responses by honoring the server’s Retry-After header, and fails fast on unrecoverable HTTP 500 errors. These improvements make API requests more resilient, reduce network congestion during transient failures.

- Previous versions only checked for bogon addresses. Version 2 introduces comprehensive pre-processing that automatically filters out invalid entries such as domain names, malformed IPs, and empty values before sending requests to the IPinfo Lite API. Deduplication has also been added to ensure a clean, optimized list of IP addresses is processed.

- Starting with version 2.0.0, IPInfoLite cmdlets follow PowerShell’s standard error model. Failed requests no longer appear as objects with SUCCESS = $false; instead, errors are emitted as structured ErrorRecord objects through the PowerShell error stream.

### Removed

- `Get-IPInfoLiteBatchParallel` has been deprecated as of version 2.0.0. With the introduction of the official IPinfo Batch API, performing parallel requests sequentially no longer provides meaningful performance gains. Version 1.3.0 of the module will remain available indefinitely for users who have integrated it into existing workflows; however, transitioning to Get-IPInfoLiteBatch is strongly recommended to take full advantage of the Batch API’s native performance and efficiency.

## [1.3.0] - 2025-06-15
### Added
- Added support for country flags, including both emoji and Unicode representations, to improve readability in reports and visual outputs.

### Fixed
- Implemented enhanced handling of network and API-related issues, increasing robustness.

### Changed
- Optimized the `Get-IPInfoLiteBatchParallel` function for improved speed and efficiency during parallel execution.

[Unreleased]: https://github.com/00destruct0/IPInfoLite/compare/v3.2.0...HEAD
[3.2.0]: https://github.com/00destruct0/IPInfoLite/compare/v3.1.0...v3.2.0
[3.1.0]: https://github.com/00destruct0/IPInfoLite/compare/v3.0.1...v3.1.0
[3.0.1]: https://github.com/00destruct0/IPInfoLite/compare/v3.0.0...v3.0.1
[3.0.0]: https://github.com/00destruct0/IPInfoLite/compare/v2.0.0...v3.0.0
[2.0.0]: https://github.com/00destruct0/IPInfoLite/compare/v1.3.0...v2.0.0
[1.3.0]: https://github.com/00destruct0/IPInfoLite/releases/tag/v1.3.0