# [<img src="https://ipinfo.io/static/ipinfo-small.svg" alt="IPinfo" width="24"/>](https://ipinfo.io/lite.) IPinfo Lite PowerShell Module

This is an open-source PowerShell module for interacting with the [IPinfo Lite API](https://ipinfo.io/developers/lite-api). IPinfo Lite provides free, unlimited access to accurate, daily-updated country-level geolocation and ASN data for both IPv4 and IPv6 addresses. This module is independently developed and not officially affiliated with IPinfo.

## Features
- Retrieve geolocation and ASN info for any IP address
- Batch query multiple IP addresses
- Enhanced Data Validation
- In-memory query cache for performance
- Structured output enabling seamless integration into scripting environments, automation frameworks, and reporting systems

## Getting Started

You will need an IPinfo Lite API access token, which you can get by signing up for a free account at [https://ipinfo.io/signup](https://ipinfo.io/signup).

## Installation
This module is tested on PowerShell 7 (Core) and Windows PowerShell 5.1 (Desktop). 

The latest version of the module is always available on the Microsoft PowerShell Gallery:
[https://www.powershellgallery.com/packages/IPInfoLite](https://www.powershellgallery.com/packages/IPInfoLite)


Install using the default command provided by the Microsoft PowerShell Gallery:
```powershell
Install-Module -Name IPInfoLite
```

If you encounter permission issues:
```powershell
Install-Module -Name IPInfoLite -Scope CurrentUser -Force
```

If you require help with PowerShell 7 on the Windows platform Microsoft provides installation instructions here [Microsoft Learn: Installing PowerShell on Windows](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows?view=powershell-7.5)


## What’s New in v2.0.0

- **IPinfo Batch API Endpoint**  
  `Get-IPInfoLiteBatch` Now uses the [IPinfo Batch API Endpoint](https://ipinfo.io/developers/advanced-usage), significantly improving performance when querying large sets of IP addresses.

- **Improved API Request Handling**  
  For [IPinfo Batch API](https://ipinfo.io/developers/advanced-usage) calls, the module now implements robust retry logic that automatically retries transient network and service errors (`502`, `503`, `504`) using exponential backoff with jitter to prevent retry storms, respects `HTTP 429` responses by honoring the server’s Retry-After header, and fails fast on unrecoverable `HTTP 500` errors. These improvements make API requests more resilient, reduce network congestion during transient failures.

- **Enhanced Data Validation**  
Previous versions only checked for bogon addresses. Version 2 introduces comprehensive pre-processing that automatically filters out invalid entries such as domain names, malformed IPs, and empty values before sending requests to the IPinfo Lite API. Deduplication has also been added to ensure a clean, optimized list of IP addresses is processed.

- **Improved Error Handling**  
Starting with version 2.0.0, IPInfoLite cmdlets follow PowerShell’s standard error model.
Failed requests no longer appear as objects with SUCCESS = $false; instead, errors are emitted as structured ErrorRecord objects through the PowerShell error stream.






## Usage

| Function | Description | Example | 
| ----------- | ----------- | ----------- |
| Get-IPInfoLiteEntry | Retrieves country-level geolocation and ASN details for a single IP via the IPinfo Lite API. | `Get-IPInfoLiteEntry -token "your_token_here" -ip "8.8.8.8"` |
| Get-IPInfoLiteBatch | Retrieves geolocation and ASN information for multiple IP addresses sequentially via the IPinfo Lite API. | `Get-IPInfoLiteBatch -Token "your_token_here" -ips @("8.8.8.8", "1.1.1.1") -ErrorVariable ipInfoErrors` |
| Get-IPInfoLiteCache |  Returns current statistics from the IPInfoLite query cache including entry count, cache hits, and evictions. | `Get-IPInfoLiteCache` |
| Clear-IPInfoLiteCache | Removes all previously cached query results. Use this if you suspect the  module is returning outdated or incorrect information. Supports `-WhatIf` and `-Confirm` parameters. | `Clear-IPInfoLiteCache` |


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
