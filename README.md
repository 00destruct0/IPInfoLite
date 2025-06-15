# [<img src="https://ipinfo.io/static/ipinfo-small.svg" alt="IPinfo" width="24"/>](https://ipinfo.io/lite.) IPinfo Lite PowerShell Module

This is an open-source PowerShell module for interacting with the [IPinfo Lite API](https://ipinfo.io/developers/lite-api). IPinfo Lite provides free, unlimited access to accurate, daily-updated country-level geolocation and ASN data for both IPv4 and IPv6 addresses. This module is independently developed and not officially affiliated with IPinfo.

## Features
- Retrieve geolocation and ASN info for any IP address
- Batch query multiple IP addresses
- Built-in bogon IP detection
- In-memory query cache for performance
- Structured output and enhanced error handling enable seamless integration into scripting environments, automation frameworks, and reporting systems

## Getting Started

You will need an IPinfo Lite API access token, which you can get by signing up for a free account at [https://ipinfo.io/signup](https://ipinfo.io/signup).

## Installation
This module is tested on PowerShell 7.4.7 / 7.5.0 and Windows PowerShell 5.1.

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


## What’s New in v1.3.0

- **Country Flag Support**  
  Added support for country flags, including both emoji and Unicode representations, to enhance readability in reports and visual outputs.

- **Improved Resilience**  
  Introduced better handling for network and API-related issues in response to the recent Google Cloud incident, improving script stability.

- **Performance Enhancements**  
  General performance improvements to `Get-IPInfoLiteBatchParallel` for faster execution and better parallel processing.




## Usage

| Function | Description | Example | 
| ----------- | ----------- | ----------- |
| Get-IPInfoLiteEntry | Retrieves country-level geolocation and ASN details for a single IP via the IPinfo Lite API. | `Get-IPInfoLiteEntry -token "your_token_here" -ip "8.8.8.8"` |
| Get-IPInfoLiteBatch | Retrieves geolocation and ASN information for multiple IP addresses sequentially via the IPinfo Lite API. | `Get-IPInfoLiteBatch -Token "your_token_here" -ips @("8.8.8.8", "1.1.1.1")` |
| Get-IPInfoLiteBatchParallel | Performs high-efficiency batch IP lookups in parallel using the IPinfo Lite API (**Requires PowerShell 7**). | `Get-IPInfoLiteBatchParallel -Token "your_token_here" -ips @("8.8.8.8", "1.1.1.1")` |
| Get-IPInfoLiteCache |  Returns current statistics from the IPInfoLite query cache including entry count, cache hits, and evictions. | `Get-IPInfoLiteCache` |
| Clear-IPInfoLiteCache | Removes all previously cached query results. Use this if you suspect the  module is returning outdated or incorrect information. | `Clear-IPInfoLiteCache` |


## Output Structure
Queries return a `[PSCustomObject]` with the following fields:

- `Success` (true / false)
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
- `CacheHit` (true/false/null)
- `ErrorCode` (if failed)
- `ErrorMessage` (if failed)
- `ErrorTarget` (if failed)
- `ErrorTimestamp` (if failed)
- `ErrorDetails` (if failed)


## Caching

The IPInfoLite module includes a built-in caching system designed to minimize redundant API calls and improve performance. When an IP address is queried, its geolocation and ASN data are stored in an in-memory cache. Subsequent lookups for the same IP within the current session are served directly from the cache, avoiding additional calls to the IPinfo Lite API. This not only reduces network overhead but also ensures more responsive performance in batch or repeated queries. The cache can be inspected using the `Get-IPInfoLiteCache` function and cleared with `Clear-IPInfoLiteCache` as needed. Caching behavior is fully automatic and requires no configuration.


## License
This module is released under the [MIT License](https://opensource.org/licenses/MIT). You may use, modify, and distribute it freely.

## Author
Ryan Terp
📧 ryan.terp@gmail.com
