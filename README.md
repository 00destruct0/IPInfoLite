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


## What’s New in v3.0.0

- **LLM-Optimized Export**  
  `Export-IPInfoLiteLLM` exports IP geolocation data in JSONL format optimized for analysis with Large Language Models (Claude, ChatGPT, Gemini). This supports LLM driven threat detection, pattern recognition, and security analysis workflows. See the [LLM Analysis Guide](Resources/Prompts/README.md) for examples and prompt templates.
  
- **Bug Fix: Removed Stray "True" Values from Output**  
 Fixed boolean return values from `HashSet.Add()` leaking into results by adding `[void]` cast to suppress output during cache processing in `Get-IPInfoLiteBatch`.






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
- "Based on infrastructure (hosting vs residential ISPs), what does this suggest about the threat actor?"

See the [LLM Analysis Guide](Resources/Prompts/LLMGuide.md) for detailed workflows and advanced examples.


### Why Use LLM Analysis?

Traditional analysis typically requires writing a new query or script for each question, filtering, pivoting, and formatting results as an investigation evolves. LLM analysis provides a natural-language interface for exploratory analysis and reporting, enabling faster iteration and easier generation of narrative summaries. For high-confidence results, validate key findings using your preferred analytical tools and repeatable queries.


**Advantages of LLM Analysis:**
- Upload once per session and perform iterative natural-language analysis  
- Generate narrative threat intelligence reports  
- No coding required for ad-hoc analysis  
- Contextual anomaly identification and correlation analysis  


### Use Cases

**Security Operations:**
- Identify coordinated attacks originating from multiple countries
- Identify potential botnet infrastructure patterns
- Highlight unusual or rare network infrastructure

**Threat Intelligence:**
- Generate executive summaries of attack origins
- Compare changes in attacker infrastructure within a dataset or across multiple datasets
- Assist in identifying emerging threat patterns

**Compliance & Reporting:**
- Support automated geolocation compliance analysis
- Generate incident response documentation
- Generate audit-ready documentation and summaries

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
