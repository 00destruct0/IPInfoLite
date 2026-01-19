### Module Configuration (Private)
$script:config = @{
    api = @{
        baseUrl      = "https://api.ipinfo.io/lite/"
        baseUrlMe    = "https://api.ipinfo.io/lite/me"
        baseUrlBatch = "https://api.ipinfo.io/batch/lite"
        headers      = @{ Accept = "application/json" }
    }
    cache = @{
        cacheLimit = 25000
    }
    processing = @{
        chunkSize = 1000
    }
    apiRetry = @{
        hardMaxBackoff = 45   # max seconds to wait between retries
        baseDelay      = 2    # initial delay factor
        maxRetries     = 5    # maximum retry attempts
    }
}

function New-ErrorRecord {
    <#
    .SYNOPSIS
    Creates a standardized PowerShell ErrorRecord object for consistent error handling.

    .DESCRIPTION
    New-ErrorRecord constructs and returns a [System.Management.Automation.ErrorRecord] with a defined ErrorId, 
    message, category, and target object. This ensures that errors are generated in a consistent format across 
    the module and align with PowerShell’s native error handling model. 

    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ErrorId,
        [Parameter(Mandatory)][string]$Message,
        [Parameter(Mandatory)]$TargetObject,
        [System.Management.Automation.ErrorCategory]$Category = 
            [System.Management.Automation.ErrorCategory]::NotSpecified
    )

    return [System.Management.Automation.ErrorRecord]::new(
        [System.Exception]::new($Message),
        $ErrorId,
        $Category,
        $TargetObject
    )
}



# The QueryCache class implements a lightweight, in-memory cache for IP query results using a static
# hashtable for storage and a queue to track insertion order for eviction when a configurable limit
# is reached. Keys are normalized to lowercase to ensure consistency, and the class tracks cache
# statistics including hits, misses, and evictions for monitoring. It provides Add, Get, ContainsKey,
# Clear, and GetStats methods, with Get optimized to use a single TryGetValue lookup and throwing a
# typed CacheResolverException on misses for strong error handling. This design provides efficient
# O(1) average-time operations and helps reduce redundant external API calls while keeping memory
# usage predictable in large-scale processing.

class CacheResolverException : Exception {
    CacheResolverException ([string]$Message, [Exception]$InnerException) : base ($Message, $InnerException) { }
}
class QueryCache {
    hidden static [Hashtable]$Records = @{}
    hidden static [System.Collections.Queue]$KeyOrder = [System.Collections.Queue]::new()  # Tracks insertion order for eviction

    hidden [UInt64] $Hit = 0
    hidden [UInt64] $Miss = 0
    hidden [int] $Limit = 0
    hidden [UInt64] $Evicted = 0

    QueryCache () {
        $this.Init()
    }

    QueryCache ([int]$Limit) {
        $this.Init()
        if ($Limit -gt 0) {
            $this.Limit = $Limit
        }
    }

    hidden [void] Init() {
        $this | Add-Member -MemberType ScriptProperty -Name 'Count' -Value { return [QueryCache]::Records.Count }
    }

    [void] Add ([string]$Key, $Value) {
        if ([string]::IsNullOrEmpty($Key)) {
            throw "Cache key cannot be null or empty."
        }

        $_key = $Key.ToLower()

        # Only run eviction + queue tracking for brand-new keys
        if (-not [QueryCache]::Records.ContainsKey($_key)) {
            if ($this.Limit -gt 0 -and [QueryCache]::Records.Count -ge $this.Limit) {
                $evictKey = [QueryCache]::KeyOrder.Dequeue()
                [QueryCache]::Records.Remove($evictKey)
                $this.Evicted++
            }
            [QueryCache]::KeyOrder.Enqueue($_key)
        }

        # Add or update the record
        [QueryCache]::Records[$_key] = $Value
    }

    [bool] ContainsKey ([string]$Key) {
        if ([string]::IsNullOrEmpty($Key)) {
            return $false
        }

        $_key = $Key.ToLower()
        return [QueryCache]::Records.ContainsKey($_key)
    }

    [object] Get ([string]$Key) {
        if ([string]::IsNullOrEmpty($Key)) {
            return $null
        }

        $_key = $Key.ToLower()

        if ([QueryCache]::Records.ContainsKey($_key)) {
            $this.Hit++
            return [QueryCache]::Records[$_key]
        }

        $this.Miss++
        return $null
    }

    [object] GetStats () {
        return [PSCustomObject]@{
            Count   = [QueryCache]::Records.Count
            Hit     = $this.Hit
            Miss    = $this.Miss
            Evicted = $this.Evicted
        }
    }

    [void] Clear() {
        [QueryCache]::Records.Clear()
        [QueryCache]::KeyOrder.Clear()
        $this.Hit = 0
        $this.Miss = 0
        $this.Evicted = 0
    }
}

function Get-IPInfoLiteCache {
    <#
    .SYNOPSIS
        Returns current statistics from the IPInfoLite query cache.

    .DESCRIPTION
        The Get-IPInfoLiteCache function retrieves internal cache performance metrics 
        used by the IPInfoLite module. It reports the number of cached entries, the 
        number of successful cache hits, misses (failed lookups), and evictions caused 
        by capacity limits. It also calculates the hit ratio percentage and shows the 
        configured maximum cache size (CacheLimit). This function is useful for 
        monitoring cache effectiveness and diagnosing performance or capacity issues.

    .PARAMETER None
        This function does not accept any parameters.

    .OUTPUTS
        PSCustomObject
        The returned object includes:
            - Count      (Int; current number of cache entries)
            - Hit        (UInt64; total successful cache lookups)
            - Miss       (UInt64; total failed cache lookups)
            - Evicted    (UInt64; total entries removed due to capacity limits)
            - HitRatio   (String; percentage of successful lookups, e.g. "75.5 %")
            - CacheLimit (Int; maximum allowed cache size)
            - Error      (String; present only if Success is $false, otherwise $null)


    .EXAMPLE
        Get-IPInfoLiteCache

        Returns a PSCustomObject with Success, Count, Hit, Miss, Evicted, HitRatio, 
        and CacheLimit representing the current state of the query cache.
    #>
    try {
        if (-not $script:QueryCache) {

            $err = New-ErrorRecord  `
                -ErrorId "ERR_CACHE_STATS_UNAVAILABLE"  `
                -Message "The QueryCache object is not initialized."  `
                -TargetObject "Memory Cache"  `
                -Category ResourceUnavailable
            throw $err
        }
        if (-not $script:config -or -not $script:config.cache) {
            $err = New-ErrorRecord  `
                -ErrorId "ERR_CACHE_STATS_UNAVAILABLE"  `
                -Message "Cache configuration is not available."  `
                -TargetObject "Memory Cache"  `
                -Category ResourceUnavailable
            throw $err
        }

        $totalLookups = $script:QueryCache.Hit + $script:QueryCache.Miss
        $hitRatio = if ($totalLookups -gt 0) {
            [math]::Round(($script:QueryCache.Hit / $totalLookups) * 100, 2)
        } else { 0 }

        return [PSCustomObject]@{
            Count      = [QueryCache]::Records.Count
            Hit        = $script:QueryCache.Hit
            Miss       = $script:QueryCache.Miss
            Evicted    = $script:QueryCache.Evicted
            HitRatio   = "$hitRatio%"
            CacheLimit = $script:config.cache.cacheLimit
        }
    }
    catch {
        $err = New-ErrorRecord  `
            -ErrorId "ERR_CACHE_STATS_FAILURE"  `
            -Message "Failed to collect cache performance metrics."  `
            -TargetObject "Cache Performance Metrics"  `
            -Category InvalidOperation
        Write-Error -ErrorRecord $err
    }
}


function Clear-IPInfoLiteCache {
    <#
    .SYNOPSIS
        Clears the shared query cache used by the module.

    .DESCRIPTION
        The Clear-IPInfoLiteCache function removes all previously cached query results 
        stored in the module’s shared QueryCache object. This is useful when cached 
        data may be outdated, incorrect, or if you want to ensure fresh queries are 
        made to the IPinfo Lite API.

    .PARAMETER None
        This function does not take any parameters.

    .OUTPUTS
        PSCustomObject

        On success:
            Returns a PSCustomObject containing the current cache statistics after the clear operation.
            The object may include properties such as:

            - CacheSize   : The maximum number of entries the cache can hold.
            - EntryCount  : The number of entries currently stored (should be 0 after a successful clear).
            - Hits        : The number of successful cache lookups performed.
            - Misses      : The number of failed lookups (items not found in cache).
            - Evictions   : The number of entries automatically removed due to capacity limits.
            - HitRatio    : The percentage of cache lookups that resulted in a hit.

        On failure:
            No object is returned. A [System.Management.Automation.ErrorRecord] is written
            to the error stream describing the failure condition.
    
    .EXAMPLE
        Clear-IPInfoLiteCache

        Clears all entries from the in-memory query cache. 
        On success, returns an object containing the current cache statistics, 
        which will show EntryCount = 0 after the operation.

    .EXAMPLE
        Clear-IPInfoLiteCache -WhatIf

        Displays a message describing the action that would be performed, 
        but does not actually clear the cache. Useful for previewing the 
        effect of the command without committing changes.

    .EXAMPLE
        Clear-IPInfoLiteCache -Confirm

        Prompts the user for confirmation before clearing the cache. 
        This adds an extra safeguard against accidental cache resets.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    process {
        try {
            if ($script:QueryCache) {
                if ($PSCmdlet.ShouldProcess("QueryCache", "Clear all cached entries")) {
                    $script:QueryCache.Clear()

                    # Return updated cache stats (instead of just $true)
                    return Get-IPInfoLiteCache
                }
            }
            else {
                $err = New-ErrorRecord  `
                    -ErrorId "ERR_CACHE_NOT_INITIALIZED"  `
                    -Message "The QueryCache object is not initialized and cannot be cleared."  `
                    -TargetObject "Memory Cache"  `
                    -Category ResourceUnavailable
                Write-Error -ErrorRecord $err
            }
        }
        catch {
            $err = New-ErrorRecord  `
                -ErrorId "ERR_CACHE_CLEAR_FAILURE"  `
                -Message "Failed to clear QueryCache. $($_.Exception.Message)"  `
                -TargetObject "Memory Cache"  `
                -Category InvalidOperation
            Write-Error -ErrorRecord $err
        }
    }
}

## Working 
function Export-IPInfoLiteLLM {
    <#
    .SYNOPSIS
        Exports IP geolocation data in JSONL format optimized for LLM analysis.
    
    .DESCRIPTION
        Export-IPInfoLiteLLM converts IPInfoLite query results to JSONL (JSON Lines) 
        format for analysis with Large Language Models such as Claude, ChatGPT, and 
        Gemini. Each line contains a complete, self-contained JSON object with 
        consistent schema and explicit null values.
        
        This format is optimized for:
        - LLM-powered security analysis and threat detection
        - Threat intelligence workflows
        - RAG (Retrieval-Augmented Generation) systems
        - Automated pattern detection and anomaly identification
        - Integration with AI-powered security platforms        
    
    .PARAMETER InputObject
        IP geolocation data from Get-IPInfoLiteBatch or Get-IPInfoLiteEntry.
        Accepts PSCustomObject array via pipeline or parameter.
    
    .PARAMETER Path
        The path where the JSONL output file will be saved. The directory must already
        exist, but the file itself must not. This prevents accidental overwrites and
        helps maintain data integrity when running automated workflows.
    
    .EXAMPLE
        Get-IPInfoLiteBatch -Token $token -IPs @("8.8.8.8", "1.1.1.1") | Export-IPInfoLiteLLM -Path "results.jsonl"
        
        Exports IP geolocation data to JSONL format for LLM analysis.
    
    .EXAMPLE
        # Pipeline usage
        $results = Get-IPInfoLiteBatch -Token $token -IPs $ips
        $results | Export-IPInfoLiteLLM -Path "analysis.jsonl"
        
        Retrieves IP data then exports for LLM analysis.
    
    .EXAMPLE
        # Automation with timestamps
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        Get-IPInfoLiteBatch -Token $token -IPs $ips | Export-IPInfoLiteLLM -Path "ips_$timestamp.jsonl"
        
        Creates uniquely named files for automated workflows.
    
    .EXAMPLE
        # Test without creating file
        Get-IPInfoLiteBatch -Token $token -IPs $ips | Export-IPInfoLiteLLM -Path "results.jsonl" -WhatIf
        
        Shows what would happen without actually creating the file.
    
    .EXAMPLE
        # Use with Claude, ChatGPT, or other LLMs
        Get-IPInfoLiteBatch -Token $token -IPs $suspiciousIPs | Export-IPInfoLiteLLM -Path "threat_analysis.jsonl"
        # Upload threat_analysis.jsonl to Claude Projects or ChatGPT for analysis
    
    .NOTES
        JSONL Format Details:
        - Each line is a complete, valid JSON object
        - Consistent schema across all records
        - Explicit null values for missing data (not omitted fields)
        - No trailing commas or array wrappers
        - Optimized for LLM consumption
        - UTF-8 encoding without BOM
        
        WhatIf and Confirm Switch Support:
        - Supports -WhatIf to preview operations without creating files
        - Supports -Confirm for interactive confirmation prompts
        
        LLM Usage:
        After exporting, upload the JSONL file to:
        - Claude (Anthropic) via Claude.ai or Claude Projects
        - ChatGPT (OpenAI) via web interface or API
        - Gemini (Google) via Google AI Studio
        - Custom RAG systems or AI security platforms
        
        For prompt templates and analysis examples, visit:
        https://github.com/00destruct0/IPInfoLite/tree/main/Resources/Prompts
    #>
    
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            Position = 0
        )]
        [PSCustomObject[]]$InputObject,
        
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    
    begin {
        # Validate that the directory exists
        $directory = Split-Path -Path $Path -Parent
        
        # FIXED: Check if directory path is not empty/whitespace before validating
        # This handles cases like "analysis.jsonl" where Split-Path returns ""
        if (-not [string]::IsNullOrWhiteSpace($directory)) {
            if (-not (Test-Path -Path $directory -PathType Container)) {
                $errorRecord = New-ErrorRecord `
                    -ErrorId 'DirectoryNotFound' `
                    -Message "Directory does not exist: $directory. Please create the directory before exporting." `
                    -TargetObject $directory `
                    -Category ([System.Management.Automation.ErrorCategory]::ObjectNotFound)
                
                $PSCmdlet.WriteError($errorRecord)
                return
            }
        }
        
        # Fail if file already exists to prevent data loss in automation
        if (Test-Path -Path $Path -PathType Leaf) {
            $errorRecord = New-ErrorRecord `
                -ErrorId 'FileAlreadyExists' `
                -Message "File already exists: $Path. To prevent accidental data loss, this function will not overwrite existing files. Please remove the existing file or use a different filename." `
                -TargetObject $Path `
                -Category ([System.Management.Automation.ErrorCategory]::ResourceExists)
            
            $PSCmdlet.WriteError($errorRecord)
            return
        }
        
        # Track records processed
        $recordCount = 0
        
        # FIXED: Create UTF8 encoder without BOM for cross-platform compatibility
        $script:utf8NoBom = New-Object System.Text.UTF8Encoding $false
    }
    
    process {
        foreach ($record in $InputObject) {
            # Create a normalized object with consistent schema and explicit nulls
            # This ensures every JSONL line has the same structure
            $normalizedRecord = [ordered]@{
                ip              = if ($null -ne $record.IP) { $record.IP } else { $null }
                asn             = if ($null -ne $record.ASN) { $record.ASN } else { $null }
                asn_name        = if ($null -ne $record.ASN_Name) { $record.ASN_Name } else { $null }
                asn_domain      = if ($null -ne $record.ASN_Domain) { $record.ASN_Domain } else { $null }
                country         = if ($null -ne $record.Country) { $record.Country } else { $null }
                country_code    = if ($null -ne $record.Country_Code) { $record.Country_Code } else { $null }
                continent       = if ($null -ne $record.Continent) { $record.Continent } else { $null }
                continent_code  = if ($null -ne $record.Continent_Code) { $record.Continent_Code } else { $null }
            }
            
            # Convert to compact JSON (single line, no whitespace)
            # -Compress ensures each record is a single line
            # -Depth 1 is sufficient for flat structure
            try {
                $jsonLine = $normalizedRecord | ConvertTo-Json -Compress -Depth 1
                
                # Write to file only if ShouldProcess confirms
                if ($PSCmdlet.ShouldProcess($Path, "Write JSONL record")) {
                    try {
                        #  Use .NET methods to write UTF8 without BOM
                        # This works consistently across PowerShell 5.1 and 7+
                        $content = $jsonLine + "`n"
                        [System.IO.File]::AppendAllText($Path, $content, $script:utf8NoBom)
                        $recordCount++
                    }
                    catch {
                        $errorRecord = New-ErrorRecord `
                            -ErrorId 'FileWriteFailed' `
                            -Message "Failed to write record to file '$Path': $($_.Exception.Message)" `
                            -TargetObject $Path `
                            -Category ([System.Management.Automation.ErrorCategory]::WriteError)
                        
                        $PSCmdlet.WriteError($errorRecord)
                        continue
                    }
                }
            }
            catch {
                $errorRecord = New-ErrorRecord `
                    -ErrorId 'JsonConversionFailed' `
                    -Message "Failed to convert record to JSON: $($_.Exception.Message)" `
                    -TargetObject $record `
                    -Category ([System.Management.Automation.ErrorCategory]::InvalidData)
                
                $PSCmdlet.WriteError($errorRecord)
                continue
            }
        }
    }
    
    end {
        if ($recordCount -gt 0) {
            Write-Verbose "Successfully exported $recordCount records to $Path"
        }
    }
}



## Working

function Get-IPInfoLiteEntry {
    <#
    .SYNOPSIS
        Retrieves IP geolocation and ASN information using the IPinfo Lite API.

    .DESCRIPTION
        The Get-IPInfoLiteEntry function queries the IPinfo Lite API to obtain 
        country-level geolocation and Autonomous System Number (ASN) details for 
        either a specified IP address or the caller’s own public IP if none is 
        provided. 

    .PARAMETER token
        Your IPinfo API token. This is required to authenticate requests against 
        the IPinfo Lite API.

    .PARAMETER ip
        Optional. The IP address to look up. If not provided, the function will 
        automatically query the caller’s public IP address.

    .OUTPUTS
        Returns an array of PSCustomObject results with country-level geolocation and ASN data, or an error message if the query fails.

    .EXAMPLE
        Get-IPInfoLiteEntry -token "your_token_here" -ip "8.8.8.8"

        Retrieves geolocation and ASN information for the IP address 8.8.8.8
        using the IPinfo Lite API.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$token,
        [string]$ip = ""
    )

    # Don't attempt to cache or bogon-check self queries
    if ($ip -eq "") {
        $url = "$($script:config.api.baseUrlMe)?token=$token"

        try {
            $response = Invoke-RestMethod -Uri $url -Method Get -Headers $script:config.api.headers

            return [PSCustomObject]@{
                IP                      = $response.ip
                ASN                     = $response.asn
                ASN_Name                = $response.as_name
                ASN_Domain              = $response.as_domain
                Country                 = $response.country
                Country_Code            = $response.country_code
                Country_Flag_Emoji      = $flags[$response.country_code].Emoji
                Country_Flag_Unicode    = $flags[$response.country_code].unicode
                Continent               = $response.continent
                Continent_Code          = $response.continent_code
                CacheHit                = $false
            }
        } catch {

            # Only sanitize if an error occurred
            $sanitizedUrl = "$($script:config.api.baseUrlMe)" + "?token=<REDACTED>"

            $err = New-ErrorRecord  `
                -ErrorId "ERR_API_FAILURE"  `
                -Message "External API request failed due to a possible timeout, network error, invalid token, or unexpected response."  `
                -TargetObject $sanitizedUrl `
                -Category NotSpecified
            throw $err
        }
    }

    # Validate input IP
    if (Test-BogonIP -ip $ip) {
        $err = New-ErrorRecord  `
            -ErrorId "INPUT_ERR_BOGON" `
            -Message "The IP address $ip is a bogon (reserved or non-routable). Only public IP addresses can be queried for geolocation." `
            -TargetObject $ip `
            -Category InvalidData
        throw $err
    }

    # Use cache for normal IP lookups
    $cache = $script:QueryCache

        if ($cache.ContainsKey($ip)) {
            $cached = $cache.Get($ip) | Select-Object * -ExcludeProperty CacheHit
            $cached | Add-Member -NotePropertyName 'CacheHit' -NotePropertyValue $true
            return $cached
        }
    
    try {
        $url = "$($script:config.api.baseUrl)$ip" + "?token=$token"
        $response = Invoke-RestMethod -Uri $url -Method Get -Headers $script:config.api.headers

        $result = [PSCustomObject]@{
            IP                      = $response.ip
            ASN                     = $response.asn
            ASN_Name                = $response.as_name
            ASN_Domain              = $response.as_domain
            Country                 = $response.country
            Country_Code            = $response.country_code
            Country_Flag_Emoji      = $flags[$response.country_code].Emoji
            Country_Flag_Unicode    = $flags[$response.country_code].unicode
            Continent               = $response.continent
            Continent_Code          = $response.continent_code
            CacheHit                = $false
        }

        $cache.Add($ip, $result)
        return $result

    } catch {
        
        # Only sanitize if an error occurred
        $sanitizedUrl = "$($script:config.api.baseUrl)$ip" + "?token=<REDACTED>"

        $err = New-ErrorRecord  `
            -ErrorId "ERR_API_FAILURE"  `
            -Message "External API request failed due to a possible timeout, network error, invalid token, or unexpected response."  `
            -TargetObject $sanitizedUrl `
            -Category NotSpecified
        Write-Error -ErrorRecord $err
    }
}


function Get-IPInfoLiteBatch {
    <#
    .SYNOPSIS
        Performs batched IP information lookups using the IPinfo Lite Batch API.

    .DESCRIPTION
        The Get-IPInfoLiteBatch function queries the IPinfo Lite Batch API to retrieve 
        country-level geolocation and ASN details for multiple IP addresses in a single 
        request. 
    
    .PARAMETER token
        Your IPinfo API token. This is required for authentication with the Batch API.

    .PARAMETER ips
        One or more IP addresses to look up. Accepts an array of IPv4 or IPv6 addresses.

    .OUTPUTS
        Returns an array of PSCustomObject results with country-level geolocation and ASN data, or an error message if the query fails.

    .EXAMPLE
        Get-IPInfoLiteBatch -token "your_token_here" -ips @("8.8.8.8", "1.1.1.1")

        Performs a batch lookup for multiple IP addresses using the IPinfo Lite Batch API.
        Returns a PSCustomObject array with geolocation and ASN details for each IP.

    .EXAMPLE
        $ips = Get-Content ".\ips.txt"
        Get-IPInfoLiteBatch -token "your_token_here" -ips $ips

        Reads a list of IP addresses from a text file and performs a batch lookup.
        Returns geolocation and ASN details for all valid, routable IPs.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$token,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$ips
    )

    $results = New-Object System.Collections.Generic.List[PSObject]
    $cache = $script:QueryCache  # Use shared cache instance
    
    
    # Validate token once at the top
    $testResult = Test-IPInfoLiteToken -token $token
    if (-not $testResult.Success) {
        $err = New-ErrorRecord  `
            -ErrorId "ERR_AUTH_TOKEN_INVALID" `
            -Message "The API token provided could not be verified. Please ensure the token is correct, active, and has the necessary permissions." `
            -TargetObject "Token Validation" `
            -Category SecurityError
        
        throw $err
    }

    # This preprocessing pipeline ensures a clean and controlled set of IPs for downstream use by
    # systematically validating each entry: removing null or whitespace values, trimming, verifying
    # format with TryParse, excluding bogon addresses, and returning cached results when available.
    # Any IP excluded at any stage is logged into $results to maintain traceability, while only valid,
    # uncached, routable IPs are collected into $validIps for deduplication prior to querying.

    # Initialize a strongly-typed list for valid IPs
    $validIps = [System.Collections.Generic.List[string]]::new()

    # Track all IPs that have already been added to $results from cache to prevent duplicates
    $ProcessedCacheIPs = [System.Collections.Generic.HashSet[string]]::new()
    
    foreach ($ip in $ips) {
        if ([string]::IsNullOrWhiteSpace($ip)) {
            $err = New-ErrorRecord  `
                -ErrorId "INPUT_ERR_NULL_OR_EMPTY" `
                -Message "The provided entry is null, empty, or whitespace and is excluded from querying." `
                -TargetObject $ip `
                -Category InvalidData
            Write-Error -ErrorRecord $err
            continue
        }

        $trimmed = $ip.Trim()
        $ipObj = $null

        if (-not [System.Net.IPAddress]::TryParse($trimmed, [ref]$ipObj)) {
            $err = New-ErrorRecord  `
                -ErrorId "INPUT_ERR_INVALID_IP" `
                -Message "The provided IP address $($trimmed) is not in a valid IPv4 or IPv6 format and has been excluded from querying." `
                -TargetObject $trimmed `
                -Category InvalidData
            Write-Error -ErrorRecord $err
            continue
        }

        #Skip bogon IPs
        if (Test-BogonIP -ip $trimmed) {
            $err = New-ErrorRecord  `
                -ErrorId "INPUT_ERR_BOGON" `
                -Message "The provided IP address $($trimmed) is classified as a bogon (non-routable or reserved) and is excluded from querying." `
                -TargetObject $trimmed `
                -Category InvalidData
            Write-Error -ErrorRecord $err
            continue
        }

        # Cached result handling with duplicate suppression.
        # $ProcessedCacheIPs ensures each cached IP is added to $results only once per execution
        if ($cache.ContainsKey($trimmed)) {
        
            if (-not $ProcessedCacheIPs.Contains($trimmed)) {
                $cached = $cache.Get($trimmed) | Select-Object * -ExcludeProperty CacheHit
                $cached | Add-Member -NotePropertyName 'CacheHit' -NotePropertyValue $true
                [void]$results.Add($cached) 

                # Mark this IP as processed from cache
                # Cast Void to avoid leakage into pipeline
                [void]$ProcessedCacheIPs.Add($trimmed)
            }

            continue
        }

        # If we got here, it's a valid, routable, uncached IP
        $validIps.Add($trimmed)
}

    # Deduplicate in place
    $set = [System.Collections.Generic.HashSet[string]]::new($validIps)
    $validIps = [System.Collections.Generic.List[string]]::new()
    $validIps.AddRange($set)

    # This section breaks the validated IP list into configurable chunks to comply with API limits,
    # builds a JSON payload for each chunk.

    # Combine Base URL and provided token.
    $url = "$($script:config.api.baseUrlBatch)" + "?token=$token"

    for ($i = 0; $i -lt $validIps.Count; $i += $script:config.processing.chunkSize) {
        $size  = [Math]::Min($script:config.processing.chunkSize, $validIps.Count - $i)
        $chunk = $validIps.GetRange($i, $size)

        # Prepend 'lite/' to each IP for API call
        $patterns = $chunk | ForEach-Object { "lite/$_" }

        # Convert to JSON for request body
        $body = $patterns | ConvertTo-Json

        # Use the private helper Invoke-RestRequest to perform the actual API call.
        # If the helper exhausts its retries and returns $null, skip this batch and continue.
        $response = Invoke-RestRequest  -Uri $url `
                                        -Method Post `
                                        -Body $body `
                                        -Headers $script:config.api.headers

      
        if (-not $response.Success) {
      
            switch ($response.StatusCode) {
                429 {
                    $batchErrorId           = "HTTP_ERR_TOO_MANY_REQUESTS"
                    $batchErrorCategory     = "ResourceBusy"
                    $batchMessage           = "The API request failed with status code 429 (Too Many Requests) after repeated backoff and retry attempts."
                }

                {$_ -ge 500 -and $_ -lt 600} {
                    $batchErrorId           = "HTTP_ERR_SERVER_ERROR"
                    $batchErrorCategory     = "ResourceUnavailable"
                    
                     if ($response.StatusCode -in 502,503,504) {
                        $batchMessage   = "The API request failed with status code $($response.StatusCode) (Server Error) after repeated backoff and retry attempts."
                    } else { 
                        $batchMessage   = "The API request failed with status code $($response.StatusCode) (Server Error)."
                    }
                }

                Default {
                    $batchErrorId           = "HTTP_ERR_UNHANDLED_STATUS_CODE"
                    $batchErrorCategory     = "NotSpecified"
                    $batchMessage           = "The API request failed with unhandled status code $($response.StatusCode)."
                }
            }

            
            foreach ($ip in $chunk) {
                $err = New-ErrorRecord  `
                    -ErrorId $batchErrorId `
                    -Message $batchMessage  `
                    -TargetObject $ip `
                    -Category $batchErrorCategory 
                Write-Error -ErrorRecord $err
            }

            continue
        }

        # Process each property in the response.Content
        foreach ($prop in $response.Content.PSObject.Properties) {
        $json = $prop.Value

            # Build normalized result object
            $result = [PSCustomObject]@{
                IP                   = $json.ip
                ASN                  = $json.asn
                ASN_Name             = $json.as_name
                ASN_Domain           = $json.as_domain
                Country              = $json.country
                Country_Code         = $json.country_code
                Country_Flag_Emoji   = $flags[$json.country_code].Emoji
                Country_Flag_Unicode = $flags[$json.country_code].Unicode
                Continent            = $json.continent
                Continent_Code       = $json.continent_code
                CacheHit             = $false
            }
            $cache.Add($json.ip, $result)
            $results.Add($result)
        }
    }

    return ,$results.ToArray()
}


function Invoke-RestRequest {
    <#
    .SYNOPSIS
        Helper function to invoke a REST API request with retry, backoff, jitter, and a hard cap.

    .DESCRIPTION
        This function wraps Invoke-WebRequest to provide robust error handling.
        It retries transient failures (502/503/504), respects HTTP 429 Retry-After headers,
        and fails fast on HTTP 500. Network errors and transient errors use exponential 
        backoff with jitter to reduce thundering herd effects. Backoff is capped at a 
        maximum defined in the module configuration ($script:config.apiRetry).

    .PARAMETER Uri
        The target URI for the REST request. This parameter is mandatory.

    .PARAMETER Method
        The HTTP method to use for the request. Supported values are GET, POST, PUT, DELETE, PATCH.
        Defaults to GET.

    .PARAMETER Body
        The request body content. For POST/PUT/PATCH requests, provide an object or string.
        Defaults to $null.

    .PARAMETER Headers
        Additional HTTP headers to include with the request. Provide as a hashtable.
        Defaults to an empty hashtable.

    .PARAMETER ContentType
        The Content-Type header for the request. Defaults to "application/json".

    .PARAMETER MaxRetries
        The maximum number of retry attempts for failed requests. 
        Defaults to the value defined in $script:config.apiRetry.maxRetries.

    .PARAMETER BaseDelay
        The initial backoff delay (in seconds). This value doubles with each retry attempt,
        and is capped at $script:config.apiRetry.hardMaxBackoff seconds. 
        Defaults to the value defined in $script:config.apiRetry.baseDelay.

    .EXAMPLE
        Invoke-RestRequest -Uri "https://api.ipinfo.io/lite/me"

        Sends a GET request to the /me endpoint and returns parsed JSON representing
        details about the caller’s IP address.

    .EXAMPLE
        $body = @{ "1.1.1.1" = @{}; "8.8.8.8" = @{} } | ConvertTo-Json
        Invoke-RestRequest -Uri "https://api.ipinfo.io/batch/lite" -Method POST -Body $body

        Sends a POST request to the batch endpoint with multiple IP addresses.
        Returns parsed JSON containing details for each requested IP.

    .OUTPUTS
        Parsed JSON object on success, or $null on failure.

    .NOTES
        This is a private helper function intended for internal use only.
        Public cmdlets such as Get-IPInfoLiteBatch call this function to handle
        REST requests with retry/backoff logic. It is not exported from the module.
    #>
    [CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Uri,
    
    [ValidateSet("GET","POST","PUT","DELETE","PATCH")]
    [string]$Method = "GET",

    [AllowNull()]
    [object]$Body = $null,
    
    [hashtable]$Headers = @{}, 
    [string]$ContentType = "application/json",

    # Defaults pulled from module config if not overridden
    [int]$MaxRetries = $script:config.apiRetry.maxRetries,
    [int]$BaseDelay  = $script:config.apiRetry.baseDelay
)

# Hard safeguard for backoff (from module config only)
$HardMaxBackoff = $script:config.apiRetry.hardMaxBackoff

$attempt = 0
$statusCode = 0
$lastErrorMessage = $null

$attempt = 0
$statusCode = $null
$lastErrorMessage = $null

while ($attempt -lt $MaxRetries) {
    $attempt++
    try {
        $response = Invoke-WebRequest -Uri $Uri `
                                      -Method $Method `
                                      -Body $Body `
                                      -Headers $Headers `
                                      -ContentType $ContentType `
                                      -ErrorAction Stop
                                      
        if ($response.StatusCode -eq 200) {
            return [PSCustomObject]@{
                Success    = $true
                StatusCode = 200
                Content    = ($response.Content | ConvertFrom-Json)
            }
        }

        return [PSCustomObject]@{
            Success    = $false
            StatusCode = $response.StatusCode
            Content    = $null
        }
    }
    catch {
        # --- Unified cross-version error handling (PS 5.1 + 7+) ---
        $ex    = $_.Exception
        $inner = $ex.InnerException
        $resp  = $null
        $statusCode = $null

        # --- PowerShell 7+ ---
        if (
            ($ex.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
            ($inner -and $inner.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException')
        ) {
            $resp = if ($ex.Response) { $ex.Response } elseif ($inner -and $inner.Response) { $inner.Response } else { $null }
            if ($resp) { $statusCode = [int]$resp.StatusCode.value__ }
        }

        # --- PowerShell 5.1 (WebCmdletWebResponseException) ---
        elseif (
            ($ex.GetType().FullName -eq 'Microsoft.PowerShell.Commands.WebCmdletWebResponseException') -or
            ($inner -and $inner.GetType().FullName -eq 'Microsoft.PowerShell.Commands.WebCmdletWebResponseException')
        ) {
            $resp = if ($ex.Response) { $ex.Response } elseif ($inner -and $inner.Response) { $inner.Response } else { $null }
            if ($resp) { $statusCode = [int]$resp.StatusCode }
        }

        # --- PowerShell 5.1 (plain .NET WebException) ---
        elseif ($ex -is [System.Net.WebException]) {
            $resp = $ex.Response
            if ($resp -and $resp -is [System.Net.HttpWebResponse]) {
                $statusCode = [int]$resp.StatusCode
            }
        }

        # --- Network failure (no HTTP response) ---
        if (-not $resp) {
            $lastErrorMessage = $ex.Message
            $statusCode     = -1   # <-- flag for network-level failure (not HTTP)
            $maxDelay       = [math]::Pow(2, $attempt - 1) * $BaseDelay
            $maxDelay       = [math]::Min($maxDelay, $HardMaxBackoff)
            $delay          = Get-Random -Minimum 0 -Maximum ($maxDelay + 1)
            $delayDisplay   = [math]::Round($delay, 2)
            Write-Warning "Network connectivity issue while contacting the API on attempt ${attempt}: $($ex.Message). Retrying in $delayDisplay seconds..."
            Start-Sleep -Seconds $delay
            continue
        }

        # fall through to status-code handling
    }

    # --- Unified error handling (PS5 + PS7) ---
    switch ($statusCode) {
        429 {
            $retryAfter = $resp.Headers["Retry-After"]
            if ($retryAfter) {
                if ($retryAfter -as [int]) {
                    $delay          = [int]$retryAfter
                    $delayDisplay   = [math]::Round($delay, 2)
                    Write-Warning "API rate limit reached (HTTP 429). Waiting $delayDisplay seconds before retry ${attempt}."
                } else {
                    $retryDate      = [DateTime]::Parse($retryAfter)
                    $delay          = [int]([Math]::Max(0, ($retryDate - (Get-Date)).TotalSeconds))
                    $delayDisplay   = [math]::Round($delay, 2)
                    Write-Warning "API rate limit reached (HTTP 429). Waiting until $retryDate ($delayDisplay seconds)."
                }
            } else {
                $maxDelay       = [math]::Pow(2, $attempt - 1) * $BaseDelay
                $maxDelay       = [math]::Min($maxDelay, $HardMaxBackoff)
                $delay          = Get-Random -Minimum 0 -Maximum ($maxDelay + 1)
                $delayDisplay   = [math]::Round($delay, 2)
                Write-Warning "API rate limit reached (HTTP 429) with no Retry-After. Backing off $delayDisplay seconds."
            }
            Start-Sleep -Seconds $delay
            continue
        }
        500 {
            return [PSCustomObject]@{
                Success    = $false
                StatusCode = 500
                Content    = $null
            }
        }
        {$_ -in 502,503,504} {
            $maxDelay       = [math]::Pow(2, $attempt - 1) * $BaseDelay
            $maxDelay       = [math]::Min($maxDelay, $HardMaxBackoff)
            $delay          = Get-Random -Minimum 0 -Maximum ($maxDelay + 1)
            $delayDisplay   = [math]::Round($delay, 2)
            Write-Warning "Transient API error (HTTP $statusCode) detected on attempt ${attempt}. Retrying in $delayDisplay seconds."
            Start-Sleep -Seconds $delay
            continue
        }
        default {
            return [PSCustomObject]@{
                Success    = $false
                StatusCode = [int]$statusCode
                Content    = $null
            }
        }
    }
}

# --- Final structured return if retries exhausted ---
return [PSCustomObject]@{
    Success    = $false
    StatusCode = if ($statusCode -and $statusCode -ne 0) { [int]$statusCode } else { -1 }
    Error      = if ($lastErrorMessage) { $lastErrorMessage } else { "Request failed after $MaxRetries attempts." }
    Content    = $null
}

}

function Test-IPInfoLiteToken {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory)]
        [string]$token
    )

    $url = "$($script:config.api.baseUrlMe)?token=$token"

    try {
        $null = Invoke-RestMethod -Uri $url -Headers $script:config.api.headers -Method Get -TimeoutSec 5
        return [PSCustomObject]@{
            Success = $true
            Message = "Token is valid."
        }
    } catch {
        return [PSCustomObject]@{
            Success = $false
            Message = "Token validation failed: $($_.Exception.Message)"
            ErrorCode = $_.Exception.Response.StatusCode.Value__
        }
    }
}


function Initialize-BogonRanges {
    $filePath = Join-Path $PSScriptRoot 'Resources\bogonRanges.json'

    if (-not (Test-Path $filePath)) {
        throw "Bogon range data file not found: $filePath"
    }

    $jsonData = Get-Content $filePath -Raw | ConvertFrom-Json

    return $jsonData | ForEach-Object {
        [PSCustomObject]@{
            Network      = [System.Net.IPAddress]::Parse($_.Network)
            PrefixLength = $_.PrefixLength
        }
    }
}

function Test-BogonIP {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$IPAddress
    )

    $parsedIP = $null
    if (-not [System.Net.IPAddress]::TryParse($IPAddress, [ref]$parsedIP)) {
        Write-Warning "Invalid IP address format: $IPAddress"
        return $false
    }

    foreach ($range in $Script:BogonRanges) {
        if (Test-IPInCIDR -IPAddress $parsedIP -Network $range.Network -PrefixLength $range.PrefixLength) {
            return $true
        }
    }

    return $false
}


function Test-IPInCIDR {
    param (
        [System.Net.IPAddress]$IPAddress,
        [System.Net.IPAddress]$Network,
        [int]$PrefixLength
    )

    $ipBytes  = $IPAddress.GetAddressBytes()
    $netBytes = $Network.GetAddressBytes()

    if ($ipBytes.Length -ne $netBytes.Length) {
        return $false
    }

    $fullBytes = [math]::Floor($PrefixLength / 8)
    $remainingBits = $PrefixLength % 8

    for ($i = 0; $i -lt $fullBytes; $i++) {
        if ($ipBytes[$i] -ne $netBytes[$i]) {
            return $false
        }
    }

    if ($remainingBits -gt 0) {
        $mask = 0xFF -shl (8 - $remainingBits)
        if (($ipBytes[$fullBytes] -band $mask) -ne ($netBytes[$fullBytes] -band $mask)) {
            return $false
        }
    }

    return $true
}


function Initialize-CountryFlagTable {
    [CmdletBinding()]
    param ()

    $filePath = Join-Path $PSScriptRoot 'Resources\countries_flags.json'

    if (-not (Test-Path -Path $filePath)) {
        throw "The file '$filePath' does not exist. Ensure the JSON file is present in the 'Resources' folder relative to the script location."
    }

    $jsonContent = Get-Content -Raw -Path $filePath | ConvertFrom-Json

    $countryFlagTable = @{}

    foreach ($property in $jsonContent.PSObject.Properties) {
        $countryCode = $property.Name
        $entry = $property.Value

        $countryFlagTable[$countryCode] = [PSCustomObject]@{
            Emoji   = $entry.emoji
            Unicode = $entry.unicode
        }
    }

    return $countryFlagTable
}

# Initialize query cache instance
$script:QueryCache = [QueryCache]::new($script:config.cache.cacheLimit)

# Initialize static bogon range cache
$Script:BogonRanges = Initialize-BogonRanges

# Initialize Country Flag Table
$Script:flags = Initialize-CountryFlagTable


Export-ModuleMember -Function Get-IPInfoLiteEntry, Get-IPInfoLiteBatch, Get-IPInfoLiteCache, Clear-IPInfoLiteCache, Export-IPInfoLiteLLM