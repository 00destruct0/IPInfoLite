### Module Configuration (Private)
$script:config = @{
    api = @{
        baseUrl    = "https://api.ipinfo.io/lite/"
        baseUrlMe  = "https://api.ipinfo.io/lite/me"
        headers    = @{ Accept = "application/json" }
    }
    cache = @{
        queryLimit = 5000
    }
    processing = @{
        chunkSize = 200
    }
}


function New-ErrorResponse {
    param (
        [string]$ErrorCode,
        [string]$ErrorMessage,
        [string]$ErrorTarget = $null,
        $ErrorDetails = $null,
        $IP = $null
    )

    return [PSCustomObject]@{
        Success                 = $false
        IP                      = $IP
        ASN                     = $null
        ASN_Name                = $null
        ASN_Domain              = $null
        Country                 = $null
        Country_Code            = $null
        Country_Flag_Emoji      = $null
        Country_Flag_Unicode    = $null
        Continent               = $null
        Continent_Code          = $null
        CacheHit                = $null
        ErrorCode               = $ErrorCode
        ErrorMessage            = $ErrorMessage
        ErrorTarget             = $ErrorTarget
        ErrorTimestamp          = (Get-Date).ToUniversalTime().ToString("o")
        ErrorDetails            = $ErrorDetails
    }
}



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

    QueryCache ($Limit) {
        $this.Init()
        if ($Limit -gt 0) {
            $this.Limit = $Limit
        }
    }

    hidden [void] Init() {
        $this | Add-Member -MemberType ScriptProperty -Name 'Count' -Value { return [QueryCache]::Records.Count }
    }

    [void] Add ([string]$Key, $Value) {
        if ([String]::IsNullOrEmpty($Key)) {
            throw '$Key is null. Key must be a non-empty string.'
        }

        $_key = $Key.ToLower()

        if ([QueryCache]::Records.ContainsKey($_key)) {
            [QueryCache]::Records[$_key] = $Value
            return
        }

        if ($this.Limit -gt 0 -and [QueryCache]::Records.Count -ge $this.Limit) {
            $evictKey = [QueryCache]::KeyOrder.Dequeue()
            [QueryCache]::Records.Remove($evictKey)
            $this.Evicted++  # Tracks evictions
        }


        [QueryCache]::Records[$_key] = $Value
        [QueryCache]::KeyOrder.Enqueue($_key)
    }

    [bool] ContainsKey ([String]$Key) {
        if ([String]::IsNullOrEmpty($Key)) {
            throw '$Key is null. Key must be a non-empty string.'
        }

        $_key = $Key.ToLower()
        return [QueryCache]::Records.ContainsKey($_key)
    }

    [object] Get ([string]$Key) {
        if ([String]::IsNullOrEmpty($Key)) {
            throw '$Key is null. Key must be a non-empty string.'
        }

        $_key = $Key.ToLower()

        if ([QueryCache]::Records.ContainsKey($_key)) {
            $this.Hit++
            return [QueryCache]::Records[$_key]
        }

        $this.Miss++
        throw "Cache miss for key: $Key"
    }

    [object] GetStats () {
        return [PSCustomObject]@{
            Count = [QueryCache]::Records.Count
            Hit   = $this.Hit
            Miss  = $this.Miss
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
    Returns current statistics from the IPInfoLite query cache including entry count, cache hits, and evictions.
    .DESCRIPTION
    Get-IPInfoLiteCache retrieves internal cache performance metrics used by the IPInfoLite module.
    This includes the current number of entries in the cache, the number of successful cache hits,
    and the number of failed lookups (misses). It is useful for automation, monitoring, and diagnostics.
    .EXAMPLE
    Get-IPInfoLiteCache
    .OUTPUTS
    Returns a PSCustomObject with Count, Hit, and Miss properties.
    #>
    return [PSCustomObject]@{
        Success = $true
        Count   = [QueryCache]::Records.Count
        Hit     = $script:QueryCache.Hit
        Evicted = $script:QueryCache.Evicted
    }
}


function Clear-IPInfoLiteCache {
    <#
      .SYNOPSIS
        Clears the shared query cache used by the module.
      .DESCRIPTION
        Removes all previously cached query results. Use this if you suspect the 
        module is returning outdated or incorrect information due to cached data.
      .EXAMPLE
        Clear-IPInfoLiteCache
    #>
    try {
        if ($script:QueryCache) {
            $script:QueryCache.Clear()
            return [PSCustomObject]@{
                Success = $true
            }
        }
        else {
            return [PSCustomObject]@{
                Success         = $false
                ErrorCode       = "ERR_QUERYCACHE_UNINITIALIZED"
                ErrorMessage    = "QueryCache has not been initialized."
                ErrorTarget     = "QueryCache"
                ErrorTimestamp  = (Get-Date).ToUniversalTime().ToString("o")
                ErrorDetails    = $null
            }
        }
    }
    catch {
        return [PSCustomObject]@{
            Success         = $false
            ErrorCode       = "ERR_QUERYCACHE_CLEAR_FAILED"
            ErrorMessage    = "Failed to clear QueryCache."
            ErrorTarget     = "QueryCache"
            ErrorTimestamp  = (Get-Date).ToUniversalTime().ToString("o")
            ErrorDetails    = $_
        }
    }
}


function Get-IPInfoLiteEntry {
        <#
    .SYNOPSIS
        Gets a single IP geolocation and ASN info using IPinfo Lite API.
    .PARAMETER token
        Your IPinfo API token.
    .PARAMETER ip
        Optional. IP address to look up. If not supplied, looks up caller's IP.
    .OUTPUTS
        Returns an array of PSCustomObject results with country-level geolocation and ASN data, or an error message if the query fails.
    .EXAMPLE
        Get-IPInfoLiteEntry -token "your_token_here" -ip "8.8.8.8"

        Returns geolocation and ASN information for the IP address 8.8.8.8
        using the IPInfo Lite API.

    .EXAMPLE
        Get-IPInfoLiteEntry -token "your_token_here"

        Returns geolocation and ASN information for the caller's public IP
        address using the IPInfo Lite API.
     #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [string]$token,
        [string]$ip = ""
    )

    # Don't attempt to cache or bogon-check self queries
    if ($ip -eq "") {
        $url = "$($script:config.api.baseUrlMe)?token=$token"

        try {
            $response = Invoke-RestMethod -Uri $url -Method Get -Headers $script:config.api.headers

            return [PSCustomObject]@{
                Success                 = $true
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
            
            return New-ErrorResponse `
                -ErrorCode "ERR_API_FAILURE" `
                -ErrorMessage "External API request failed due to possible timeout, network error or unexpected response." `
                -ErrorTarget $sanitizedUrl `
                -ErrorDetails $_.ErrorDetails.Message `
                -IP $null
        }
    }

    # Validate input IP
    if (Test-BogonIP -ip $ip) {
        return New-ErrorResponse `
            -ErrorCode "ERR_BOGON_INPUT" `
            -ErrorMessage "The provided IP address is classified as a bogon (non-routable or reserved) and is excluded from querying." `
            -ErrorTarget $ip `
            -IP $ip
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
            Success                 = $true
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

        return New-ErrorResponse `
            -ErrorCode "ERR_API_FAILURE" `
            -ErrorMessage "External API request failed due to possible timeout, network error or unexpected response." `
            -ErrorTarget $sanitizedUrl `
            -ErrorDetails $null `
            -IP $ip
    }
}

function Get-IPInfoLiteBatch {
    <#
    .SYNOPSIS
        Performs sequential IP info lookups using the IPinfo Lite API.
    .PARAMETER token
        Your IPinfo API token.
    .PARAMETER ips
        Array of IP addresses to look up.
    .OUTPUTS
        Returns an array of PSCustomObject results with country-level geolocation and ASN data, or an error message if the query fails.
    .EXAMPLE
        Get-IPInfoLiteBatch -token "your_token_here" -ips @("8.8.8.8", "1.1.1.1")
 
        Performs a batch lookup for multiple IP addresses using the IPInfo Lite API.
        Returns a list of geolocation and ASN information for each IP.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param (
        [Parameter(Mandatory = $true)]
        [string]$token,

        [Parameter(Mandatory = $true)]
        [string[]]$ips
    )

    # Validate token once at the top
    $testResult = Test-IPInfoLiteToken -token $token
    if (-not $testResult.Success) {
        return New-ErrorResponse `
            -ErrorCode "ERR_TOKEN_VERIFICATION" `
            -ErrorMessage "The API token provided could not be verified. Please ensure the token is correct, active, and has the necessary permissions" `
            -ErrorTarget "Token Validation" `
            -ErrorDetails $testResult
    }

    $results = New-Object System.Collections.Generic.List[PSObject]
    $cache = $script:QueryCache  # Use shared cache instance

    # Configure HttpClient
    $httpClient = $script:httpClient

    # Apply default headers from config
        foreach ($key in $script:config.api.headers.Keys) {
            if (-not $httpClient.DefaultRequestHeaders.Contains($key)) {
            [void]$httpClient.DefaultRequestHeaders.Add($key, $script:config.api.headers[$key])
        }
    }

    foreach ($ip in $ips) {
        
        # Skip bogon IPs
        if (Test-BogonIP -ip $ip) {
            $results.Add((New-ErrorResponse `
                -ErrorCode "ERR_BOGON_INPUT" `
                -ErrorMessage "The provided IP address is classified as a bogon (non-routable or reserved) and is excluded from querying." `
                -ErrorTarget $ip `
                -IP $ip))
            continue
        }

        # Return cached value if available
        if ($cache.ContainsKey($ip)) {
            $cached = $cache.Get($ip) | Select-Object * -ExcludeProperty CacheHit
            $cached | Add-Member -NotePropertyName 'CacheHit' -NotePropertyValue $true
            $results.Add($cached)
            continue
        }
         
        try {
            # Remote Query
            $url = "$($script:config.api.baseUrl)$ip" + "?token=$token"
            $response = $httpClient.GetAsync($url).Result
            $jsonContent = $response.Content.ReadAsStringAsync().Result
            $json = $jsonContent | ConvertFrom-Json

                $result = [PSCustomObject]@{
                    Success                 = $true
                    IP                      = $json.ip
                    ASN                     = $json.asn
                    ASN_Name                = $json.as_name
                    ASN_Domain              = $json.as_domain
                    Country                 = $json.country
                    Country_Code            = $json.country_code
                    Country_Flag_Emoji      = $flags[$json.country_code].Emoji
                    Country_Flag_Unicode    = $flags[$json.country_code].unicode
                    Continent               = $json.continent
                    Continent_Code          = $json.continent_code
                    CacheHit                = $false
                    }

            $cache.Add($ip, $result)
            $results.Add($result)
                        
        } catch {

            # Only sanitize if an error occurred
            $sanitizedUrl = "$($script:config.api.baseUrl)$ip" + "?token=<REDACTED>"

            $results.Add((New-ErrorResponse `
                -ErrorCode "ERR_API_FAILURE" `
                -ErrorMessage "External API request failed due to possible timeout, network error or unexpected response." `
                -ErrorTarget $sanitizedUrl `
                -ErrorDetails $null `
                -IP $ip))

        }
    }
    
    return ,$results.ToArray()

}


function Get-IPInfoLiteBatchParallel {
    <#
    .SYNOPSIS
        Performs high-efficiency batch IP lookups in parallel using the IPinfo Lite API. Requires PowerShell 7 or later.
    .PARAMETER token
        Your IPinfo API token.
    .PARAMETER ips
        Array of IP addresses to look up.
    .OUTPUTS
        Returns an array of PSCustomObject results with country-level geolocation and ASN data, or an error message if the query fails.
 
    .EXAMPLE
        Get-IPInfoLiteBatchParallel -Token "your_token_here" -ips @("8.8.8.8", "1.1.1.1")
 
        Executes a batch of parallel IP lookups using the IPinfo Lite API.
        Returns structured geolocation and ASN information for each IP address.
    #>
    
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param (
        [Parameter(Mandatory = $true)]
        [string]$token,

        [Parameter(Mandatory = $true)]
        [string[]]$ips
    )

    if ($PSVersionTable.PSVersion.Major -lt 7) {
        $errorRecord = [System.Management.Automation.ErrorRecord]::new(
            ([System.NotSupportedException]::new("PowerShell 7 or later is required.")),
            "ERR_PS_VERSION_UNSUPPORTED",
            [System.Management.Automation.ErrorCategory]::NotInstalled,
            $null
        )
        throw $errorRecord
    }

    # Validate token
    $testResult = Test-IPInfoLiteToken -token $token
    if (-not $testResult.Success) {
        return New-ErrorResponse `
            -ErrorCode "ERR_TOKEN_VERIFICATION" `
            -ErrorMessage "The API token provided could not be verified. Please ensure the token is correct, active, and has the necessary permissions" `
            -ErrorTarget "Token Validation" `
            -ErrorDetails $testResult
    }
    # Use shared cache instance
    $cache = $script:QueryCache

    # Create the ConcurrentBag typed to PSCustomObject for thread-safe results
    $resultsBag = [System.Collections.Concurrent.ConcurrentBag[PSCustomObject]]::new()

    # Use a high-performance list to track IPs to process
    $ipsToQueryList = [System.Collections.Generic.List[string]]::new()

    # Initialize an empty strongly-typed .NET List to hold chunks of IP addresses for batch processing
    $ipChunks = [System.Collections.Generic.List[object]]::new()


    foreach ($ip in $ips) {
            
            # Check if the IP is a bogon
            if (Test-BogonIP -ip $ip) {
                $bogonResponse = New-ErrorResponse `
                    -ErrorCode "ERR_BOGON_INPUT" `
                    -ErrorMessage "The provided IP address is classified as a bogon (non-routable or reserved) and is excluded from querying." `
                    -ErrorTarget $ip `
                    -IP $ip
                

                $resultsBag.Add($bogonResponse)
                continue
            }

            # Check if the IP is already cached
            if ($cache.ContainsKey($ip)) {
                $cached = $cache.Get($ip) | Select-Object * -ExcludeProperty CacheHit
                $cached | Add-Member -NotePropertyName 'CacheHit' -NotePropertyValue $true
                
                $resultsBag.Add($cached)
                continue
            }
            
            # If not bogon or cached, queue for parallel querying
            $ipsToQueryList.Add($ip)
    }

    # Convert to array for use with ForEach-Object -Parallel
    $ipsToQuery = $ipsToQueryList.ToArray()

    # Split the IP list into chunks of size $chunkSize for controlled parallel processing.
    # Helps manage resource usage and stay within API rate limits.
    $chunkSize = $config.processing.chunkSize
    for ($i = 0; $i -lt $ipsToQuery.Count; $i += $chunkSize) {
        $ipChunks.Add($ipsToQuery[$i..[Math]::Min($i + $chunkSize - 1, $ipsToQuery.Count - 1)])
    }

    # Move the API configurations to local variables
    # This tends to work better with -Parallel
    $apiBaseUrl = $config.api.baseUrl
    $apiHeaders = $config.api.headers

    foreach ($ipChunk in $ipChunks) {
        $ipChunk | ForEach-Object -Parallel {
        $ip = $_

        Try {
            # Prepare Local Variables
            $locaHeaders = $using:apiHeaders
            $localHttpClient = $using:httpClient
        
    
            # Prepare URL
            $localBaseUrl = $using:apiBaseUrl
            $localToken = $using:token
            $url = "${localBaseUrl}${ip}" + "?token=${localToken}"
    
            # Build HTTP request
            $request = [System.Net.Http.HttpRequestMessage]::new(
            [System.Net.Http.HttpMethod]::Get, $url
            )

            # Add headers to the request
            foreach ($kvp in $locaHeaders.GetEnumerator()) {
            [void]$request.Headers.TryAddWithoutValidation($kvp.Key, $kvp.Value) #| Out-Null
            }      

            # Send the request and read the response
            $response = $localHttpClient.Send($request)

            if (-not $response.IsSuccessStatusCode) {
                throw "HTTP request failed with status code $($response.StatusCode) for IP $ip"
            }

            $stream = $response.Content.ReadAsStream()
            $reader = New-Object System.IO.StreamReader($stream)
            $body = $reader.ReadToEnd()
            $json = $body | ConvertFrom-Json

            # Prepare Flag Data
            $localFlags = $using:flags
            $flagEmoji = $localFlags[$json.country_code].Emoji
            $flagUnicode = $localFlags[$json.country_code].unicode

            $result = [PSCustomObject]@{
                Success                 = $true
                IP                      = $json.ip
                ASN                     = $json.asn
                ASN_Name                = $json.as_name
                ASN_Domain              = $json.as_domain
                Country                 = $json.country
                Country_Code            = $json.country_code
                Country_Flag_Emoji      = $flagEmoji
                Country_Flag_Unicode    = $flagUnicode
                Continent               = $json.continent
                Continent_Code          = $json.continent_code
                CacheHit                = $false
            }
        }
        catch {
            # Only sanitize if an error occurred
            $sanitizedUrl = "${localBaseUrl}${ip}" + "?token=<REDACTED>"
        
            $result = [PSCustomObject]@{
                Success                 = $false
                IP                      = $ip
                ASN                     = $null
                ASN_Name                = $null
                ASN_Domain              = $null
                Country                 = $null
                Country_Code            = $null
                Country_Flag_Emoji      = $null
                Country_Flag_Unicode    = $null
                Continent               = $null
                Continent_Code          = $null
                CacheHit                = $null
                ErrorCode               = "ERR_API_FAILURE"
                ErrorMessage            = "External API request failed due to possible timeout, network error or unexpected response."
                ErrorTarget             = $sanitizedUrl
                ErrorTimestamp          = (Get-Date).ToUniversalTime().ToString("o")
                ErrorDetails            = $null
            }
        }

        $bag = $using:resultsBag
        $bag.Add($result)
        } -ThrottleLimit 15
    
        Start-Sleep -Milliseconds 250  # Backoff between chunks
    }

    # Update the shared cache with new successful results.
    foreach ($result in $resultsBag) {
        if ($result.Success -and -not $result.CacheHit -and $result.IP -and $result.IP.Trim() -ne "") {
            $cache_object = $result.PSObject.Copy()
            $cache_object.CacheHit = $true
            $cache.Add($result.ip, $cache_object)
        }
    }

    return $resultsBag.ToArray()
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


# Ensure the System.Net.Http assembly is loaded.
# PowerShell 5.1 does not automatically load this .NET assembly, even though it exists on all supported systems.
# This check ensures that HttpClient and related types are available before use.
if ($PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSEdition -eq 'Desktop') {
    if (-not ("System.Net.Http.HttpClient" -as [type])) {
        Add-Type -AssemblyName "System.Net.Http"
    }
}

# Initialize a reusable HttpClient (if not already initialized)
if (-not $script:httpClient) {
    $script:httpClient = [System.Net.Http.HttpClient]::new()
    $script:httpClient.Timeout = [System.TimeSpan]::FromSeconds(30)
}

# Initialize query cache instance
$script:QueryCache = [QueryCache]::new($script:config.cache.queryLimit)

# Initialize static bogon range cache
$Script:BogonRanges = Initialize-BogonRanges

# Initialize Country Flag Table
$Script:flags = Initialize-CountryFlagTable


Export-ModuleMember -Function Get-IPInfoLiteEntry, Get-IPInfoLiteBatch, Get-IPInfoLiteBatchParallel, Get-IPInfoLiteCache, Clear-IPInfoLiteCache