@{
    RootModule        = 'IPInfoLite.psm1'
    ModuleVersion     = '1.3.0'
    GUID              = 'f6f32c7f-3e53-4d65-a821-9e4f3476a33d'
    Author            = 'Ryan Terp'
    Description       = 'Queries geolocation and ASN info from IPinfo Lite API'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Get-IPInfoLiteEntry', 'Get-IPInfoLiteBatch', 'Get-IPInfoLiteBatchParallel', 'Get-IPInfoLiteCache', 'Clear-IPInfoLiteCache')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags          = @('IP','geolocation','ASN','IPinfo')
            LicenseUri   = 'https://opensource.org/licenses/MIT'
            ReleaseNotes  = 'Added support for country flags, including both emoji and Unicode representations, to enhance readability in reports and visual outputs. Also improved resilience to network and API issues, along with general performance enhancements.'
        }
    }
}