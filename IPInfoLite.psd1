@{
    RootModule              = 'IPInfoLite.psm1'
    ModuleVersion           = '2.0.0'
    GUID                    = 'f6f32c7f-3e53-4d65-a821-9e4f3476a33d'
    Author                  = 'Ryan Terp'
    Copyright               = 'Copyright (c) 2025 Ryan Terp. Licensed under the MIT License.'
    Description             = 'Queries geolocation and ASN info from IPinfo Lite API'
    PowerShellVersion       = '5.1'
    CompatiblePSEditions    = @('Desktop','Core')
    FunctionsToExport       = @('Get-IPInfoLiteEntry', 'Get-IPInfoLiteBatch', 'Get-IPInfoLiteCache', 'Clear-IPInfoLiteCache')
    CmdletsToExport         = @()
    VariablesToExport       = @()
    AliasesToExport         = @()
    PrivateData             = @{
        PSData = @{
            Tags          = @('IP','geolocation','ASN','IPinfo')
            LicenseUri    = 'https://opensource.org/licenses/MIT'
            ProjectUri    = 'https://github.com/00destruct0/IPInfoLite'
            ReleaseNotes  = 'Added IPInfo Lite Batch API integration with improved IP address validation to automatically filter out invalid inputs such as domain names, hostnames, malformed addresses, and empty values.'
        }
    }
}  