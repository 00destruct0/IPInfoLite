@{
    RootModule              = 'IPInfoLite.psm1'
    ModuleVersion           = '3.1.0'
    GUID                    = 'f6f32c7f-3e53-4d65-a821-9e4f3476a33d'
    Author                  = 'Ryan Terp'
    Copyright               = 'Copyright (c) 2025 Ryan Terp. Licensed under the MIT License.'
    Description             = 'Retrieves geolocation and ASN information from the IPinfo Lite API, with optional structured output optimized for LLM-based analysis.'
    PowerShellVersion       = '5.1'
    CompatiblePSEditions    = @('Desktop','Core')
    FunctionsToExport       = @('Clear-IPInfoLiteCache','Export-IPInfoLiteLLM','Get-IPInfoLiteEntry', 'Get-IPInfoLiteBatch', 'Get-IPInfoLiteCache')
    CmdletsToExport         = @()
    VariablesToExport       = @()
    AliasesToExport         = @()
    PrivateData             = @{
        PSData = @{
            Tags          = @('IP','geolocation','ASN','IPinfo','LLM','AI','Security')
            LicenseUri    = 'https://opensource.org/licenses/MIT'
            ProjectUri    = 'https://github.com/00destruct0/IPInfoLite'
            ReleaseNotes  = 'v3.1.0 - API authentication migrated to Bearer token headers, eliminating token exposure in URLs and logs. Includes SPDX SBOM with file integrity checksums, ASN normalization for LLM exports, and bug fixes for pipeline error handling and variable initialization.'
        }
    }
}  