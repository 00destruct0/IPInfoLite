@{
    RootModule              = 'IPInfoLite.psm1'
    ModuleVersion           = '3.0.1'
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
            ReleaseNotes  = 'v3.0.1: Added Export-IPInfoLiteLLM function for exporting IP geolocation data in JSONL format optimized for Large Language Model analysis (Claude, ChatGPT, Gemini). Enables AI-driven threat detection and pattern recognition. Fixed stray "True" values in Get-IPInfoLiteBatch output.'
        }
    }
}  