<#
.SYNOPSIS
    Windows CA Certificate Exporting Script
.DESCRIPTION
    Scans a Windows CA server and export the certificates as Base64 .CER files.
    It does not export private keys for security reasons.
    It includes many optional parameters that you can use to filter out specific certificates.
    The purpose of this script is to allow the PSCertsReport script to then produce a CSV/HTML report for monitoring expiration dates and avoid downtinmes as a result of expired certificates.
    => Run this script on your Windows CA server directly.
.NOTES
    Version: 1.1
    Date : 04-Nov-2025
    Requires: PowerShell 5.1 or higher (7.0+ recommended for parallel processing)
    Author: Michael DALLA RIVA with the help of some AI
    GitHub : https://github.com/michaeldallariva
    Blog : https://lafrenchaieti.com/
    License : Feel free to use for any purpose, personal or commercial.
#>


param(
    [string]$CAServer = "",  # Optional CA server name for full automation - You will not be prompted (e.g., "CASERVER01\MyCA")
    [string]$OutputFolder = "C:\ExportedCerts",
    [int]$MinimumValidityHours = 24,
    [string[]]$ExcludeCommonNames = @("Network Certificate", "testuser"),
    [string[]]$ExcludePrefixes = @("iphone", "laptop"),  # Exclude certificates starting with these prefixes
    [switch]$ExcludeEmailProtection = $true,  # Exclude certificates for email protection (S/MIME)
    [switch]$ExcludeEFS = $true,  #  Exclude certificates for Encrypting File System (EFS)
    [switch]$AllowDuplicateOverwrite = $true  # Set to $false to keep all duplicates with serial numbers
)

# Check if PSPKI module is installed
if (-not (Get-Module -ListAvailable -Name PSPKI)) {
    Write-Error "PSPKI module not found. Please install it first."
    exit 1
}

Import-Module PSPKI

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Certificate Export Script for Monitoring" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Get CA (manual or auto-detect)
try {
    if ([string]::IsNullOrWhiteSpace($CAServer)) {
        # Auto-detect CA
        Write-Host "`nAuto-detecting CA..." -ForegroundColor Yellow
        $CA = Get-CertificationAuthority
        
        if ($CA.Count -gt 1) {
            Write-Host "`nMultiple CAs detected:" -ForegroundColor Yellow
            Write-Host "========================================" -ForegroundColor Cyan
            
            # Display all detected CAs
            for ($i = 0; $i -lt $CA.Count; $i++) {
                Write-Host "[$($i + 1)] $($CA[$i].DisplayName) - $($CA[$i].ComputerName)" -ForegroundColor White
            }
            
            Write-Host "========================================" -ForegroundColor Cyan
            
            # Prompt user to select
            do {
                $selection = Read-Host "`nSelect CA number (1-$($CA.Count))"
                $selectedIndex = [int]$selection - 1
            } while ($selectedIndex -lt 0 -or $selectedIndex -ge $CA.Count)
            
            $CA = $CA[$selectedIndex]
            Write-Host "Selected CA: $($CA.DisplayName)" -ForegroundColor Green
        }
        else {
            Write-Host "Detected CA: $($CA.DisplayName)" -ForegroundColor Cyan
        }
    }
    else {
        # Use specified CA server
        Write-Host "`nUsing specified CA: $CAServer" -ForegroundColor Yellow
        $CA = Get-CertificationAuthority -Name $CAServer
        
        if ($null -eq $CA) {
            Write-Error "Could not connect to specified CA: $CAServer"
            Write-Host "`nPlease verify the CA name format. Examples:" -ForegroundColor Yellow
            Write-Host "  - 'CASERVER01\MyCA'" -ForegroundColor White
            Write-Host "  - 'ca.domain.com\Enterprise-CA'" -ForegroundColor White
            exit 1
        }
        Write-Host "Connected to CA: $($CA.DisplayName)" -ForegroundColor Green
    }
    
    Write-Host "Using CA: $($CA.DisplayName)" -ForegroundColor Cyan
}
catch {
    if ([string]::IsNullOrWhiteSpace($CAServer)) {
        Write-Error "Failed to detect CA automatically: $_"
    }
    else {
        Write-Error "Failed to connect to CA '$CAServer': $_"
    }
    exit 1
}

# Create output folder if it doesn't exist
if (-not (Test-Path -Path $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
    Write-Host "Created output folder: $OutputFolder" -ForegroundColor Green
} else {
    Write-Host "Output folder: $OutputFolder" -ForegroundColor White
}

# Calculate minimum validity date
$MinValidityDate = (Get-Date).AddHours($MinimumValidityHours)

Write-Host "`nRetrieving certificates from CA database..." -ForegroundColor Yellow
Write-Host "Criteria:" -ForegroundColor White
Write-Host "  - Valid until at least: $MinValidityDate" -ForegroundColor White
Write-Host "  - Excluding revoked certificates" -ForegroundColor White
Write-Host "  - Excluding CommonNames: $($ExcludeCommonNames -join ', ')" -ForegroundColor White
Write-Host "  - Excluding prefixes: $($ExcludePrefixes -join ', ')" -ForegroundColor White
if ($ExcludeEmailProtection) {
    Write-Host "  - Excluding email protection certificates (S/MIME)" -ForegroundColor White
}
if ($ExcludeEFS) {
    Write-Host "  - Excluding Encrypting File System (EFS) certificates" -ForegroundColor White
}
if ($AllowDuplicateOverwrite) {
    Write-Host "  - Duplicate CommonNames: Last certificate wins (overwrites)" -ForegroundColor Yellow
} else {
    Write-Host "  - Duplicate CommonNames: Keep all (append serial number)" -ForegroundColor Yellow
}

# Get all certificates
$AllCerts = Get-IssuedRequest -CertificationAuthority $CA -Property `
    RequestID, `
    CommonName, `
    SerialNumber, `
    NotAfter, `
    RawCertificate, `
    RevokedWhen

if ($null -eq $AllCerts -or $AllCerts.Count -eq 0) {
    Write-Warning "No certificates found in CA database."
    exit 0
}

Write-Host "Retrieved $($AllCerts.Count) total certificates." -ForegroundColor Green

# Filter certificates
Write-Host "`nFiltering certificates..." -ForegroundColor Yellow

$FilteredCerts = $AllCerts | Where-Object {
    $cert = $_
    $isExcludedPrefix = $false
    $isEmailCert = $false
    $isEFSCert = $false
    
    # Check if CommonName starts with any excluded prefix
    foreach ($prefix in $ExcludePrefixes) {
        if ($cert.CommonName -like "$prefix*") {
            $isExcludedPrefix = $true
            break
        }
    }
    
    # Check if certificate is for email protection (S/MIME) or EFS
    if (($ExcludeEmailProtection -or $ExcludeEFS) -and $null -ne $cert.RawCertificate) {
        try {
            $CertBytes = [Convert]::FromBase64String($cert.RawCertificate)
            $X509Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$CertBytes)
            
            # Check Enhanced Key Usage for Email Protection OID (1.3.6.1.5.5.7.3.4) and EFS OID (1.3.6.1.4.1.311.10.3.4)
            foreach ($eku in $X509Cert.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.37" }) {
                $ekuExt = [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]$eku
                foreach ($oid in $ekuExt.EnhancedKeyUsages) {
                    if ($ExcludeEmailProtection -and $oid.Value -eq "1.3.6.1.5.5.7.3.4") {  # Secure Email OID
                        $isEmailCert = $true
                    }
                    if ($ExcludeEFS -and $oid.Value -eq "1.3.6.1.4.1.311.10.3.4") {  # EFS OID
                        $isEFSCert = $true
                    }
                    if ($isEmailCert -and $isEFSCert) { break }
                }
                if (($isEmailCert -or -not $ExcludeEmailProtection) -and ($isEFSCert -or -not $ExcludeEFS)) { break }
            }
        }
        catch {
            # If we can't parse the cert, skip the email/EFS check
        }
    }
    
    # Apply all filters
    $_.NotAfter -gt $MinValidityDate -and
    [string]::IsNullOrEmpty($_.RevokedWhen) -and
    ($_.CommonName -notin $ExcludeCommonNames) -and
    (-not $isExcludedPrefix) -and
    (-not $isEmailCert) -and
    (-not $isEFSCert) -and
    ($null -ne $_.RawCertificate)
}

if ($null -eq $FilteredCerts -or $FilteredCerts.Count -eq 0) {
    Write-Warning "No certificates match the filtering criteria."
    exit 0
}

Write-Host "Found $($FilteredCerts.Count) certificates to export." -ForegroundColor Green

# Clean up old CER files
Write-Host "`nCleaning up old certificate files..." -ForegroundColor Yellow
$OldFiles = Get-ChildItem -Path $OutputFolder -Filter "*.cer" -ErrorAction SilentlyContinue
if ($OldFiles) {
    $OldFiles | Remove-Item -Force
    Write-Host "Removed $($OldFiles.Count) old certificate files." -ForegroundColor White
}

# Export certificates
Write-Host "`nExporting certificates as .CER files..." -ForegroundColor Yellow

$ExportedCount = 0
$SkippedCount = 0
$OverwrittenCount = 0
$Counter = 0
$ExportedFiles = @{}

foreach ($Cert in $FilteredCerts) {
    $Counter++
    if ($Counter % 100 -eq 0) {
        Write-Progress -Activity "Exporting Certificates" -Status "Processing $Counter of $($FilteredCerts.Count)" -PercentComplete (($Counter / $FilteredCerts.Count) * 100)
    }
    
    try {
        # Clean the CommonName for filename (same as original script)
        $SafeFileName = $Cert.CommonName
        $SafeFileName = $SafeFileName -replace '[*]', 'Star'
        $SafeFileName = $SafeFileName -replace '[\\/:"*?<>|]', '_'
        $SafeFileName = $SafeFileName -replace '\s+', '_'
        $SafeFileName = $SafeFileName.Trim('_')
        
        if ([string]::IsNullOrWhiteSpace($SafeFileName)) {
            $SafeFileName = "Cert_$($Cert.SerialNumber)"
        }
        
        $FilePath = Join-Path -Path $OutputFolder -ChildPath "$SafeFileName.cer"
        
        # Check if file already exists
        if ((Test-Path -Path $FilePath) -and -not $AllowDuplicateOverwrite) {
            # Append serial number for duplicates
            $SafeFileName = "${SafeFileName}_$($Cert.SerialNumber)"
            $FilePath = Join-Path -Path $OutputFolder -ChildPath "$SafeFileName.cer"
        }
        
        # Track if we're overwriting
        $IsOverwrite = $false
        if (Test-Path -Path $FilePath) {
            $IsOverwrite = $true
        }
        
        # Export certificate in Base64 PEM format
        if ($null -ne $Cert.RawCertificate -and $Cert.RawCertificate.Length -gt 0) {
            try {
                $CleanBase64 = $Cert.RawCertificate -replace '\s+', ''
                
                $Base64Lines = [regex]::Replace($CleanBase64, "(.{64})", "`$1`r`n")
                
                $PemContent = "-----BEGIN CERTIFICATE-----`r`n"
                $PemContent += $Base64Lines.TrimEnd()
                $PemContent += "`r`n-----END CERTIFICATE-----`r`n"
                
                $Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
                [System.IO.File]::WriteAllText($FilePath, $PemContent, $Utf8NoBom)
                
                if ($IsOverwrite) {
                    $OverwrittenCount++
                } else {
                    $ExportedCount++
                }
            }
            catch {
                Write-Warning "Certificate '$($Cert.CommonName)' - Failed to export: $_"
                $SkippedCount++
            }
        } else {
            $SkippedCount++
        }
    }
    catch {
        Write-Warning "Failed to export certificate '$($Cert.CommonName)': $_"
        $SkippedCount++
    }
}

Write-Progress -Activity "Exporting Certificates" -Completed

# Count actual files
$ActualFileCount = (Get-ChildItem -Path $OutputFolder -Filter "*.cer" | Measure-Object).Count

# Summary
Write-Host "`n========================================" -ForegroundColor Green
Write-Host "Export Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host "Total certificates processed: $($FilteredCerts.Count)" -ForegroundColor White
Write-Host "Unique files exported:        $ActualFileCount" -ForegroundColor Cyan
Write-Host "New exports:                  $ExportedCount" -ForegroundColor White
if ($OverwrittenCount -gt 0) {
    Write-Host "Overwritten duplicates:       $OverwrittenCount" -ForegroundColor Yellow
}
if ($SkippedCount -gt 0) {
    Write-Host "Skipped (errors):             $SkippedCount" -ForegroundColor Red
}
Write-Host "Output folder:                $OutputFolder" -ForegroundColor Cyan

# Show breakdown by CommonName to identify duplicates
Write-Host "`n=== Duplicate CommonName Analysis ===" -ForegroundColor Cyan
$DuplicateAnalysis = $FilteredCerts | Group-Object CommonName | Where-Object { $_.Count -gt 1 } | Sort-Object Count -Descending
if ($DuplicateAnalysis) {
    Write-Host "CommonNames with multiple certificates:" -ForegroundColor Yellow
    $DuplicateAnalysis | Select-Object -First 10 Name, Count | Format-Table -AutoSize
    Write-Host "Total CommonNames with duplicates: $($DuplicateAnalysis.Count)" -ForegroundColor White
} else {
    Write-Host "No duplicate CommonNames found." -ForegroundColor Green
}

Write-Host "`nThese .CER files are ready for monitoring." -ForegroundColor Green
