# ################################################################################################################
# Certificate Export Script for Monitoring (PSExportAllCerts.ps1)
# ################################################################################################################


A set of 2 PowerShell scripts to automatically export certificates from a Windows Certificate Authority (CA) database to PEM format files for monitoring
It does export .CER files as Base64 format.

## Prerequisites

- Windows Server with Active Directory Certificate Services (AD CS)
- PowerShell 5.1 or later
- **PSPKI Module** - Install with:
  ```powershell
  Install-Module -Name PSPKI -Force
  ```
- Appropriate permissions to read from the CA database

## Features

- **Flexible CA Selection**: Auto-detect CA or specify a fixed CA server for automation
- **Smart Filtering**: Exclude expired, revoked, S/MIME, and EFS certificates
- **Duplicate Handling**: Configurable behavior for certificates with the same Common Name
- **PEM Format Output**: Exports certificates in Base64 PEM format (.cer files)
- **Prefix/Name Exclusions**: Filter out certificates by CommonName or prefix patterns
- **Progress Tracking**: Real-time progress display for large certificate databases

## Basic Usage

### Auto-detect CA (Interactive)
```powershell
.\PSExportAllCerts.ps1
```

### Specify CA Server (Automation)
```powershell
.\PSExportAllCerts.ps1 -CAServer "CASERVER01\MyCA"
```

### Custom Output Folder
```powershell
.\PSExportAllCerts.ps1 -CAServer "ca.domain.com\Enterprise-CA" -OutputFolder "C:\ExportedCerts"
```

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `CAServer` | String | `""` | Optional CA server name (e.g., "CASERVER01\MyCA"). If empty, auto-detects CA. |
| `OutputFolder` | String | `"C:\ExportedCerts"` | Directory where .cer files will be saved |
| `MinimumValidityHours` | Int | `24` | Minimum hours of validity remaining to export certificate |
| `ExcludeCommonNames` | String[] | `@("Network Certificate", "testuser")` | Exact CommonNames to exclude |
| `ExcludePrefixes` | String[] | `@("iphone", "laptop")` | Exclude certificates with CommonNames starting with these prefixes |
| `ExcludeEmailProtection` | Switch | `$true` | Exclude S/MIME email protection certificates |
| `ExcludeEFS` | Switch | `$true` | Exclude Encrypting File System (EFS) certificates |
| `AllowDuplicateOverwrite` | Switch | `$true` | If `$true`, overwrites duplicates. If `$false`, appends serial number to filename |

## Examples

### Keep All Certificates Including Duplicates
```powershell
.\PSExportAllCerts.ps1 -AllowDuplicateOverwrite:$false
```

### Export Certificates Valid for at Least 7 Days
```powershell
.\PSExportAllCerts.ps1 -MinimumValidityHours 168
```

### Custom Exclusions
```powershell
.\PSExportAllCerts.ps1 -ExcludeCommonNames @("TestCert", "TempUser") -ExcludePrefixes @("dev-", "test-")
```

### Include S/MIME and EFS Certificates
```powershell
.\PSExportAllCerts.ps1 -ExcludeEmailProtection:$false -ExcludeEFS:$false
```

### Full Automation Example
```powershell
.\PSExportAllCerts.ps1 `
    -CAServer "MYCA01\Corporate-CA" `
    -OutputFolder "C:\ExportedCerts" `
    -MinimumValidityHours 48 `
    -ExcludeCommonNames @("Network Certificate", "testuser") `
    -ExcludePrefixes @("temp-", "dev-") `
    -AllowDuplicateOverwrite:$true
```

## Output

The script generates:
- **PEM-formatted certificate files** (`.cer`) named after the certificate CommonName
- **Progress statistics** during execution
- **Summary report** showing:
  - Total certificates processed
  - Files exported
  - Duplicates handled
  - Any errors encountered
- **Duplicate analysis** showing CommonNames with multiple certificates

## Automation

### Scheduled Task Example
Create a scheduled task to run daily:
```powershell
$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File C:\Scripts\PSExportAllCerts.ps1 -CAServer 'CA01\MyCA'"
$Trigger = New-ScheduledTaskTrigger -Daily -At 2am
Register-ScheduledTask -TaskName "Export CA Certificates" -Action $Action -Trigger $Trigger -User "DOMAIN\ServiceAccount"
```

## Notes

- !!! The script removes all existing `.cer` files in the output folder before exporting !!!
- Certificates are filtered to exclude revoked and expired entries automatically
- CommonNames with invalid filesystem characters are sanitized in filenames
- The script requires appropriate CA read permissions to function


# ################################################################################################################
# Certificate Monitoring Script (PSCertsReport_v0.x)
# ################################################################################################################

A PowerShell script that scans .CER certificate files, generates visual reports, and sends optional email notifications.

## Features

- 📊 Scans folders containing .CER certificate files
- 📈 Generates HTML dashboard with interactive table and search/filter
- 📄 Exports detailed CSV reports
- 📧 Optional email notifications with attachments (Use a local SMTP server with IP whitelisting)
- 📧 Informations extracted from the certificates are publicaly available internally. No much point of encrypting the data or using SMTPS.
- ⚡ Parallel processing support (PowerShell 7+)

## Requirements

- **PowerShell 5.1+** (PowerShell 7+ recommended for faster processing)
- .NET Framework for SMTP functionality
- Read access to certificate folder

## Quick Start

### 1. Configure the Script

Edit the `$Config` section at the top of the script:

```powershell
$Config = @{
    # Certificate folder path
    CertificateFolder = "C:\ExportedCerts"
    
    # Output paths
    OutputFolder      = "C:\CertificateReports"
    
    # Email settings
    EnableEmail      = $true   # Set to $false to disable emails
    SmtpServer       = "your-smtp-server.local"
    EmailFrom        = "certificates@yourdomain.com"
    EmailTo          = @("admin@yourdomain.com")
    EmailCC          = @("manager@yourdomain.com")  # Optional
    EmailSubjectPrefix = "Certificate Monitoring Report"
    
    # Parallel processing
    ThrottleLimit    = 10  # Number of parallel threads (PS7+ only)
}
```

### 2. Run the Script

```powershell
.\PSCertsMonitor_v0.8.ps1
```

## Output Files

The script generates three files in the `OutputFolder`:

1. **HTML Report** - Interactive dashboard with:
   - Certificate statistics (Total, Valid, Expiring, Critical)
   - Sortable/filterable table
   - Click rows for detailed certificate information
   - Modern dark-themed interface

2. **CSV Report** - Spreadsheet-compatible data export with all certificate details

3. **Log File** - Execution log with timestamps and status messages

### File Naming Convention

```
HOSTNAME_Certs_Report_04-Nov-2025_14-30.html
HOSTNAME_Certs_Report_04-Nov-2025_14-30.csv
certificate_monitor.log
```

## Certificate Status Categories

| Status | Days Until Expiry | Badge Color |
|--------|------------------|-------------|
| **Valid** | > 30 days | 🟢 Green |
| **Notice** | 8-30 days | 🟡 Yellow |
| **Warning** | 3-7 days | 🟡 Yellow |
| **Critical** | 0-2 days | 🔴 Red |
| **Expired** | < 0 days | 🔴 Red |

## Email Notifications

When `EnableEmail = $true`, the script sends a daily summary email containing:

- Total certificate count
- Valid certificates count
- Certificates expiring soon (≤30 days)
- Critical certificates (≤2 days)
- Attached HTML and CSV reports

### Disable Email

Set `EnableEmail = $false` in the configuration to skip all email notifications.

## HTML Dashboard Features

- **Search**: Real-time text search across all certificate fields
- **Filter**: Filter by status (All, Valid, Expiring soon, Critical & Expired)
- **Interactive Details**: Click any row to view complete certificate information
- **Responsive Design**: Adapts to different screen sizes

## Scheduled Execution

Create a Windows Task Scheduler task to run the script automatically:

```powershell
# Example: Daily at 8:00 AM
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File C:\Scripts\PSCertsMonitor_v0.8.ps1"
$trigger = New-ScheduledTaskTrigger -Daily -At 8:00AM
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "Certificate Monitor" -Description "Daily certificate monitoring"
```

## Troubleshooting

### SMTP Errors

If you receive SMTP relay errors:
- Verify your server is whitelisted on the SMTP server
- Ensure the SMTP server allows unauthenticated relay
- Check `SmtpServer` hostname is correct

### No Certificates Found

- Verify `CertificateFolder` path is correct
- Ensure folder contains .CER files
- Check PowerShell has read permissions

### Performance (Large Certificate Sets)

- Use PowerShell 7+ for parallel processing
- Adjust `ThrottleLimit` (default: 10) based on system resources
- Consider filtering certificate folder to relevant certs only

