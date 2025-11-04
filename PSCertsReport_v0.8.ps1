<#
.SYNOPSIS
    Certificate Monitoring Script with Parallel Processing (PS7+) and PS5.1 Support
.DESCRIPTION
    Scans a folder for .CER certificate files, processes them (in parallel on PS7+),
    generates CSV/HTML reports, and sends email alerts for expiring certificates.
    Compatible with PowerShell 5.1 and PowerShell 7+.
.NOTES
    Version: 0.8
    Date : 04-Nov-2025
    Requires: PowerShell 5.1 or higher (7.0+ recommended for parallel processing)
    Author: Michael DALLA RIVA with the help of some AI
    GitHub : https://github.com/michaeldallariva
    Blog : https://lafrenchaieti.com/
    License : Feel free to use for any purpose, personal or commercial.
#>

# Minimum version check
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Host "ERROR: This script requires PowerShell 5.1 or higher" -ForegroundColor Red
    Write-Host "Your version: $($PSVersionTable.PSVersion)" -ForegroundColor Red
    exit 1
}

# ============================================================================
# CONFIGURATION SECTION - Modify these variables as needed
# ============================================================================

$Config = @{
    # Certificate folder path - Default location where .CER files are exported to using the PSExportAllCerts.ps1 script
    CertificateFolder = "C:\ExportedCerts"
    
    # Output paths
    OutputFolder      = "C:\CertificateReports" # Default location where the reports (CSV/HTML are created)
    LogFile          = "C:\CertificateReports\certificates_report.log"
    CsvReport        = "C:\CertificateReports\$($env:COMPUTERNAME)_Certs_Report_$(Get-Date -Format 'dd-MMM-yyyy_HH-mm').csv"
    HtmlReport       = "C:\CertificateReports\$($env:COMPUTERNAME)_Certs_Report_$(Get-Date -Format 'dd-MMM-yyyy_HH-mm').html"
    
    # Email settings
    EnableEmail      = $false   # Set to $false to disable all email notifications
    SmtpServer       = "192.168.50.10" # Change to your own SMTP server IP address / Uses port 25 per default / Information extracted from the .CER files is not confidentiel / Private keys are not exported.
    EmailFrom        = "sender@company.com"
    EmailTo          = @("recipient@company.com","second@company.com")
    EmailCC          = @() 
    EmailSubject     = "Certificate Monitoring Report - $(Get-Date -Format 'dd-MM-yyyy')"
    
    # Parallel processing settings
    ThrottleLimit    = 10  # Number of parallel threads
}

# ============================================================================
# FUNCTIONS
# ============================================================================

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO', 'WARNING', 'ERROR')]
        [string]$Level = 'INFO'
    )
    
    $timestamp = Get-Date -Format "dd-MMM-yyyy HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Ensure log directory exists
    $logDir = Split-Path $Config.LogFile -Parent
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    
    Add-Content -Path $Config.LogFile -Value $logMessage
    
    # Also write to console with color
    $color = switch ($Level) {
        'ERROR' { 'Red' }
        'WARNING' { 'Yellow' }
        default { 'White' }
    }
    Write-Host $logMessage -ForegroundColor $color
}

function Get-CertificateDetails {
    param(
        [string]$CertPath
    )
    
    try {
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertPath)
        
        # Extract Common Name from Subject
        $subject = $cert.Subject
        $cn = if ($subject -match 'CN=([^,]+)') { $Matches[1] } else { $subject }
        
        # Calculate days until expiration
        $daysLeft = ($cert.NotAfter - (Get-Date)).Days
        
        # Determine status based on days left
                if ($daysLeft -lt 0) {
                    $status = 'Expired'
                }
                elseif ($daysLeft -le 2) {
                    $status = 'Critical'
                }
                elseif ($daysLeft -le 7) {
                    $status = 'Warning'
                }
                elseif ($daysLeft -le 30) {
                    $status = 'Notice'
                }
                else {
                    $status = 'Valid'
                }
        
        # Extract additional details from Subject and Issuer
        $subjectDict = @{}
        if ($cert.Subject) {
            $cert.Subject -split ',' | ForEach-Object {
                if ($_ -match '^\s*([^=]+)=(.+)$') {
                    $subjectDict[$Matches[1].Trim()] = $Matches[2].Trim()
                }
            }
        }
        
        # Get Enhanced Key Usage
        $eku = ""
        try {
            $ekuExt = $cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Enhanced Key Usage" }
            if ($ekuExt) {
                $eku = $ekuExt.Format($false)
            }
        } catch { }
        
        # Get Key Usage
        $keyUsage = ""
        try {
            $kuExt = $cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Key Usage" }
            if ($kuExt) {
                $keyUsage = $kuExt.Format($false)
            }
        } catch { }

        # Get Subject Alternative Names (SAN)
        $san = ""
        try {
            $sanExt = $cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Subject Alternative Name" }
            if ($sanExt) {
                $san = $sanExt.Format($false)
            }
        } catch { }
        
        return [PSCustomObject]@{
            FileName     = Split-Path $CertPath -Leaf
            Domain       = $cn
            Subject      = $cert.Subject
            Issuer       = $cert.Issuer
            IssuerName   = if ($cert.Issuer -match 'CN=([^,]+)') { $Matches[1] } else { $cert.Issuer }
            NotBefore    = $cert.NotBefore
            NotAfter     = $cert.NotAfter
            Thumbprint   = $cert.Thumbprint
            SerialNumber = $cert.SerialNumber
            DaysLeft     = $daysLeft
            Status       = $status
            LastChecked  = Get-Date
            Country      = if ($subjectDict.ContainsKey('C')) { $subjectDict['C'] } else { "" }
            Organization = if ($subjectDict.ContainsKey('O')) { $subjectDict['O'] } else { "" }
            OrgUnit      = if ($subjectDict.ContainsKey('OU')) { $subjectDict['OU'] } else { "" }
            Locality     = if ($subjectDict.ContainsKey('L')) { $subjectDict['L'] } else { "" }
            State        = if ($subjectDict.ContainsKey('S')) { $subjectDict['S'] } else { "" }
            KeyUsage     = $keyUsage
            EnhancedKeyUsage = $eku
            SubjectAltNames = $san
        }
    }
    catch {
        Write-Log "Error processing certificate '$CertPath': $($_.Exception.Message)" -Level ERROR
        return $null
    }
}


function New-HtmlReport {
    param(
        [array]$Certificates
    )
    
    # Calculate statistics
    $totalCount = $Certificates.Count
    $validCount = @($Certificates | Where-Object Status -eq 'Valid').Count
    $expiringCount = @($Certificates | Where-Object Status -in 'Notice','Warning').Count
    $criticalCount = @($Certificates | Where-Object Status -eq 'Critical').Count
    
    $html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Certificate Monitoring – Minimal Dark</title>
<style>
  :root {
    --bg: #1a2332;
    --panel: #1f2d42;
    --ink: #f0f4f8;
    --muted: #b4c5d8;
    --border: #2d3f5a;
    --success: #22c55e;
    --warning: #f59e0b;
    --danger: #ef4444;
    --accent: #4f46e5;
  }
  html, body { height:100%; }
  body {
    margin:0;
    background: var(--bg);
    color: var(--ink);
    font: 14px/1.45 Inter, ui-sans-serif, system-ui, Segoe UI, Roboto, Helvetica, Arial;
  }
  .wrapper { max-width: 80%; margin: 28px auto; padding: 0 20px; }
  header { display:flex; justify-content:space-between; align-items:center; margin-bottom: 20px; }
 h1 { font-size: 24px; margin:0 0 8px 0; font-weight:600; }
.meta { color: var(--muted); font-size:14px; margin-bottom: 4px; }

  .kpis {
    display:grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap:12px;
    margin-bottom: 12px;
  }
  .kpi {
    background: linear-gradient(180deg, rgba(255,255,255,.04), rgba(255,255,255,.02));
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 12px 14px;
  }
  .kpi .label { color: var(--muted); font-size:11px; text-transform: uppercase; letter-spacing:.08em; margin-bottom:6px; }
  .kpi .value { font-size:24px; font-weight:700; }

  .table-wrap {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    overflow: hidden;
  }
  table { width:100%; border-collapse: collapse; }
  thead th {
    text-align:left; padding:12px 14px; font-size:11px; color: var(--muted);
    background: #0f1528; text-transform: uppercase; letter-spacing:.06em; position: sticky; top:0;
  }
  tbody td { padding:11px 14px; border-top:1px solid var(--border); }
  tbody tr:hover td { background: rgba(255,255,255,.02); }
  td.numeric { text-align:center; font-variant-numeric: tabular-nums; }

  .badge {
    padding:2px 8px; border-radius:999px; font-size:12px; font-weight:600; display:inline-block;
    border:1px solid currentColor;
  }
  .badge.success { color: var(--success); }
  .badge.warning { color: var(--warning); }
  .badge.danger { color: var(--danger); }

  .tools { display:flex; gap:8px; margin: 8px 0 12px; }
  .tools input, .tools select {
    background: #0f1528; color: var(--ink); border:1px solid var(--border); border-radius:8px; padding:10px 12px;
  }

  @media (max-width: 900px) { .kpis { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
.modal {
    display: none;
    position: fixed;
    z-index: 1000;
    left: 0;
    top: 0;
    width: 100%;
    height: 100%;
    background-color: rgba(0,0,0,0.7);
    animation: fadeIn 0.2s;
  }
  
  @keyframes fadeIn {
    from { opacity: 0; }
    to { opacity: 1; }
  }
  
  .modal-content {
    background: var(--panel);
    margin: 3% auto;
    padding: 0;
    border: 1px solid var(--border);
    border-radius: 12px;
    width: 90%;
    max-width: 800px;
    max-height: 85vh;
    overflow-y: auto;
    box-shadow: 0 20px 60px rgba(0,0,0,0.5);
  }
  
  .modal-header {
    background: linear-gradient(180deg, rgba(255,255,255,.06), rgba(255,255,255,.03));
    padding: 20px 24px;
    border-bottom: 1px solid var(--border);
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  
  .modal-header h2 {
    margin: 0;
    font-size: 18px;
    font-weight: 600;
    color: var(--ink);
  }
  
  .modal-close {
    color: var(--muted);
    font-size: 28px;
    font-weight: bold;
    cursor: pointer;
    background: none;
    border: none;
    width: 32px;
    height: 32px;
    display: flex;
    align-items: center;
    justify-content: center;
    border-radius: 6px;
    transition: all 0.2s;
  }
  
  .modal-close:hover {
    background: rgba(255,255,255,0.1);
    color: var(--ink);
  }
  
  .modal-body {
    padding: 24px;
  }
  
  .cert-section {
    margin-bottom: 24px;
  }
  
  .cert-section:last-child {
    margin-bottom: 0;
  }
  
  .cert-section h3 {
    font-size: 14px;
    color: #64b5f6;
    margin-bottom: 12px;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    font-weight: 600;
  }
  
  .cert-detail-row {
    display: flex;
    padding: 10px 0;
    border-bottom: 1px solid rgba(255,255,255,0.05);
  }
  
  .cert-detail-row:last-child {
    border-bottom: none;
  }
  
  .cert-detail-label {
    flex: 0 0 180px;
    color: var(--muted);
    font-size: 13px;
    font-weight: 500;
  }
  
  .cert-detail-value {
    flex: 1;
    color: var(--ink);
    font-size: 13px;
    word-break: break-all;
    font-family: 'Courier New', monospace;
  }
  
  tbody tr {
    cursor: pointer;
  }
</style>
</head>
<body>
<div class="wrapper">
<header>
    <div>
      <h1>Certificate Monitoring</h1>
      <div class="meta">Report time: $(Get-Date -Format 'dd-MMM-yyyy HH:mm:ss')</div>
      <div class="meta">Hostname: $($env:COMPUTERNAME)</div>
    </div>
  </header>

  <section class="kpis">
    <div class="kpi"><div class="label">Total</div><div class="value">$totalCount</div></div>
    <div class="kpi"><div class="label">Valid</div><div class="value">$validCount</div></div>
    <div class="kpi"><div class="label">Expiring soon</div><div class="value">$expiringCount</div></div>
    <div class="kpi"><div class="label">Critical</div><div class="value">$criticalCount</div></div>
  </section>

<div class="tools">
    <input id="q2" type="search" placeholder="Search" />
    <select id="f2">
      <option value="">All</option>
      <option value="Valid">Valid</option>
      <option value="Expiring soon">Expiring soon</option>
      <option value="Critical">Critical & Expired</option>
    </select>
  </div>

  <div class="table-wrap">
    <table id="t2">
      <thead>
        <tr>
          <th>Domain</th>
          <th>Status</th>
          <th>Issuer</th>
          <th>Expiration</th>
          <th style="text-align:center;">Days left</th>
          <th>Last checked</th>
        </tr>
      </thead>
      <tbody>
        
"@

    foreach ($cert in $Certificates | Sort-Object DaysLeft) {
        # Determine badge class and status text
        $badgeClass = switch ($cert.Status) {
            'Valid' { 'success' }
            'Notice' { 'warning' }
            'Warning' { 'warning' }
            'Critical' { 'danger' }
            'Expired' { 'danger' }
            default { 'success' }
        }
        
        $statusText = switch ($cert.Status) {
            'Valid' { 'Valid' }
            'Notice' { 'Expiring soon' }
            'Warning' { 'Expiring soon' }
            'Critical' { 'Critical warning' }
            'Expired' { 'Expired' }
            default { 'Valid' }
        }
        
$daysLeftText = if ($cert.DaysLeft -lt 0) {
            "Expired"
        } else {
            "$($cert.DaysLeft) days"
        }
        
        $certDataJson = @{
            Domain = $cert.Domain
            Status = $statusText
            Issuer = $cert.IssuerName
            IssuerFull = $cert.Issuer
            Subject = $cert.Subject
            Expiration = $cert.NotAfter.ToString('dd-MMM-yyyy')
            IssueDate = $cert.NotBefore.ToString('dd-MMM-yyyy')
            DaysLeft = $daysLeftText
            LastChecked = $cert.LastChecked.ToString('dd-MMM-yyyy')
            Thumbprint = $cert.Thumbprint
            SerialNumber = $cert.SerialNumber
            Country = $cert.Country
            Organization = $cert.Organization
            OrgUnit = $cert.OrgUnit
            Locality = $cert.Locality
            State = $cert.State
            KeyUsage = $cert.KeyUsage
            EnhancedKeyUsage = $cert.EnhancedKeyUsage
            SubjectAltNames = $cert.SubjectAltNames
        } | ConvertTo-Json -Compress
        
        $certDataEscaped = $certDataJson -replace '"', '&quot;'
        
        $html += @"
<tr onclick="showCertDetails(this)" data-cert='$certDataEscaped'>
  <td>$($cert.Domain)</td>
  <td><span class="badge $badgeClass">$statusText</span></td>
  <td>$($cert.IssuerName)</td>
  <td>$($cert.NotAfter.ToString('dd-MMM-yyyy'))</td>
  <td class="numeric">$daysLeftText</td>
  <td>$($cert.LastChecked.ToString('dd-MMM-yyyy'))</td>
</tr>

"@
    }

    $html += @"
      </tbody>
    </table>
  </div>
  <div id="certModal" class="modal">
    <div class="modal-content">
      <div class="modal-header">
        <h2>Certificate Details</h2>
        <button class="modal-close" onclick="closeModal()">&times;</button>
      </div>
      <div class="modal-body" id="modalBody">
      </div>
    </div>
  </div>
</div>

<script>
  const q2 = document.getElementById('q2');
  const f2 = document.getElementById('f2');
  const tb2 = document.getElementById('t2').getElementsByTagName('tbody')[0];
  const modal = document.getElementById('certModal');
  
    function apply2() {
        const query = q2.value.toLowerCase().trim();
        const status = f2.value;
        for (const row of Array.from(tb2.rows)) {
        const text = row.innerText.toLowerCase();
        const matchesQuery = !query || text.includes(query);
        const statusText = row.cells[1].innerText.trim();
        let matchesStatus = !status;
        if (status === 'Critical') {
            matchesStatus = statusText === 'Critical warning' || statusText === 'Expired';
        } else if (status) {
            matchesStatus = statusText === status;
        }
        row.style.display = (matchesQuery && matchesStatus) ? '' : 'none';
        }
    }
  
  function showCertDetails(row) {
    const certData = JSON.parse(row.getAttribute('data-cert'));
    const modalBody = document.getElementById('modalBody');
    
    html = '<div class="cert-section"><h3>Certificate Status</h3>';
    html += '<div class="cert-detail-row"><div class="cert-detail-label">Domain:</div><div class="cert-detail-value">' + certData.Domain + '</div></div>';
    html += '<div class="cert-detail-row"><div class="cert-detail-label">Status:</div><div class="cert-detail-value">' + certData.Status + '</div></div>';
    html += '<div class="cert-detail-row"><div class="cert-detail-label">Issuer:</div><div class="cert-detail-value">' + certData.IssuerFull + '</div></div>';
    html += '<div class="cert-detail-row"><div class="cert-detail-label">Issue Date:</div><div class="cert-detail-value">' + certData.IssueDate + '</div></div>';
    html += '<div class="cert-detail-row"><div class="cert-detail-label">Expiration:</div><div class="cert-detail-value">' + certData.Expiration + '</div></div>';
    html += '<div class="cert-detail-row"><div class="cert-detail-label">Days Until Expiry:</div><div class="cert-detail-value">' + certData.DaysLeft + '</div></div>';
    html += '<div class="cert-detail-row"><div class="cert-detail-label">Serial Number:</div><div class="cert-detail-value">' + certData.SerialNumber + '</div></div>';
    html += '<div class="cert-detail-row"><div class="cert-detail-label">Thumbprint:</div><div class="cert-detail-value">' + certData.Thumbprint + '</div></div>';
    html += '<div class="cert-detail-row"><div class="cert-detail-label">Last Checked:</div><div class="cert-detail-value">' + certData.LastChecked + '</div></div>';
    html += '</div>';
    
    html += '<div class="cert-section"><h3>Certificate Details</h3>';
    html += '<div class="cert-detail-row"><div class="cert-detail-label">Subject:</div><div class="cert-detail-value">' + certData.Subject + '</div></div>';
    if (certData.SubjectAltNames && certData.SubjectAltNames !== 'None') {
        var sanFormatted = certData.SubjectAltNames.split(',').map(function(s) { return s.trim(); }).join('<br>');
        html += '<div class="cert-detail-row"><div class="cert-detail-label">Subject Alternative Names:</div><div class="cert-detail-value">' + sanFormatted + '</div></div>';
    } else {
        html += '<div class="cert-detail-row"><div class="cert-detail-label">Subject Alternative Names:</div><div class="cert-detail-value">None</div></div>';
    }

    
    if (certData.Country) html += '<div class="cert-detail-row"><div class="cert-detail-label">Country:</div><div class="cert-detail-value">' + certData.Country + '</div></div>';
    if (certData.State) html += '<div class="cert-detail-row"><div class="cert-detail-label">State/Province:</div><div class="cert-detail-value">' + certData.State + '</div></div>';
    if (certData.Locality) html += '<div class="cert-detail-row"><div class="cert-detail-label">Locality/Town:</div><div class="cert-detail-value">' + certData.Locality + '</div></div>';
    if (certData.Organization) html += '<div class="cert-detail-row"><div class="cert-detail-label">Organization:</div><div class="cert-detail-value">' + certData.Organization + '</div></div>';
    if (certData.OrgUnit) html += '<div class="cert-detail-row"><div class="cert-detail-label">Organizational Unit:</div><div class="cert-detail-value">' + certData.OrgUnit + '</div></div>';
    html += '</div>';
    
    html += '<div class="cert-section"><h3>Key Usage</h3>';
    if (certData.KeyUsage) html += '<div class="cert-detail-row"><div class="cert-detail-label">Key Usage:</div><div class="cert-detail-value">' + certData.KeyUsage + '</div></div>';
    if (certData.EnhancedKeyUsage) html += '<div class="cert-detail-row"><div class="cert-detail-label">Enhanced Key Usage:</div><div class="cert-detail-value">' + certData.EnhancedKeyUsage + '</div></div>';
    html += '</div>';
    
    modalBody.innerHTML = html;
    modal.style.display = 'block';
  }
  
  function closeModal() {
    modal.style.display = 'none';
  }
  
  window.onclick = function(event) {
    if (event.target == modal) {
      closeModal();
    }
  }
  
  q2.addEventListener('input', apply2);
  f2.addEventListener('change', apply2);
</script>

</body>
</html>
"@

    return $html
}

function Send-EmailNotification {
    param(
        [string]$Subject,
        [string]$Body,
        [switch]$IsHtml,
        [array]$Attachments = @()
    )
    
    if (-not $Config.EnableEmail) {
        Write-Log "Email notifications disabled - skipping email" -Level INFO
        return
    }
    
    try {
        $smtpClient = New-Object System.Net.Mail.SmtpClient($Config.SmtpServer)
        $smtpClient.EnableSsl = $false
        $smtpClient.UseDefaultCredentials = $false
        
        $mailMessage = New-Object System.Net.Mail.MailMessage
        $mailMessage.From = $Config.EmailFrom
        
        foreach ($to in $Config.EmailTo) {
            $mailMessage.To.Add($to)
        }
        
        if ($Config.EmailCC -and $Config.EmailCC.Count -gt 0) {
            foreach ($cc in $Config.EmailCC) {
                $mailMessage.CC.Add($cc)
            }
        }
        
        $mailMessage.Subject = $Subject
        $mailMessage.Body = $Body
        $mailMessage.IsBodyHtml = $IsHtml.IsPresent
        
        if ($Attachments.Count -gt 0) {
            foreach ($attachment in $Attachments) {
                if (Test-Path $attachment) {
                    $mailMessage.Attachments.Add($attachment)
                }
            }
        }
        
        $smtpClient.Send($mailMessage)
        Write-Log "Email sent successfully to $($Config.EmailTo -join ', ')" -Level INFO
        
        $mailMessage.Dispose()
        $smtpClient.Dispose()
    }
    catch {
        Write-Log "Failed to send email: $($_.Exception.Message)" -Level ERROR
    }
}

# ============================================================================
# MAIN SCRIPT EXECUTION
# ============================================================================

Write-Log "========================================" -Level INFO
Write-Log "Certificate Monitoring Script Started" -Level INFO
Write-Log "========================================" -Level INFO

# Validate configuration
if (-not (Test-Path $Config.CertificateFolder)) {
    Write-Log "Certificate folder not found: $($Config.CertificateFolder)" -Level ERROR
    exit 1
}

# Ensure output folder exists
if (-not (Test-Path $Config.OutputFolder)) {
    New-Item -ItemType Directory -Path $Config.OutputFolder -Force | Out-Null
    Write-Log "Created output folder: $($Config.OutputFolder)" -Level INFO
}

# Get all certificate files
Write-Log "Scanning for certificate files in: $($Config.CertificateFolder)" -Level INFO
$certFiles = Get-ChildItem -Path $Config.CertificateFolder -Filter "*.cer" -File -ErrorAction SilentlyContinue

if ($certFiles.Count -eq 0) {
    Write-Log "No certificate files found!" -Level WARNING
    exit 0
}

Write-Log "Found $($certFiles.Count) certificate files" -Level INFO

# Check PowerShell version and process certificates accordingly
$psVersion = $PSVersionTable.PSVersion.Major

if ($psVersion -ge 7) {
    # PowerShell 7+ with parallel processing
    Write-Log "Processing certificates in parallel using PowerShell $psVersion (Throttle: $($Config.ThrottleLimit))..." -Level INFO
    
    $certificates = $certFiles | ForEach-Object -ThrottleLimit $Config.ThrottleLimit -Parallel {
        function Get-CertificateDetails {
            param([string]$CertPath)
            
            try {
                $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertPath)
                
                # Extract Common Name from Subject
                $subject = $cert.Subject
                $cn = if ($subject -match 'CN=([^,]+)') { $Matches[1] } else { $subject }
                
                # Calculate days until expiration
                $daysLeft = ($cert.NotAfter - (Get-Date)).Days
                
                # Determine status based on days left
                        if ($daysLeft -lt 0) {
                            $status = 'Expired'
                        }
                        elseif ($daysLeft -le 2) {
                            $status = 'Critical'
                        }
                        elseif ($daysLeft -le 7) {
                            $status = 'Warning'
                        }
                        elseif ($daysLeft -le 30) {
                            $status = 'Notice'
                        }
                        else {
                            $status = 'Valid'
                        }
                
                # Extract additional details from Subject and Issuer
                $subjectDict = @{}
                if ($cert.Subject) {
                    $cert.Subject -split ',' | ForEach-Object {
                        if ($_ -match '^\s*([^=]+)=(.+)$') {
                            $subjectDict[$Matches[1].Trim()] = $Matches[2].Trim()
                        }
                    }
                }
                
                # Get Enhanced Key Usage
                $eku = ""
                try {
                    $ekuExt = $cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Enhanced Key Usage" }
                    if ($ekuExt) {
                        $eku = $ekuExt.Format($false)
                    }
                } catch { }
                
                # Get Key Usage
                $keyUsage = ""
                try {
                    $kuExt = $cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Key Usage" }
                    if ($kuExt) {
                        $keyUsage = $kuExt.Format($false)
                    }
                } catch { }

                # Get Subject Alternative Names (SAN)
                $san = ""
                try {
                    $sanExt = $cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Subject Alternative Name" }
                    if ($sanExt) {
                        $san = $sanExt.Format($false)
                    }
                } catch { }
                
                return [PSCustomObject]@{
                    FileName     = Split-Path $CertPath -Leaf
                    Domain       = $cn
                    Subject      = $cert.Subject
                    Issuer       = $cert.Issuer
                    IssuerName   = if ($cert.Issuer -match 'CN=([^,]+)') { $Matches[1] } else { $cert.Issuer }
                    NotBefore    = $cert.NotBefore
                    NotAfter     = $cert.NotAfter
                    Thumbprint   = $cert.Thumbprint
                    SerialNumber = $cert.SerialNumber
                    DaysLeft     = $daysLeft
                    Status       = $status
                    LastChecked  = Get-Date
                    Country      = if ($subjectDict.ContainsKey('C')) { $subjectDict['C'] } else { "" }
                    Organization = if ($subjectDict.ContainsKey('O')) { $subjectDict['O'] } else { "" }
                    OrgUnit      = if ($subjectDict.ContainsKey('OU')) { $subjectDict['OU'] } else { "" }
                    Locality     = if ($subjectDict.ContainsKey('L')) { $subjectDict['L'] } else { "" }
                    State        = if ($subjectDict.ContainsKey('S')) { $subjectDict['S'] } else { "" }
                    KeyUsage     = $keyUsage
                    EnhancedKeyUsage = $eku
                    SubjectAltNames = $san
                }
            }
            catch {
                Write-Warning "Error processing certificate '$CertPath': $($_.Exception.Message)"
                return $null
            }
        }
        
        $cert = Get-CertificateDetails -CertPath $_.FullName
        return $cert
    } | Where-Object { $null -ne $_ }
} else {
    # PowerShell 5.x with sequential processing
    Write-Log "Processing certificates sequentially using PowerShell $psVersion..." -Level INFO
    Write-Log "Note: Upgrade to PowerShell 7+ for faster parallel processing" -Level INFO
    
    $certificates = @()
    $counter = 0
    $total = $certFiles.Count
    
    foreach ($file in $certFiles) {
        $counter++
        if ($counter % 10 -eq 0) {
            Write-Log "Processing certificate $counter of $total..." -Level INFO
        }
        
        $cert = Get-CertificateDetails -CertPath $file.FullName
        if ($null -ne $cert) {
            $certificates += $cert
        }
    }
}

Write-Log "Successfully processed $($certificates.Count) certificates" -Level INFO

# Export to CSV
Write-Log "Exporting to CSV: $($Config.CsvReport)" -Level INFO
try {
        $certificates | Select-Object FileName, Domain, IssuerName, NotBefore, NotAfter, DaysLeft, Status, Thumbprint, SerialNumber, Country, Organization, OrgUnit, Locality, State, KeyUsage, EnhancedKeyUsage, SubjectAltNames | 
        Export-Csv -Path $Config.CsvReport -NoTypeInformation -Encoding UTF8
    
    if (Test-Path $Config.CsvReport) {
        $csvSize = (Get-Item $Config.CsvReport).Length
        Write-Log "CSV report created successfully ($csvSize bytes)" -Level INFO
    } else {
        Write-Log "CSV file was not created!" -Level ERROR
    }
}
catch {
    Write-Log "Failed to create CSV: $($_.Exception.Message)" -Level ERROR
}

# Generate HTML report
Write-Log "Generating HTML report: $($Config.HtmlReport)" -Level INFO
try {
    $htmlContent = New-HtmlReport -Certificates $certificates
    $htmlContent | Out-File -FilePath $Config.HtmlReport -Encoding UTF8
    
    if (Test-Path $Config.HtmlReport) {
        $htmlSize = (Get-Item $Config.HtmlReport).Length
        Write-Log "HTML report created successfully ($htmlSize bytes)" -Level INFO
    } else {
        Write-Log "HTML file was not created!" -Level ERROR
    }
}
catch {
    Write-Log "Failed to create HTML: $($_.Exception.Message)" -Level ERROR
}

# Send daily report email
$dailySummary = @"
<html>
<body style='font-family: Arial, sans-serif;'>
<h2>Certificate Monitoring Report</h2>
<p>Date: $(Get-Date -Format 'dd-MMM-yyyy HH:mm:ss')</p>
<ul>
    <li><strong>Total Certificates:</strong> $($certificates.Count)</li>
    <li><strong>Valid:</strong> $(@($certificates | Where-Object Status -eq 'Valid').Count)</li>
    <li><strong>Expiring Soon (≤30 days):</strong> $(@($certificates | Where-Object Status -in 'Notice','Warning','Critical').Count)</li>
    <li><strong>Critical (≤2 days):</strong> $(@($certificates | Where-Object Status -eq 'Critical').Count)</li>
</ul>
<p>Please see attached reports for complete details.</p>
</body>
</html>
"@

Send-EmailNotification -Subject $Config.EmailSubject -Body $dailySummary -IsHtml `
    -Attachments @($Config.CsvReport, $Config.HtmlReport)

# Summary
Write-Log "========================================" -Level INFO
Write-Log "Script execution completed successfully" -Level INFO
Write-Log "Total certificates processed: $($certificates.Count)" -Level INFO
Write-Log "Reports saved to: $($Config.OutputFolder)" -Level INFO

# List generated files
if (Test-Path $Config.CsvReport) {
    Write-Log "  - CSV: $($Config.CsvReport)" -Level INFO
}
if (Test-Path $Config.HtmlReport) {
    Write-Log "  - HTML: $($Config.HtmlReport)" -Level INFO
}
if (Test-Path $Config.LogFile) {
    Write-Log "  - Log: $($Config.LogFile)" -Level INFO
}

Write-Log "========================================" -Level INFO

# Display file links for easy access
Write-Host ""
Write-Host "Generated Reports:" -ForegroundColor Cyan
if (Test-Path $Config.HtmlReport) {
    Write-Host "  HTML: " -NoNewline -ForegroundColor White
    Write-Host $Config.HtmlReport -ForegroundColor Green
}
if (Test-Path $Config.CsvReport) {
    Write-Host "  CSV:  " -NoNewline -ForegroundColor White
    Write-Host $Config.CsvReport -ForegroundColor Green
}
Write-Host ""
Write-Host "To open HTML report: " -NoNewline -ForegroundColor Yellow
Write-Host "Start-Process '$($Config.HtmlReport)'" -ForegroundColor White
Write-Host ""
