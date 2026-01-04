<############################# INFORMATION ####################################
# SSL X509Certificates Inventory & Expiry Scanner v1.0
# Created 01/04/2026
# Author : ennebet.othmane@gmail.com
# Cloud & Security Architect


.COPYRIGHT .
THIS SAMPLE CODE AND ANY
RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER
EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.  We grant You a
nonexclusive, royalty-free right to use and modify the Sample Code and to
reproduce and distribute the object code form of the Sample Code, provided
that You agree: (i) to not use Our name, logo, or trademarks to market Your
software product in which the Sample Code is embedded; (ii) to include a valid
copyright notice on Your software product in which the Sample Code is embedded;
and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and
against any claims or lawsuits, including attorneys` fees, that arise or result
from the use or distribution of the Sample Code..

.DESCRITPION
+ This PowerShell script performs enterprise-wide SSL certificate inventory and expiry monitoring across Windows servers in an Active Directory domain. 
+ It discovers all domain-joined servers (excluding workstations), validates remote connectivity via ICMP and RPC, then enumerates certificates from all LocalMachine stores using the X509Store API.

.NOTES


├── [Input] Active Directory Domain Controllers/Servers (excl. WS*)
├── [Scan] All Certificate Stores (LocalMachine: Root, My, AuthRoot, etc.)
├── [Check] Remote access via WMI/RPC (Ping + Port 135)
├── [Extract] Cert details: Subject, Issuer, Thumbprint, Dates
├── [Analyze] Days to expiry, categorize (Expired/30d/90d/Year)
├── [Output] HTML Report w/ color-coded expiry status + Stats dashboard
└── [Stats] Total scanned, expiring counts by timeframe

.REQUIREMENTS 
#  - Run on a Domain Controller OR domain-joined machine with RSAT installed
#  - Requires Domain Admin or SPECIFIC access right to connect remote machines
#  - PowerShell v2 or above

.EXAMPLE
    .\Get_SSL_Certificates - v1.ps1

#>
cls

$DSroot = $env:USERDNSDOMAIN

write-host [X] SSL X509Certificates report -ForeGroundColor Blue


# Variables

$date = Get-Date -Format "dd/MM/yyyy HH:mm:ss"
$CertExpiringYear = 0
$CertExpiring0Month = 0
$ScannedCert = 0
$NbrCrtDiplayHtml = 0
$ExpIn3months = 0
$ExpIred = 0
$CertStores = (Get-ChildItem Cert:\).StoreNames.Keys | Select-Object -Unique
$month0 = "0"
$year = (get-date).year 
$DataRaw = ""

# Create Directory for HTML export

$HTMLdir = "C:\Temp\SSL Expiry"
if (!(Test-Path -Path $HTMLdir)) {
    New-Item -ItemType Directory -Path $HTMLdir -Force
}

# HTML Variables 


$Contosologo = "Contoso.png"
$Footlogo = "<IMG class='center' SRC=Footer.png width='70' height='65'>"

# FUNCTIONS 

Function Ping ([string]$hostname, [int]$timeout) 
{
    $ping = new-object System.Net.NetworkInformation.Ping #creates a ping object
	try { $result = $ping.send($hostname, $timeout).Status.ToString() }
    catch { $result = "Failed" }
	return $result
}

# Check-Port 
function Test-Port {
    param([string]$Hostname, [int]$Port = 135)
    try {
        $null = New-Object System.Net.Sockets.TcpClient($Hostname, $Port) -ErrorAction Stop
        return $true
    }
    catch { return $false }
}

function Pull-Certificate {
  
  
  [CmdLetBinding(DefaultParameterSetName = 'Certificate')]
  param(
    [Parameter(ParameterSetName = 'Certificate')]
    [Security.Cryptography.X509Certificates.StoreName[]]$StoreName = [Enum]::GetNames([Security.Cryptography.X509Certificates.StoreName]),
    [Security.Cryptography.X509Certificates.StoreLocation]$StoreLocation = "LocalMachine",
    [Parameter(ValueFromPipelineByPropertyName = $true)]
    [Alias('ComputerNameString', 'Name')]
    [String]$ComputerName = $env:ComputerName,
    [Parameter(ParameterSetName = 'Certificate')]
    [ValidateNotNullOrEmpty()]
    [String]$Issuer,
    [string]$SearchBase
  )

  begin {
    if ($StoreLocation -ne [Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine -and $ComputerName -ne $env:ComputerName) {
      Write-Warning "Certificates in the CurrentUser location cannot be read remotely."
      break
    }
 
    $WhereStatementText = '$_'
   
    if ($psboundparameters.ContainsKey("Issuer")) {
      $WhereStatementText = $WhereStatementText + ' -and $_.Issuer -like "*CN=$Issuer*"'
    }
    $WhereStatement = [ScriptBlock]::Create($WhereStatementText)
 }
  
  process {

  
      $StoreName | ForEach-Object {

        $StorePath = "\\$ComputerName\$_"
        $Store = New-Object Security.Cryptography.X509Certificates.X509Store($StorePath, $StoreLocation)
        $Store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
        
        if ($?) {
          $Store.Certificates |
            Add-Member StorePath -MemberType NoteProperty -Value $StorePath -PassThru |
            Add-Member ComputerName -MemberType NoteProperty -Value $ComputerName -PassThru |
            Where-Object $WhereStatement
          
          $Store.Close()
        }
      }
    }

}


# Active Directory Module check
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    throw "Module ActiveDirectory not found. Install RSAT or run from a host with AD tools."
}
Import-Module ActiveDirectory -ErrorAction Stop


# Remove html export file 

$Path = "C:\Temp\SSL Expiry\SSL_Certificates_Report.html"
If (Test-Path $path){
	Remove-Item $path -force
}

# Contoso SMTP INFO

$SMTPServer = ""
$SMTPPORT ="25"
$ToAddressDEST = ""
$ToAddressCC = ""


# HTML Start


$beginning="<tr style='background-color:white;'>"
$Header = "<table align='center' style='boder:0px 0px 0px 0px;'><tr>"
$header+= "<td align=center><b><td bgcolor='#000000' align=center><b><td bgcolor='#000000' align=center><b><td bgcolor='#000000' align=center><b><td bgcolor='#000000' align=center><b><td bgcolor='#000000' align=center><b><td bgcolor='#000000' align=center><b><td bgcolor='#000000' align=center><b><tr>"
$header+= "<td bgcolor='#9999FF' align=center><b><td bgcolor='#9999FF' align=center><b>Store<td bgcolor='#9999FF' align=center><b>Subject<td bgcolor='#9999FF' align=center><b>SerialNumber<td bgcolor='#9999FF' align=center><b>Thumbprint<td bgcolor='#9999FF' align=center><b>NotBefore<td bgcolor='#9999FF' align=center><b>NotAfter<td bgcolor='#9999FF' align=center><b>Expiration<tr>"
$TREND = "</tr>"
$Footer = "</table>"
$Disclamer = ("<br><I><A HREF='mailto:ennebet.othmane@gmail.com'>ennebet.othmane@gmail.com</A> <I><br>$Footlogo<br>")

# Processing 

#############

Write-Host "[X] Pulling active servers (<60d lastlogon) from $DSroot..." -ForegroundColor Blue

try {
    $CutOffDate = (Get-Date).AddDays(-60)
    $servers = Get-ADComputer -Filter "OperatingSystem -Like '*Windows Server*' -and Enabled -eq 'True' -and LastLogonDate -gt '$CutOffDate'" -Properties LastLogonDate |
               Select-Object Name, LastLogonDate
   
    Write-Host "[✓] Found $($servers.Count) active servers (Lastlogon less than 60Days)" -ForegroundColor Green

$TotalServers = $($servers.Count)
#############

foreach($S in $servers){
Sleep 1
$Server = $S
$S = $S.name
$LastLogon = if($Server.LastLogonDate) { $Server.LastLogonDate } else { "Never" }
$PingStatus = Ping $S 1000

Write-Host "[X] Getting Certificates Infos for $S (LastLogon:  $LastLogon ): " -ForegroundColor Blue


if ($PingStatus -eq "Success" -OR (Test-Port $S 135)){ 

foreach ($certificate in $CertStores){


try {

Pull-Certificate -StoreName $certificate -ComputerName $S |  ForEach-Object { 

$ScannedCert++
$NbrCrtDiplayHtml++


Write-Host [$NbrCrtDiplayHtml] Certificate on $Certificate Store  -ForegroundColor Yellow
$DataRaw +="<td bgcolor='#cccccc' align=center><font color='#000000'> " + $ScannedCert + "</td>"
$DataRaw +="<td bgcolor='#FAFAFA' align=center><font color='#000000'> "+ $S + "\" + $certificate + "</td>"
Write-Host ==> Subject : $_.subject -ForeGroundColor GREEN
$DataRaw +="<td bgcolor='#FAFAFA' align=center><font color='#000000'> " + $_.Subject + "</td>"
Write-Host ==> Issuer : $_.issuer -ForeGroundColor GREEN
$DataRaw +="<td bgcolor='#FAFAFA' align=center><font color='#000000'> " + $_.SerialNumber + " </td>"
Write-Host ==> Notbefore : $_.Notbefore -ForeGroundColor GREEN
$DataRaw +="<td bgcolor='#FAFAFA' align=center><font color='#000000'> " + $_.Thumbprint+ " </td>"
$DataRaw += "<td bgcolor='#FAFAFA' align=center><font color='#000000'> " + $_.notbefore+ " </td>"
Write-Host ==> Notafter : $_.Notafter -ForeGroundColor GREEN

# notafter
$targetDate = $_.notafter
$currentDate = Get-Date
$monthsLeft = (($targetDate.Year - $currentDate.Year) * 12) + ($targetDate.Month - $currentDate.Month)



# Current Year

if(($_.notafter).year -eq (get-date).year  ){
$CertExpiringYear++
}

# Current Month
if ($monthsLeft -eq $month0){
$CertExpiring0Month++
$DataRaw +="<td bgcolor='#f71423' align=center><font color='#FFFFFF'> " + $_.notAfter+ " </td>"
$DataRaw +="<td bgcolor='#f71423' align=center><font color='#FFFFFF'> In " + $monthsLeft + " month(s)</td></tr>"
Write-host "==> CRITICAL : Expires Current Month +$monthsLeft" -ForegroundColor RED
}

# Expiring in 3 Months

elseif ($monthsLeft -eq 3){
$ExpIn3months ++
$DataRaw +="<td bgcolor='#0FBFC0' align=center><font color='#FFFFFF'> " + $_.notAfter+ " </td>"
$DataRaw +="<td bgcolor='#0FBFC0' align=center><font color='#FFFFFF'> Expiring In 3 month(s)</td></tr>"
Write-host "==> WRN : Expires in +$monthsLeft months" -ForegroundColor Yellow
}

# Valid Certificates Month

elseif ($monthsLeft -gt $month0){
$DataRaw +="<td bgcolor='#387C44' align=center><font color='#FFFFFF'> " + $_.notAfter+ " </td>"
$DataRaw +="<td bgcolor='#387C44' align=center><font color='#FFFFFF'> In " + $monthsLeft + " month(s)</td></tr>"
Write-host "==> Info : ✅ Valid Certificate Days Left +$monthsLeft" -ForegroundColor DarkMagenta
}

# Expired Certificates
elseif ($monthsLeft -lt $month0){
$DataRaw +="<td bgcolor='#f71423' align=center><font color='#FFFFFF'> " + $_.notAfter+ " </td>"
$DataRaw +="<td bgcolor='#f71423' align=center><font color='#FFFFFF'> Expired</td></tr>"
Write-host "==> Info : Expired Certificate $monthsLeft" -ForegroundColor Gray
$ExpIred ++
}

}

}

catch {
$DataRaw +="<td bgcolor='#cccccc' align=center><font color='#000000'> -</td>"
$DataRaw +="<td bgcolor='#dedede' align=center><font color='#000000'> "+ $S + "\" + $certificate + "</td>"
$DataRaw +="<td bgcolor='#dedede' align=center><font color='#000000'> Cannot Get Info </td>"
$DataRaw +="<td bgcolor='#dedede' align=center><font color='#000000'> -</td>"
$DataRaw +="<td bgcolor='#dedede' align=center><font color='#000000'> -</td>"
$DataRaw +="<td bgcolor='#dedede' align=center><font color='#000000'> -</td>"
$DataRaw += "<td bgcolor='#dedede' align=center><font color='#000000'> - </td>"
$DataRaw +="<td bgcolor='#dedede' align=center><font color='#000000'> -</td></tr>"


}
$all += $beginning + $DataRaw + $TREND
$DataRaw = $null
}

$NbrCrtDiplayHtml = $null


}

else {
Write-Host "[!] Cannot Get Infos From " $S -ForegroundColor Red
}
}
}
catch {
Write-Host "[!] Cannot Get AD Servers objects " $S -ForegroundColor Red
}

# Creating HTML Tables 

$HeaderStart="<table class='header' width='85%' align='center'>
        <tr bgcolor='#FAFAFA'>
        <td style='text-align: center; text-shadow: 2px 2px 2px #ff0000;'>
        <img src=$Contosologo height=100 width=200>
        </td>
        <td class='header' width='626' align='center'>
       X509Certificates Inventory <td class='header' width='350' align='center'><p class='shadow'>Windows Servers</td>
</tr>

        </table><br><table width='65%' align='center'>
        <td bgcolor='#FFFFFF' width='25%'align=center><font color='#000000'> Domain : $DSroot </td><td bgcolor='#FFFFFF' width='25%'align=center><font color='#000000'> Started at $date </td><td bgcolor='#FFFFFF' width='25%'align=center><font color='#000000'> $TotalServers Server(s) Lastlogon <=60Days </td><td bgcolor='#FFFFFF' width='25%'align=center><font color='#000000'> $ScannedCert scanned certificates </td><tr><td bgcolor='#565656' width='25%' align=center><font color='#FFFFFF'> $CertExpiringYear expiring in $year </td><td bgcolor='#FFFF00' width='25%' align=center><font color='#000000'> $CertExpiring0Month expiring Current month</td><td bgcolor='#0FBFC0' width='25%'align=center><font color='#FFFFFF'> $ExpIn3Months Expiring in 3 months </td><td bgcolor='#f71423' width='25%'align=center><font color='#FFFFFF'> $ExpIred Expired</td></table>"


$afficherEnd = 	$HeaderStart + $Header + $all + $Footer

# HTML Format for Output 
$HTMLmessage = @"
<font color=""black"" face=""Arial"" size=""2"">
<STYLE TYPE="text/css">
    /* =====================
   Theme Variables
===================== */
:root {
    --primary: #387C44;
    --danger: #D32F2F;
    --border: #cfcfcf;
    --bg-light: #f9f9f9;
    --text-main: #222;
    --shadow-soft: 0 2px 6px rgba(0,0,0,0.15);
}

/* =====================
   Base Layout
===================== */
body {
    font-family: "Segoe UI", Tahoma, Arial, sans-serif;
    font-size: 8px;
    margin: 8px;
    background-color: #ffffff;
    color: var(--text-main);
}

/* =====================
   Tables (AUTO layout)
===================== */
table {
    border-collapse: collapse;
    width: 100%;
    background-color: var(--bg-light);
    /* table-layout: auto;  ← default, no fixed sizing */
}

td {
    padding: 6px 6px;
    border: 1px solid var(--border);
    font-size: 8px;
    white-space: normal;        /* allows wrapping */
    word-break: break-word;     /* prevents overflow */
    transition: background-color 0.2s ease;
}

/* Row hover instead of fixed cell feel */
tr:hover td {
    background-color: #eef6f0;
}

/* =====================
   Header
===================== */
.header {
    font-size: 22px;
    font-weight: 700;
    padding: 12px;
    text-align: center;
    color: #000;
    background: linear-gradient(135deg, #ffffff, #ececec);
    border: 1px solid var(--border);
    box-shadow: var(--shadow-soft);
}

/* =====================
   Status Labels
===================== */
.h1 {
    font-size: 8px;
    font-weight: 350;
    color: var(--primary);
    background-color: rgba(56, 124, 68, 0.12);
    padding: 3px 6px;
    border-radius: 4px;
    display: inline-block;
}

.h2 {
    font-size: 8px;
    font-weight: 350;
    color: var(--danger);
    background-color: rgba(211, 47, 47, 0.12);
    padding: 3px 6px;
    border-radius: 4px;
    display: inline-block;
}

/* =====================
   Utility
===================== */
.center { text-align: center; }
.small { font-size: 10px; opacity: 0.8; }
.shadow { box-shadow: var(--shadow-soft); }

    </style>
<body BGCOLOR=""white"">
$afficherEnd

$Disclamer
</body>
"@ 


ConvertTo-Html -body $HTMLmessage  | Out-File $Path

Write-Host "✅ Report has exported to HTML file " + ((Get-Location).Path + "\SSL_Certificates_Report.html")

If (Test-Path $path){

$body = Get-Content "C:\Temp\SSL Expiry\SSL_Certificates_Report.html" -Raw

#send-mailmessage -from "noreply@contoso.com" -to $ToAddressDEST -Cc $ToAddressCC -subject "Contoso : $date - [LAN : SSL Certificate report ] " -Body $body -BodyAsHtml -smtpServer $SMTPServer -port 25
Write-Host "Email sent to recipients!" -ForegroundColor Green
}
Write-Host "END Of Script! :)" -ForegroundColor Blue