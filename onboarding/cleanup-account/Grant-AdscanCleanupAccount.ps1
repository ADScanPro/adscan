<#
.SYNOPSIS
    Create the time-boxed cleanup account ADscan uses only to undo its own changes.

.DESCRIPTION
    Run once per forest, as an Enterprise Admin of that forest, from a host with
    the ActiveDirectory module (RSAT). It:

      1. creates a dedicated account for this engagement in the forest root, with
         an expiry date, so its activity is attributable to the engagement;
      2. adds it to Enterprise Admins, which administers every domain of this
         forest (and of no other forest);
      3. lists each enterprise certification authority of the forest and shows
         whether the account will be able to revoke certificates there
         ("Issue and Manage Certificates"). With -SetCaRights and the PSPKI module
         installed it grants that right on each CA; otherwise it prints the one
         step to do in the Certification Authority console;
      4. prints what it granted, in the same terms ADscan's pre-scan checklist uses.

    ADscan verifies all of this again, read-only, before the scan and before each
    change it makes. A right this script granted but that role separation or an
    officer restriction defeats afterwards is shown there as a gap.

    Remove everything with Revoke-AdscanCleanupAccount.ps1 when you have the report.

.EXAMPLE
    .\Grant-AdscanCleanupAccount.ps1 -AccountName svc_adscan_cleanup -ExpiresInDays 30
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string] $AccountName = "svc_adscan_cleanup",
    [ValidateRange(1, 365)]
    [int] $ExpiresInDays = 30,
    [switch] $SetCaRights
)

Set-StrictMode -Version 2
$ErrorActionPreference = "Stop"
Import-Module ActiveDirectory

$forest = Get-ADForest
$root = Get-ADDomain -Identity $forest.RootDomain
$server = $root.PDCEmulator
Write-Host "Forest $($forest.Name). Domains $($forest.Domains -join ', ')."

# 1. The account, in the forest root, expiring with the engagement.
$existing = Get-ADUser -Filter "sAMAccountName -eq '$AccountName'" -Server $server -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "The account $AccountName already exists in $($root.DNSRoot). It is reused."
    $user = $existing
} else {
    $password = Read-Host -AsSecureString "Password for $AccountName (you will give it to ADscan)"
    if ($PSCmdlet.ShouldProcess("$AccountName in $($root.DNSRoot)", "Create account")) {
        $user = New-ADUser -Name $AccountName -SamAccountName $AccountName `
            -AccountPassword $password -Enabled $true `
            -AccountExpirationDate (Get-Date).AddDays($ExpiresInDays) `
            -Description "ADscan cleanup account. Undoes ADscan's own changes only. Remove after the engagement." `
            -Server $server -PassThru
    }
}

# 2. Enterprise Admins of this forest.
$ea = Get-ADGroup -Identity "$($root.DomainSID)-519" -Server $server
if ($PSCmdlet.ShouldProcess($ea.Name, "Add $AccountName")) {
    Add-ADGroupMember -Identity $ea -Members $user -Server $server
}

# 3. Each enterprise certification authority of the forest.
$configNc = (Get-ADRootDSE -Server $server).configurationNamingContext
$cas = Get-ADObject -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNc" `
    -Filter "objectClass -eq 'pKIEnrollmentService'" -Properties dNSHostName -Server $server
$caLines = @()
foreach ($ca in $cas) {
    $config = "$($ca.dNSHostName)\$($ca.Name)"
    $acl = (& certutil -config $config -getreg CA\Security 2>$null) -join "`n"
    $granted = $acl -match "Allow\s+Issue and Manage Certificates[^\n]*Enterprise Admins"
    if (-not $granted -and $SetCaRights) {
        if (Get-Module -ListAvailable -Name PSPKI) {
            Import-Module PSPKI
            if ($PSCmdlet.ShouldProcess($config, "Grant Issue and Manage Certificates to $AccountName")) {
                Get-CertificationAuthority -ComputerName $ca.dNSHostName |
                    Get-CertificationAuthorityAcl |
                    Add-CertificationAuthorityAcl -Identity "$($root.NetBIOSName)\$AccountName" -AccessType Allow -AccessMask ManageCertificates |
                    Set-CertificationAuthorityAcl
                $granted = $true
            }
        } else {
            Write-Warning "PSPKI is not installed, so the right on $config was not set by this script."
        }
    }
    if ($granted) {
        $caLines += "  $($ca.Name), certificates ADscan requests, yes (Issue and Manage Certificates)"
    } else {
        $caLines += "  $($ca.Name), certificates ADscan requests, not with this account. On $($ca.dNSHostName), open the Certification Authority console, Properties, Security, add $AccountName and allow Issue and Manage Certificates."
    }
}

# 4. What was granted, in the checklist's terms.
Write-Host ""
Write-Host "Forest $($forest.Name), cleanup account $AccountName (expires in $ExpiresInDays days)"
foreach ($domain in $forest.Domains) {
    Write-Host "  $domain, changes in the directory, yes (Enterprise Admins)"
}
Write-Host "  $($forest.Name) forest configuration, certificate templates and the templates a CA publishes, yes (Enterprise Admins)"
$caLines | ForEach-Object { Write-Host $_ }
Write-Host ""
Write-Host "Give ADscan the account name and its password. ADscan checks every row again before the scan."
Write-Host "When you have the report, run Revoke-AdscanCleanupAccount.ps1 -AccountName $AccountName."
