<#
.SYNOPSIS
    Remove everything Grant-AdscanCleanupAccount.ps1 granted, at the end of the engagement.

.DESCRIPTION
    Run as an Enterprise Admin of the forest. It removes the account from
    Enterprise Admins, removes any right granted to it on the forest's
    certification authorities (when PSPKI is installed), and disables the account.
    With -Delete it deletes the account instead of disabling it.

.EXAMPLE
    .\Revoke-AdscanCleanupAccount.ps1 -AccountName svc_adscan_cleanup
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string] $AccountName = "svc_adscan_cleanup",
    [switch] $Delete
)

Set-StrictMode -Version 2
$ErrorActionPreference = "Stop"
Import-Module ActiveDirectory

$forest = Get-ADForest
$root = Get-ADDomain -Identity $forest.RootDomain
$server = $root.PDCEmulator
$user = Get-ADUser -Filter "sAMAccountName -eq '$AccountName'" -Server $server
if (-not $user) {
    Write-Host "No account $AccountName in $($root.DNSRoot). Nothing to remove."
    return
}

$ea = Get-ADGroup -Identity "$($root.DomainSID)-519" -Server $server
if ($PSCmdlet.ShouldProcess($ea.Name, "Remove $AccountName")) {
    Remove-ADGroupMember -Identity $ea -Members $user -Server $server -Confirm:$false
    Write-Host "Removed $AccountName from $($ea.Name)."
}

if (Get-Module -ListAvailable -Name PSPKI) {
    Import-Module PSPKI
    $configNc = (Get-ADRootDSE -Server $server).configurationNamingContext
    $cas = Get-ADObject -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNc" `
        -Filter "objectClass -eq 'pKIEnrollmentService'" -Properties dNSHostName -Server $server
    foreach ($ca in $cas) {
        if ($PSCmdlet.ShouldProcess("$($ca.dNSHostName)\$($ca.Name)", "Remove rights of $AccountName")) {
            Get-CertificationAuthority -ComputerName $ca.dNSHostName |
                Get-CertificationAuthorityAcl |
                Remove-CertificationAuthorityAcl -Identity "$($root.NetBIOSName)\$AccountName" |
                Set-CertificationAuthorityAcl
            Write-Host "Removed any right of $AccountName on $($ca.Name)."
        }
    }
} else {
    Write-Host "PSPKI is not installed. If you granted $AccountName a right on a CA by hand, remove it in the Certification Authority console (Properties, Security)."
}

if ($Delete) {
    if ($PSCmdlet.ShouldProcess($AccountName, "Delete account")) {
        Remove-ADUser -Identity $user -Server $server -Confirm:$false
        Write-Host "Deleted $AccountName."
    }
} else {
    if ($PSCmdlet.ShouldProcess($AccountName, "Disable account")) {
        Disable-ADAccount -Identity $user -Server $server
        Write-Host "Disabled $AccountName."
    }
}
