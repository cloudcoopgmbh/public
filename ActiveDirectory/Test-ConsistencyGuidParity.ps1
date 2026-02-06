<#
.SYNOPSIS
  Prüft für einen UPN in mehreren AD-Forests/Domänen, ob überall dieselbe mS-DS-ConsistencyGuid gesetzt ist.
.DESCRIPTION
  - Fragt pro Forest/Domäne eigene Anmeldedaten ab (Get-Credential), speichert sie per Export-Clixml (DPAPI-geschützt).
  - Vor der ersten Benutzung die Domains anpassen oder Parameter übergeben. Standard: 4 Einträge mit Platzhaltern.
  - Lädt gespeicherte Credentials automatisch; mit -ReenterCreds können sie erneuert werden.
  - Ermittelt Default Naming Context (RootDSE), sucht den UPN, liest mS-DS-ConsistencyGuid & objectGUID.
  - Meldet Unterschiede (Mismatch) und exportiert optional eine CSV.
.PARAMETER UPN
  Der UserPrincipalName des Benutzers, der geprüft werden soll.
.PARAMETER OutputPath
  Ordner für Logs/CSV. Standard: C:\Temp\AnchorAudit
.PARAMETER ReenterCreds
  Erzwingt neue Eingabe der Anmeldedaten und überschreibt gespeicherte Clixml-Creds.
.PARAMETER NoPersistCreds
  Speichert Credentials NICHT; fragt nur für diesen Lauf ab.
.PARAMETER IncludeObjectGuid
  Nimmt objectGUID (Base64) in die Ausgabe auf (hilfreich für Cross-Checks).
.PARAMETER Domains
  Liste von Forest/Domain-Definitionen (Name, Server, optional BaseDN). Standard: 4 Platzhalter, anpassen vor Benutzung.
.EXAMPLE
  .\Test-ConsistencyGuidParity.ps1 -UPN "max.mustermann@cloudcoop.de"
.EXAMPLE
  .\Test-ConsistencyGuidParity.ps1 -UPN "max.mustermann@cloudcoop.de" -IncludeObjectGuid -ReenterCreds
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [string]$UPN,

  [string]$OutputPath = 'C:\Temp\AnchorAudit',

  [switch]$ReenterCreds,
  [switch]$NoPersistCreds,
  [switch]$IncludeObjectGuid,

  [Parameter(Mandatory=$false)]
  [array]$Domains = @(
    @{ Name='Forest A';  Server='dom1.cloudcoop.de';  Base='' },
    @{ Name='Forest B';  Server='dom1.cloudcoop.de';  Base='' },
    @{ Name='Forest C';  Server='dom1.cloudcoop.de';  Base='' },
    @{ Name='Forest D';  Server='dom1.cloudcoop.de';  Base='' }
  )
)

# --- Setup / Imports ---
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop

# Pfade
$null = New-Item -ItemType Directory -Path $OutputPath -Force -ErrorAction SilentlyContinue
$CredPath = Join-Path $OutputPath 'Creds'
$null = New-Item -ItemType Directory -Path $CredPath -Force -ErrorAction SilentlyContinue
$CsvPath = Join-Path $OutputPath ("Audit_{0}_{1}.csv" -f ($UPN -replace '[^\w\-@\.]','_'), (Get-Date -Format 'yyyyMMdd_HHmmss'))

# --- Credential Store (per Forest) ---
function Get-StoredCredential {
  param(
    [Parameter(Mandatory)][string]$ForestName
  )
  $file = Join-Path $CredPath ("cred_{0}.xml" -f ($ForestName -replace '[^\w\-]','_'))
  if (-not $NoPersistCreds -and -not $ReenterCreds -and (Test-Path $file)) {
    try { return Import-Clixml -Path $file } catch { }
  }
  # neu abfragen
  $cred = Get-Credential -Message "Anmeldung für Forest/Domäne '$ForestName'"
  if (-not $NoPersistCreds) {
    try { $cred | Export-Clixml -Path $file -Force } catch { Write-Warning "Konnte Credential nicht persistieren: $file" }
  }
  return $cred
}

# --- Default Naming Context via RootDSE ---
function Get-DefaultNamingContext {
  param(
    [Parameter(Mandatory)][string]$Server,
    [Parameter(Mandatory)][pscredential]$Credential
  )
  try {
    $pw = $Credential.GetNetworkCredential().Password
    $de = New-Object DirectoryServices.DirectoryEntry("LDAP://$Server/RootDSE", $Credential.UserName, $pw)
    return [string]$de.Properties['defaultNamingContext'][0]
  } catch {
    throw "DefaultNamingContext konnte auf '$Server' nicht ermittelt werden: $($_.Exception.Message)"
  }
}

# --- Benutzer in Domain suchen und Anker lesen ---
function Get-UserAnchorInfo {
  param(
    [Parameter(Mandatory)][string]$ForestName,
    [Parameter(Mandatory)][string]$Server,
    [Parameter(Mandatory)][pscredential]$Credential,
    [Parameter(Mandatory)][string]$BaseDN,
    [Parameter(Mandatory)][string]$UPN
  )
  $result = @()

  # Exakter UPN-Match per LDAPFilter
  $filter = "(&(objectClass=user)(userPrincipalName=$UPN))"
  $users = Get-ADUser -Server $Server -Credential $Credential -SearchBase $BaseDN -LDAPFilter $filter `
            -Properties mS-DS-ConsistencyGuid, objectGUID, userPrincipalName, distinguishedName, enabled -ErrorAction Stop

  if (-not $users) {
    return ,([pscustomobject]@{
      Forest             = $ForestName
      Server             = $Server
      Found              = $false
      DistinguishedName  = $null
      Enabled            = $null
      ConsistencyGuidB64 = $null
      ConsistencyLen     = 0
      ObjectGuidB64      = $null
      Note               = 'UPN nicht gefunden'
    })
  }

  foreach ($u in $users) {
    # msDS-ConsistencyGuid: Byte[] -> Base64
    $consB64 = $null
    $consLen = 0
    if ($u.'mS-DS-ConsistencyGuid') {
      $bytes  = [byte[]]$u.'mS-DS-ConsistencyGuid'
      $consB64 = [Convert]::ToBase64String($bytes)
      $consLen = $bytes.Length
    }
    $objB64 = if ($IncludeObjectGuid) { [Convert]::ToBase64String([byte[]]$u.objectGUID) } else { $null }

    $result += [pscustomobject]@{
      Forest             = $ForestName
      Server             = $Server
      Found              = $true
      DistinguishedName  = $u.DistinguishedName
      Enabled            = $u.Enabled
      ConsistencyGuidB64 = $consB64
      ConsistencyLen     = $consLen
      ObjectGuidB64      = $objB64
      Note               = if ($consLen -eq 16) { 'OK' } elseif ($consLen -eq 0) { 'mS-DS-ConsistencyGuid leer' } else { "Ungültige Länge ($consLen)" }
    }
  }

  return ,$result
}

# --- MAIN ---
$rows = @()
foreach ($d in $Domains) {
  $name   = $d.Name
  $server = $d.Server
  $base   = $d.Base

  try {
    $cred = Get-StoredCredential -ForestName $name
    if ([string]::IsNullOrWhiteSpace($base)) {
      $base = Get-DefaultNamingContext -Server $server -Credential $cred
    }
    Write-Host "[$name] Suche '$UPN' in $server / $base ..." -ForegroundColor Cyan
    $rows += Get-UserAnchorInfo -ForestName $name -Server $server -Credential $cred -BaseDN $base -UPN $UPN
  }
  catch {
    $rows += [pscustomobject]@{
      Forest             = $name
      Server             = $server
      Found              = $false
      DistinguishedName  = $null
      Enabled            = $null
      ConsistencyGuidB64 = $null
      ConsistencyLen     = 0
      ObjectGuidB64      = $null
      Note               = "FEHLER: $($_.Exception.Message)"
    }
  }
}

# Ausgabe & Bewertung
$rows | Sort-Object Forest | Format-Table -AutoSize `
  Forest, Found, Enabled, ConsistencyLen, ConsistencyGuidB64, Note

# konsistente ConsistencyGuid prüfen (nur dort, wo gefunden und Länge 16)
$present = $rows | Where-Object { $_.Found -and $_.ConsistencyLen -eq 16 }
$unique  = ($present | Select-Object -ExpandProperty ConsistencyGuidB64 -Unique)

if ($present.Count -eq 0) {
  Write-Warning "Der Benutzer wurde in keinem Forest mit gültigem mS-DS-ConsistencyGuid gefunden."
}
elseif ($unique.Count -eq 1) {
  Write-Host "✔ Konsistent: mS-DS-ConsistencyGuid ist in allen gefundenen Forests identisch." -ForegroundColor Green
  Write-Host "  Wert: $($unique[0])"
} else {
  Write-Host "✖ MISMATCH: Unterschiedliche mS-DS-ConsistencyGuid-Werte gefunden!" -ForegroundColor Red
  $present | Sort-Object Forest | Format-Table -AutoSize Forest, ConsistencyGuidB64, DistinguishedName
}

# CSV export
$rows | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
Write-Host "CSV exportiert: $CsvPath" -ForegroundColor Yellow

# Hinweis zu gespeicherten Credentials
if (-not $NoPersistCreds) {
  Write-Host "Gespeicherte Credentials: $CredPath (DPAPI-geschützt, nur von diesem Benutzer auf diesem Server lesbar)." -ForegroundColor DarkGray
  Write-Host "Zum Aktualisieren Credentials neu eingeben: Script mit -ReenterCreds starten. Zum Entfernen Dateien im Cred-Ordner löschen." -ForegroundColor DarkGray
}
# SIG # Begin signature block
# MIIfngYJKoZIhvcNAQcCoIIfjzCCH4sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBMSSiAjPQ82Z6F
# QdTRp5HrJJ10ZZwdiA3Pv9GEKC1iN6CCGbswggWNMIIEdaADAgECAhAOmxiO+dAt
# 5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBa
# Fw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3E
# MB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKy
# unWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsF
# xl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU1
# 5zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJB
# MtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObUR
# WBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6
# nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxB
# YKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5S
# UUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+x
# q4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIB
# NjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMC
# AYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0Nc
# Vec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnov
# Lbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65Zy
# oUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFW
# juyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPF
# mCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9z
# twGpn1eqXijiuZQwggZ9MIIEZaADAgECAhNJAAAAB6WQ7VHleFMkAAAAAAAHMA0G
# CSqGSIb3DQEBCwUAMEYxEzARBgoJkiaJk/IsZAEZFgNsb2MxFjAUBgoJkiaJk/Is
# ZAEZFgZzaWNoZWwxFzAVBgNVBAMTDlNpY2hlbCBSb290IENBMB4XDTIzMTAxOTEy
# NDUxNloXDTI4MTAxNzEyNDUxNlowVTETMBEGCgmSJomT8ixkARkWA2xvYzEWMBQG
# CgmSJomT8ixkARkWBnNpY2hlbDEOMAwGA1UEAxMFVXNlcnMxFjAUBgNVBAMTDUFk
# bWluaXN0cmF0b3IwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCwUgay
# lStLFG4MJc+OiQfZkFy1FwIVLbExkHx3HfihFHtPvLmGXQLmeN65ad1mizhD9cNz
# gOeKOXITkkK893HHsnpmc/WzyGZYhR2T5a/lLCoLraGbtYpWWdmTj2Oimvzdn+bi
# StvT649z8Lj105hUFwxO5dFlFgqFTfNwWuH9peHY+DXLRNclIu/fFErhWiVCjlGy
# XFOZB2028olzDdMwaOHQFfKtPn69z6SM5Td6DKYqfJYBBngsthdv7a3gWl2m2nGu
# +/9cOTB0CkoOqe7whkiMCzqmlAf3R/K86YItGay9KcO3NCeElQ47XFcimXcUBVD8
# GnZ38qvl99jwJlB1AgMBAAGjggJTMIICTzA9BgkrBgEEAYI3FQcEMDAuBiYrBgEE
# AYI3FQiErbgnhf/TeYbZiRKG/8Iaheb6ZIEEu7cfgq2VEQIBZAIBBzATBgNVHSUE
# DDAKBggrBgEFBQcDAzAOBgNVHQ8BAf8EBAMCB4AwGwYJKwYBBAGCNxUKBA4wDDAK
# BggrBgEFBQcDAzAdBgNVHQ4EFgQUfYiSFefx/7JE/3w9z0VY22J3ST0wHwYDVR0j
# BBgwFoAUxDsM1sJFoDhXaVK4AfDI84UvECIwQgYDVR0fBDswOTA3oDWgM4YxaHR0
# cDovL2NybC5hc2ljaGVsLmRlL2NybGQvU2ljaGVsJTIwUm9vdCUyMENBLmNybDCB
# wwYIKwYBBQUHAQEEgbYwgbMwgbAGCCsGAQUFBzAChoGjbGRhcDovLy9DTj1TaWNo
# ZWwlMjBSb290JTIwQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2Vz
# LENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9c2ljaGVsLERDPWxvYz9j
# QUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhv
# cml0eTAzBgNVHREELDAqoCgGCisGAQQBgjcUAgOgGgwYQWRtaW5pc3RyYXRvckBz
# aWNoZWwubG9jME0GCSsGAQQBgjcZAgRAMD6gPAYKKwYBBAGCNxkCAaAuBCxTLTEt
# NS0yMS0xMTEyNjA1NjY1LTIxMDQ2MTY4Ni0xMTI5MTQyMTU4LTUwMDANBgkqhkiG
# 9w0BAQsFAAOCAgEAOrT092dqsoeyHKGuSZu8XfbHx8kwUqGF0/Ej+ix6KP8nNXMs
# KxL1qs/zS9amFHC43EkZLIss80oAJcuxQdpY8/BjtJQdi4o82Ap7xyT7sBGeup8s
# rZrhaBK5+frcntK7e5gFQNugrYlOdwNMHWmHedDq/gNR4u/gFcJg7jf5Yzkn0Nv2
# ge+Ab9UDUk5GVLwvqt0l1JohdXzQwxoHUmtqAtOPgltrJ6Y5LAbkAozw4eAyEEob
# LH8LIoyDr+40BRw2lmBKcH0XC0C7lx0rL3Xh9bjzBRDIYAzRwEltbmA1gXRSNs/M
# 4j/nMLPybCzcVqC1o+8XmghGz6Ysy3Euvwd32pig5bbDG6FeUSws2qOgw+98DoUf
# pjd6KEwGWEvBJYpmjkggunSi+G4vT0q/q7NPNB8D6cvufCTEPsQ8PB3V6jhmTQ9C
# UQiOlOAyJzqtcUBsE42vOIdT8Lkn9NkIsLof3uKnRgHQRtIkciMF2HYpkoL9SEan
# +MY3nMesDMysloBP3w4Etl09VTGTMO0mnG1yfTi08B18xjKc4cFBn9GoXEb3p7qi
# NIxf+5uwEKO9Mvz2cyMKFw9wKo0DHsyu2rJ6rSeRefx4EkU7ElfqA4EF8pqqN5hs
# E6aBcRFMiEXP6doOLum7GWgXzjSjvTbGuuI3q5M15g2/zwXZbKY1WlrW190wgga0
# MIIEnKADAgECAhANx6xXBf8hmS5AQyIMOkmGMA0GCSqGSIb3DQEBCwUAMGIxCzAJ
# BgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5k
# aWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAe
# Fw0yNTA1MDcwMDAwMDBaFw0zODAxMTQyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcw
# FQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3Rl
# ZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEwggIiMA0G
# CSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC0eDHTCphBcr48RsAcrHXbo0ZodLRR
# F51NrY0NlLWZloMsVO1DahGPNRcybEKq+RuwOnPhof6pvF4uGjwjqNjfEvUi6wui
# m5bap+0lgloM2zX4kftn5B1IpYzTqpyFQ/4Bt0mAxAHeHYNnQxqXmRinvuNgxVBd
# Jkf77S2uPoCj7GH8BLuxBG5AvftBdsOECS1UkxBvMgEdgkFiDNYiOTx4OtiFcMSk
# qTtF2hfQz3zQSku2Ws3IfDReb6e3mmdglTcaarps0wjUjsZvkgFkriK9tUKJm/s8
# 0FiocSk1VYLZlDwFt+cVFBURJg6zMUjZa/zbCclF83bRVFLeGkuAhHiGPMvSGmhg
# aTzVyhYn4p0+8y9oHRaQT/aofEnS5xLrfxnGpTXiUOeSLsJygoLPp66bkDX1ZlAe
# SpQl92QOMeRxykvq6gbylsXQskBBBnGy3tW/AMOMCZIVNSaz7BX8VtYGqLt9MmeO
# reGPRdtBx3yGOP+rx3rKWDEJlIqLXvJWnY0v5ydPpOjL6s36czwzsucuoKs7Yk/e
# hb//Wx+5kMqIMRvUBDx6z1ev+7psNOdgJMoiwOrUG2ZdSoQbU2rMkpLiQ6bGRinZ
# bI4OLu9BMIFm1UUl9VnePs6BaaeEWvjJSjNm2qA+sdFUeEY0qVjPKOWug/G6X5uA
# iynM7Bu2ayBjUwIDAQABo4IBXTCCAVkwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNV
# HQ4EFgQU729TSunkBnx6yuKQVvYv1Ensy04wHwYDVR0jBBgwFoAU7NfjgtJxXWRM
# 3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMI
# MHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNl
# cnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20v
# RGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRw
# Oi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAg
# BgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQAD
# ggIBABfO+xaAHP4HPRF2cTC9vgvItTSmf83Qh8WIGjB/T8ObXAZz8OjuhUxjaaFd
# leMM0lBryPTQM2qEJPe36zwbSI/mS83afsl3YTj+IQhQE7jU/kXjjytJgnn0hvrV
# 6hqWGd3rLAUt6vJy9lMDPjTLxLgXf9r5nWMQwr8Myb9rEVKChHyfpzee5kH0F8HA
# BBgr0UdqirZ7bowe9Vj2AIMD8liyrukZ2iA/wdG2th9y1IsA0QF8dTXqvcnTmpfe
# Qh35k5zOCPmSNq1UH410ANVko43+Cdmu4y81hjajV/gxdEkMx1NKU4uHQcKfZxAv
# BAKqMVuqte69M9J6A47OvgRaPs+2ykgcGV00TYr2Lr3ty9qIijanrUR3anzEwlvz
# ZiiyfTPjLbnFRsjsYg39OlV8cipDoq7+qNNjqFzeGxcytL5TTLL4ZaoBdqbhOhZ3
# ZRDUphPvSRmMThi0vw9vODRzW6AxnJll38F0cuJG7uEBYTptMSbhdhGQDpOXgpIU
# sWTjd6xpR6oaQf/DJbg3s6KCLPAlZ66RzIg9sC+NJpud/v4+7RWsWCiKi9EOLLHf
# MR2ZyJ/+xhCx9yHbxtl5TPau1j/1MIDpMPx0LckTetiSuEtQvLsNz3Qbp7wGWqbI
# iOWCnb5WqxL3/BAPvIXKUjPSxyZsq8WhbaM2tszWkPZPubdcMIIG7TCCBNWgAwIB
# AgIQCoDvGEuN8QWC0cR2p5V0aDANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQGEwJV
# UzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRy
# dXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExMB4X
# DTI1MDYwNDAwMDAwMFoXDTM2MDkwMzIzNTk1OVowYzELMAkGA1UEBhMCVVMxFzAV
# BgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBTSEEyNTYg
# UlNBNDA5NiBUaW1lc3RhbXAgUmVzcG9uZGVyIDIwMjUgMTCCAiIwDQYJKoZIhvcN
# AQEBBQADggIPADCCAgoCggIBANBGrC0Sxp7Q6q5gVrMrV7pvUf+GcAoB38o3zBlC
# MGMyqJnfFNZx+wvA69HFTBdwbHwBSOeLpvPnZ8ZN+vo8dE2/pPvOx/Vj8TchTySA
# 2R4QKpVD7dvNZh6wW2R6kSu9RJt/4QhguSssp3qome7MrxVyfQO9sMx6ZAWjFDYO
# zDi8SOhPUWlLnh00Cll8pjrUcCV3K3E0zz09ldQ//nBZZREr4h/GI6Dxb2UoyrN0
# ijtUDVHRXdmncOOMA3CoB/iUSROUINDT98oksouTMYFOnHoRh6+86Ltc5zjPKHW5
# KqCvpSduSwhwUmotuQhcg9tw2YD3w6ySSSu+3qU8DD+nigNJFmt6LAHvH3KSuNLo
# ZLc1Hf2JNMVL4Q1OpbybpMe46YceNA0LfNsnqcnpJeItK/DhKbPxTTuGoX7wJNdo
# RORVbPR1VVnDuSeHVZlc4seAO+6d2sC26/PQPdP51ho1zBp+xUIZkpSFA8vWdoUo
# HLWnqWU3dCCyFG1roSrgHjSHlq8xymLnjCbSLZ49kPmk8iyyizNDIXj//cOgrY7r
# lRyTlaCCfw7aSUROwnu7zER6EaJ+AliL7ojTdS5PWPsWeupWs7NpChUk555K096V
# 1hE0yZIXe+giAwW00aHzrDchIc2bQhpp0IoKRR7YufAkprxMiXAJQ1XCmnCfgPf8
# +3mnAgMBAAGjggGVMIIBkTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTkO/zyMe39
# /dfzkXFjGVBDz2GM6DAfBgNVHSMEGDAWgBTvb1NK6eQGfHrK4pBW9i/USezLTjAO
# BgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwgZUGCCsGAQUF
# BwEBBIGIMIGFMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20w
# XQYIKwYBBQUHMAKGUWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2Vy
# dFRydXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNydDBf
# BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNl
# cnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5jcmww
# IAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUA
# A4ICAQBlKq3xHCcEua5gQezRCESeY0ByIfjk9iJP2zWLpQq1b4URGnwWBdEZD9gB
# q9fNaNmFj6Eh8/YmRDfxT7C0k8FUFqNh+tshgb4O6Lgjg8K8elC4+oWCqnU/ML9l
# Ffim8/9yJmZSe2F8AQ/UdKFOtj7YMTmqPO9mzskgiC3QYIUP2S3HQvHG1FDu+WUq
# W4daIqToXFE/JQ/EABgfZXLWU0ziTN6R3ygQBHMUBaB5bdrPbF6MRYs03h4obEMn
# xYOX8VBRKe1uNnzQVTeLni2nHkX/QqvXnNb+YkDFkxUGtMTaiLR9wjxUxu2hECZp
# qyU1d0IbX6Wq8/gVutDojBIFeRlqAcuEVT0cKsb+zJNEsuEB7O7/cuvTQasnM9AW
# cIQfVjnzrvwiCZ85EE8LUkqRhoS3Y50OHgaY7T/lwd6UArb+BOVAkg2oOvol/DJg
# ddJ35XTxfUlQ+8Hggt8l2Yv7roancJIFcbojBcxlRcGG0LIhp6GvReQGgMgYxQbV
# 1S3CrWqZzBt1R9xJgKf47CdxVRd/ndUlQ05oxYy2zRWVFjF7mcr4C34Mj3ocCVcc
# AvlKV9jEnstrniLvUxxVZE/rptb7IRE2lskKPIJgbaP5t2nGj/ULLi49xTcBZU8a
# tufk+EMF/cWuiC7POGT75qaL6vdCvHlshtjdNXOCIUjsarfNZzGCBTkwggU1AgEB
# MF0wRjETMBEGCgmSJomT8ixkARkWA2xvYzEWMBQGCgmSJomT8ixkARkWBnNpY2hl
# bDEXMBUGA1UEAxMOU2ljaGVsIFJvb3QgQ0ECE0kAAAAHpZDtUeV4UyQAAAAAAAcw
# DQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkq
# hkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGC
# NwIBFTAvBgkqhkiG9w0BCQQxIgQg9R25fAOvQJLR5eMUosmTnIQYzPkT3UodrcxU
# djlvGRkwDQYJKoZIhvcNAQEBBQAEggEAR00TcIuvusaLwYx9pM6wTr7l1cgpfnaO
# xaD4NHGHLy0cYZQfK4qrCdJs6eRPo2S4CyEWtSC1kFraALMIpOCv6n9SgWnV9wXl
# JP8OX3cytv41cz5w0r25U9a7av0C8hKMDKeocHE3/GV+8RHtpfsyd6WSzFweCXal
# Nk83hjy1htc06UuyQr1hhyyLvNMMPt71fPh2Qt+9YJ4lDK9tvWSbi68xkEQuBG6y
# Z6I9hbiqSns0ToSUFkKdODD+6n3uJwHyuubjZgiiNQgvNSawWWzXtecQXQWabVBz
# zRjPnqWYEKa8XaJI1gsOAuilXs8d6tVNOsb6FUE3NjVnAApgw+JAU6GCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjAyMDYxMzU1MjVaMC8GCSqGSIb3DQEJBDEiBCDp
# tFNmmefAO1IZYGVVL4RTOxRcbZ701g7cvLlmZA6VKzANBgkqhkiG9w0BAQEFAASC
# AgAm2oH448S7uK5xv0JxM23NJTOPyoJLPzPnG//OmMtei9g5mU6Pgq5Bj7pgqxb/
# AyWiMDR1l7fLneRLwFr5SInbsa9vcnEYoHdNR3JnKzIDaV5SBoNrpLzS9kNQLynM
# o9iDZAcg3AiQYsPD7M6SzcGlkCwUdFDD7Srlf1rgu7ipQP8ODD0KYxSGWuFNiNLH
# HLZ5KDq72rFcMDwPC1vkGbnasHrVKjg+9m+btc3uBW55NB8qCHIpUZPW9qkvoWdR
# pxdRjCWpICOBuCOlLMwaU+STk8th4oWuE2rb55MloDDG8XLwJYd2Litunpzdpf2R
# hclw3T6/ARTgc7YaNJ/4WZJY6Sb4bzwfuluVqUdTPke5cZNjWSeIWZJfrFmdohld
# H4QOTzqdE/Jy/VbB6h/cHFzsDB4+aXdelGbfH0t6cswvB3njhasmct4hAs/a+Jht
# csmJDbwNXdRRk7OiT7F34YoKNozJ7dC00ZfQUYsEy3aWGUBdtvubebW70Jk/SeZA
# h4m0vuUFNt85ZL2B0czQHf8GCNofiMEMQIXA1yTuiz60TO34Xsl0Fuu4Z4GkkyTw
# 1QnADs2pWgA8gMc0bV3KBV5PiBsFks0R1NIf5iTJSu7lCctLARzVLC1cU+SgQIKe
# rVAFsWdaJ9rqrysdPIcfrrofMzFI3/nn0kq2zI7zN05GfQ==
# SIG # End signature block
