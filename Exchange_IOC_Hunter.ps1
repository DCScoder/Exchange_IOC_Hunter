###################################################################################
#
#    Script:    Exchange_IOC_Hunter.ps1
#    Version:   1.0
#    Author:    Dan Saunders
#    Contact:   dcscoder@gmail.com
#    Purpose:   Hunt for IOCs in IIS Logs - CVE-2021-26855, CVE-2021-26857, CVE-2021-26858, CVE-2021-27065
#    Usage:     .\Exchange_IOC_Hunter.ps1
#    Credit:    https://github.com/mr-r3b00t/ExchangeMarch2021IOCHunt
#
#    This program is free software: you can redistribute it and / or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program. If not, see <https://www.gnu.org/licenses/>.
#
###################################################################################

$script = "Exchange_IOC_Hunter"
$version = "v1.0"

# IOC
# IP Address
$ips = "103.77.192.219","104.140.114.110","104.248.49.97","104.250.191.110","108.61.246.56","125.70.170.26",
"149.28.14.163","157.230.221.198","161.35.1.207","161.35.1.225","161.35.45.41","165.232.154.116","167.99.168.251",
"167.99.239.29","182.18.152.105","185.250.151.72","188.166.162.201","192.81.208.169","203.160.69.66","211.56.98.146",
"45.77.252.175","5.2.69.13","5.254.43.18","80.92.205.81","86.105.18.116","89.34.111.11","91.192.103.43"

########## Startup ##########

Write-Host "
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Script: Exchange_IOC_Hunter.ps1 - $version - Author / Autor: Dan Saunders dcscoder@gmail.com

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"

# Destination
$dst = $PSScriptRoot
# System Date/Time
$timestamp = ((Get-Date).ToString('_yyyyMMdd_HHmmss'))
# Store
$name = $script+$timestamp
$dir = $name
New-Item $dst\$dir\Files -ItemType Directory | Out-Null
New-Item $dst\$dir\Files\JavaScript -ItemType Directory | Out-Null
New-Item $dst\$dir\Files\WebShell -ItemType Directory | Out-Null
New-Item $dst\$dir\IPAddress -ItemType Directory | Out-Null

# Source
$src = Read-Host -Prompt "
Enter IIS Logs Source File Path, i.e. C:\IIS\Logs ->"

# Fetch Logs
$logs = Get-ChildItem -Recurse "$src\*.log"

# Search Files
# JavaScript
Write-Host "`nHunting for potential malicious Javascript (.js) files..." -ForegroundColor yellow -BackgroundColor black
findstr /S /snip /c:"/Error.aspx" "$src\*.log" > $dst\$dir\Files\JavaScript\x.txt
findstr /S /snip /c:"/Logout.aspx" "$src\*.log" > $dst\$dir\Files\JavaScript\y.txt

# Webshells
Write-Host "`nHunting for potential malicious WebShells (.aspx) files..." -ForegroundColor yellow -BackgroundColor black
findstr /S /snip /c:"/OutlookJP.aspx" "$src\*.log" > $dst\$dir\Files\WebShell\OutlookJP.txt
findstr /S /snip /c:"/MultiUp.aspx" "$src\*.log" > $dst\$dir\Files\WebShell\MultiUp.aspx.txt
findstr /S /snip /c:"/Shell.aspx" "$src\*.log" > $dst\$dir\Files\WebShell\Shell.aspx.txt
findstr /S /snip /c:"/RedirSuiteServerProxy.aspx" "$src\*.log" > $dst\$dir\Files\WebShell\RedirSuiteServerProxy.aspx.txt
findstr /S /snip /c:"/OutlookRU.aspx" "$src\*.log" > $dst\$dir\Files\WebShell\OutlookRU.aspx.txt
findstr /S /snip /c:"/Online.aspx" "$src\*.log" > $dst\$dir\Files\WebShell\Online.aspx.txt
findstr /S /snip /c:"/Discover.aspx" "$src\*.log" > $dst\$dir\Files\WebShell\Discover.aspx.txt
findstr /S /snip /c:"/OutlookEN.aspx" "$src\*.log" > $dst\$dir\Files\WebShell\OutlookEN.aspx.txt
findstr /S /snip /c:"/HttpProxy.aspx" "$src\*.log" > $dst\$dir\Files\WebShell\HttpProxy.aspx.txt
findstr /S /snip /c:"/Error.aspx" "$src\*.log" > $dst\$dir\Files\WebShell\Error.aspx.txt
findstr /S /snip /c:"/Logout.aspx" "$src\*.log" > $dst\$dir\Files\WebShell\Logout.aspx.txt
findstr /S /snip /c:"/help.aspx" "$src\*.log" > $dst\$dir\Files\WebShell\Help.aspx.txt
findstr /S /snip /c:"/iisstart.aspx" "$src\*.log" > $dst\$dir\Files\WebShell\iisstart.aspx.txt

# Search IP Addresses
Write-Host "`nHunting for malicious C2 IP Addresses..." -ForegroundColor yellow -BackgroundColor black
Write-Host "Please Note: This may take some time, please be patient."
foreach($log in $logs)
{
    Write-Host "Checking" $log.Name
    try
    {
        $file = Get-Content -Path $log
    }
    catch
    {

    }

    foreach ($ip in $ips)
    {
        $found = $file -cmatch $ip | Out-File $dst\$dir\IPAddress\IP_Address_Hits.txt
    }

}

Write-Host "
Script completed - review results in output files." -ForegroundColor green -BackgroundColor black