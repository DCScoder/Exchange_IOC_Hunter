###################################################################################
#
#    Script:    Exchange_IOC_Hunter.ps1
#    Version:   1.2
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
$version = "v1.2"

# IOC
# IP Address
$ips = "103.77.192.219","104.140.114.110","104.248.49.97","104.250.191.110","108.61.246.56","125.70.170.26",
"149.28.14.163","157.230.221.198","161.35.1.207","161.35.1.225","161.35.45.41","165.232.154.116","167.99.168.251",
"167.99.239.29","182.18.152.105","185.250.151.72","188.166.162.201","192.81.208.169","203.160.69.66","211.56.98.146",
"45.77.252.175","5.2.69.13","5.254.43.18","80.92.205.81","86.105.18.116","89.34.111.11","91.192.103.43"

########## Startup ##########

Write-Host "
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Script: Exchange_IOC_Hunter.ps1 - $version - Author: Dan Saunders dcscoder@gmail.com

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"

# Destination
$dst = $PSScriptRoot
# System Date/Time
$timestamp = ((Get-Date).ToString('_yyyyMMdd_HHmmss'))
# Store
$name = $script+$timestamp
$dir = $name
New-Item $dst\$dir\Files -ItemType Directory | Out-Null

# Source
$src = Read-Host -Prompt "
Enter IIS Logs Source File Path, i.e. C:\IIS\Logs ->"

# Fetch Logs
$logs = Get-ChildItem -Recurse "$src\*.log"

# Search Files

# Remote Code Execution (RCE)
Write-Host "`nHunting for potential malicious Remote Code Execution (RCE)..." -ForegroundColor yellow -BackgroundColor black
New-Item $dst\$dir\RCE -ItemType Directory | Out-Null
New-Item $dst\$dir\RCE\Strings -ItemType Directory | Out-Null
findstr /S /snip /c:"/ecp/DDI/DDIService.svc/SetObject" "$src\*.log" > $dst\$dir\RCE\Strings\DDIService_svc_SetObject.txt
findstr /S /snip /c:"ResetOABVirtualDirectory" "$src\*.log" > $dst\$dir\RCE\Strings\ResetOABVirtualDirectory.txt

# JavaScript
Write-Host "`nHunting for potential malicious Javascript (.js) files..." -ForegroundColor yellow -BackgroundColor black
New-Item $dst\$dir\Files\JavaScript -ItemType Directory | Out-Null
findstr /S /snip /c:"/x.js" "$src\*.log" > $dst\$dir\Files\JavaScript\x.txt
findstr /S /snip /c:"/y.js" "$src\*.log" > $dst\$dir\Files\JavaScript\y.txt

# Webshells
Write-Host "`nHunting for potential malicious WebShells (.aspx) files..." -ForegroundColor yellow -BackgroundColor black
New-Item $dst\$dir\Files\WebShell -ItemType Directory | Out-Null
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
findstr /S /snip /c:"/Server.aspx" "$src\*.log" > $dst\$dir\Files\WebShell\Server.aspx.txt
findstr /S /snip /c:"/Supp0rt.aspx" "$src\*.log" > $dst\$dir\Files\WebShell\Supp0rt.aspx.txt
findstr /S /snip /c:"/xx.aspx" "$src\*.log" > $dst\$dir\Files\WebShell\xx.aspx.txt
findstr /S /snip /c:"/xclkmcfldfi948398430fdjkfdkj.aspx" "$src\*.log" > $dst\$dir\Files\WebShell\xclkmcfldfi948398430fdjkfdkj.aspx.txt
findstr /S /snip /c:"/log.aspx" "$src\*.log" > $dst\$dir\Files\WebShell\log.aspx.txt
findstr /S /snip /c:"/iispage.aspx" "$src\*.log" > $dst\$dir\Files\WebShell\iispage.aspx.txt
findstr /S /snip /c:"/s.aspx" "$src\*.log" > $dst\$dir\Files\WebShell\s.aspx.txt
findstr /S /snip /c:"/a.aspx" "$src\*.log" > $dst\$dir\Files\WebShell\a.aspx.txt
findstr /S /snip /c:"/shell2.aspx" "$src\*.log" > $dst\$dir\Files\WebShell\shell2.aspx.txt
findstr /S /snip /c:"/shell90.aspx" "$src\*.log" > $dst\$dir\Files\WebShell\shell90.aspx.txt
findstr /S /snip /c:"/default1.aspx" "$src\*.log" > $dst\$dir\Files\WebShell\default1.aspx.txt
findstr /S /snip /c:"/default.aspx" "$src\*.log" > $dst\$dir\Files\WebShell\default.aspx.txt
findstr /S /snip /c:"/one.aspx" "$src\*.log" > $dst\$dir\Files\WebShell\one.aspx.txt
findstr /S /snip /c:"/one1.aspx" "$src\*.log" > $dst\$dir\Files\WebShell\one1.aspx.txt
findstr /S /snip /c:"/log.aspx" "$src\*.log" > $dst\$dir\Files\WebShell\log.aspx.txt
findstr /S /snip /c:"/logg.aspx" "$src\*.log" > $dst\$dir\Files\WebShell\logg.aspx.txt
findstr /S /snip /c:"/bob.aspx" "$src\*.log" > $dst\$dir\Files\WebShell\bob.aspx.txt
findstr /S /snip /c:"/OutlookZH.aspx" "$src\*.log" > $dst\$dir\Files\WebShell\OutlookZH.aspx.txt
findstr /S /snip /c:"/w7tAhF9i1pJnRo.aspx" "$src\*.log" > $dst\$dir\Files\WebShell\w7tAhF9i1pJnRo.aspx.txt
findstr /S /snip /c:"/authhead.aspx" "$src\*.log" > $dst\$dir\Files\WebShell\authhead.aspx.txt
findstr /S /snip /c:"/fatal-erro.aspx" "$src\*.log" > $dst\$dir\Files\WebShell\fatal-erro.aspx.txt
findstr /S /snip /c:"/errorPage.aspx" "$src\*.log" > $dst\$dir\Files\WebShell\errorPage.aspx.txt
findstr /S /snip /c:"/errorPages.aspx" "$src\*.log" > $dst\$dir\Files\WebShell\errorPages.aspx.txt
findstr /S /snip /c:"/aspnet_client.aspx" "$src\*.log" > $dst\$dir\Files\WebShell\aspnet_client.aspx.txt
findstr /S /snip /c:"/aspnet_iisstart.aspx" "$src\*.log" > $dst\$dir\Files\WebShell\aspnet_iisstart.aspx.txt
findstr /S /snip /c:"/aspnet_pages.aspx" "$src\*.log" > $dst\$dir\Files\WebShell\aspnet_pages.aspx.txt
findstr /S /snip /c:"/aspnet_www.aspx" "$src\*.log" > $dst\$dir\Files\WebShell\aspnet_www.aspx.txt

# HTTP POST
Write-Host "`nHunting for potential malicious HTTP POST requests (themes file path only)..." -ForegroundColor yellow -BackgroundColor black
New-Item $dst\$dir\Files\Strings -ItemType Directory | Out-Null
findstr /S /snip /c:"POST /owa/auth/Current/themes/resources" "$src\*.log" > $dst\$dir\Files\Strings\owa_auth_current_themes_resources.txt

# IP Addresses
Write-Host "`nHunting for malicious C2 IP Addresses..." -ForegroundColor yellow -BackgroundColor black
Write-Host "Please Note: This may take some time, please be patient."
New-Item $dst\$dir\IPAddress -ItemType Directory | Out-Null
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