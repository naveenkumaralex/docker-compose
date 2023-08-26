<#
DESCRIPTION   This script will create a configured Remote Desktop Session Farm.
Author:         Julian Mooren | https://citrixguyblog.com
Contributer:    Sander van Gelderen | https://www.van-gelderen.eu
Creation Date:  12.05.17 
Change Date:    09.02.18
#>
 

#Requires -version 4.0
#Requires -RunAsAdministrator

#Functions
#http://www.leeholmes.com/blog/2009/11/20/testing-for-powershell-remoting-test-psremoting/
function Test-PsRemoting {
    param(
        [Parameter(Mandatory = $true)]
        $computername
    )
   
    try
    {
        $errorActionPreference = "Stop"
        $result = Invoke-Command -ComputerName $computername { 1 }
    }
    catch
    {
        Write-Verbose $_
        return $false
    }
   
    ## I've never seen this happen, but if you want to be
    ## thorough....
    if($result -ne 1)
    {
        Write-Verbose "Remoting to $computerName returned an unexpected result."
        return $false
    }
   
    $true   
} # end Test-PsRemoting


# Thanks @xenappblog.com for the Transcript Log idea
$configpath= "C:\rds\configT.json"
$StartDate = (Get-Date) 
$Vendor = "Microsoft"
$Product = "Remote Desktop Farm"
$Version = "2022"
$LogPath = "${env:SystemRoot}" + "\Temp\$Vendor $Product $Version.log"

Start-Transcript $LogPath

#region "Check Prerequisites"
Write-Verbose "Check Prerequisites" -Verbose

if (Get-WindowsFeature -Name RSAT-AD-Tools, RSAT-DNS-Server){
   Write-Verbose "Needed PowerShell Modules available." -Verbose
} else {    
    Write-Verbose "Needed PowerShell Modules will be installed." -Verbose
    Install-WindowsFeature RSAT-AD-Tools, RSAT-DNS-Server
    Write-Verbose "Needed PowerShell Modules have been installed." -Verbose
} #end if Get-WindowsFeature

if (Test-Path $configpath) {
    Write-Verbose "JSON File was found." -Verbose
    $config = Get-Content -Path $configpath -Raw | ConvertFrom-Json
    Write-Verbose "JSON File was imported." -Verbose
} Else {
    Write-Warning "Failed to find the JSON File."
    break
} #end if Test-Path $configpath

if (Test-Path $config.CertPath) {
    Write-Verbose "SSL Certificate was found." -Verbose
} Else {
    Write-Warning "Failed to find the SSL Certificate."
    break
} # end if Test-Path $config.CertPath

Import-Module Activedirectory
$NameRDSAccessGroup = $config.RDSAccessGroup.split('@')[0]
$NameRDSAccessGroup2 = $config.RDSAccessGroup2.split('@')[0]
$NameRDSAccessGroup3 = $config.RDSAccessGroup3.split('@')[0]
$NameGatewayAccessGroup = $config.GatewayAccessGroup.split('@')[0]
New-ADGroup -Name $NameRDSAccessGroup -DisplayName $NameRDSAccessGroup -GroupCategory Security -GroupScope Global
New-ADGroup -Name $NameRDSAccessGroup2 -DisplayName $NameRDSAccessGroup2 -GroupCategory Security -GroupScope Global
New-ADGroup -Name $NameRDSAccessGroup3 -DisplayName $NameRDSAccessGroup3 -GroupCategory Security -GroupScope Global
New-ADGroup -Name $NameGatewayAccessGroup -DisplayName $NameGatewayAccessGroup -GroupCategory Security -GroupScope Global

#endregion "Check Prerequisites"

#region TEST
if($config.MultiDeployment -like "Yes"){

    if(Test-PsRemoting -computername $config.RDSHost01, $config.RDSHost02, $config.RDSHost03, $config.ConnectionBroker01, $config.WebAccessServer01, $config.RDGatewayServer01){
        Write-Verbose "PSRemoting is enabled on all Hosts. MultiDeployment GO GO GO!" -Verbose
    } Else {
        Write-Warning "PSRemoting is not enabled on all Hosts. MultiDeployment is not ready!" 
        $PSRemoteMulti = @("$($config.RDSHost01)","$($config.RDSHost02)","$($config.RDSHost03)","$($config.ConnectionBroker01)","$($config.WebAccessServer01)","$($config.RDGatewayServer01)")
        foreach($TestMulti in $PSRemoteMulti){
            $status = Test-PsRemoting -computername $TestMulti; "$TestMulti;$status"
        }
        Stop-Transcript
        break
    } #end Test-PsRemoting MultiDeployment

    
    #enable SMB
    #Invoke-Command -ComputerName $config.ConnectionBroker01 {
    #    Get-NetFirewallRule -DisplayName "File and Printer Sharing (SMB-In)" | Enable-NetFirewallRule
    #}
    #if(Test-Path "\\$($config.ConnectionBroker01)\c$"){Write-Verbose "UNC path reachable"} else { Write-Warning "$($config.ConnectionBroker01) might have troubles"; break}
    

}


# Import the RemoteDesktop Module
Import-Module RemoteDesktop

##### MultiDeployment Configuration Parameters ##### 

if($config.MultiDeployment -like "Yes"){

    # Create RDS deployment
    New-RDSessionDeployment -ConnectionBroker $config.ConnectionBroker01 -WebAccessServer $config.WebAccessServer01 -SessionHost @($config.RDSHost01, $config.RDSHost02, $config.RDSHost03)
    Write-Verbose "Created new RDS deployment" -Verbose  

    # Create Desktop Collection RDSH01
    New-RDSessionCollection  -CollectionName $config.DesktopCollectionName -SessionHost @($config.RDSHost01)  -CollectionDescription $config.DesktopDiscription  -ConnectionBroker $config.ConnectionBroker01 
    Write-Verbose "Created new Desktop Collection"  -Verbose

    # Create Desktop Collection RDSH02
    New-RDSessionCollection  -CollectionName $config.DesktopCollectionName2 -SessionHost @($config.RDSHost02)  -CollectionDescription $config.DesktopDiscription  -ConnectionBroker $config.ConnectionBroker01 
    Write-Verbose "Created new Desktop Collection"  -Verbose
    
    # Create Desktop Collection RDSH03
    New-RDSessionCollection  -CollectionName $config.DesktopCollectionName3 -SessionHost @($config.RDSHost03)  -CollectionDescription $config.DesktopDiscription  -ConnectionBroker $config.ConnectionBroker01 
    Write-Verbose "Created new Desktop Collection"  -Verbose

    #Install Gateway
    Add-WindowsFeature -Name RDS-Gateway -IncludeManagementTools -ComputerName $config.RDGatewayServer01
    Write-Verbose "Installed RDS Gateway"  -Verbose

    #Join Gateway to Broker
    Add-RDServer -Server $config.RDGatewayServer01 -Role "RDS-GATEWAY" -ConnectionBroker $config.ConnectionBroker01 -GatewayExternalFqdn $config.GatewayExternalFqdn
    Write-Verbose "Joined RDS Gateway to Broker"  -Verbose

    # Configure GW Policies on RDGatewayServer01
    # https://stackoverflow.com/questions/61725242/rds-gateway-update-resource-authorization-policies-with-powershell
    # Configure GW Policies on RDGatewayServer01
    Invoke-Command -ComputerName $config.RDGatewayServer01 -ArgumentList $config.GatewayAccessGroup, $config.RDBrokerDNSInternalName, $config.RDBrokerDNSInternalZone, $config.RDSHost01, $config.RDSHost02, $config.RDSHost03 -ScriptBlock {
        $GatewayAccessGroup = $args[0]
        $RDBrokerDNSInternalName = $args[1]
        $RDBrokerDNSInternalZone = $args[2]
        $RDSHost01 = $args[3]
        $RDSHost02 = $args[4]
        $RDSHost03 = $args[5]
        $GroupsName = "RDGW1"
        Import-Module RemoteDesktopServices
        Remove-Item -Path "RDS:\GatewayServer\CAP\RDG_CAP_AllUsers" -Force -recurse
        Remove-Item -Path "RDS:\GatewayServer\RAP\RDG_RDConnectionBrokers" -Force -recurse
        Remove-Item -Path "RDS:\GatewayServer\RAP\RDG_AllDomainComputers" -Force -recurse
        Remove-Item  -Path "RDS:\GatewayServer\GatewayManagedComputerGroups\RDG_RDCBComputers" -Force -recurse
        New-Item -Path "RDS:\GatewayServer\GatewayManagedComputerGroups" -Name "$GroupsName" -Description "$GroupsName" -Computers "$RDBrokerDNSInternalName.$RDBrokerDNSInternalZone" -ItemType "String"
        New-Item -Path "RDS:\GatewayServer\GatewayManagedComputerGroups\$GroupsName\Computers" -Name $RDSHost01 -ItemType "String"
        New-Item -Path "RDS:\GatewayServer\GatewayManagedComputerGroups\$GroupsName\Computers" -Name $RDSHost02 -ItemType "String"
        New-Item -Path "RDS:\GatewayServer\GatewayManagedComputerGroups\$GroupsName\Computers" -Name $RDSHost03 -ItemType "String"
        New-Item -Path "RDS:\GatewayServer\RAP" -Name "RDG_RAP_$GroupsName" -UserGroups $GatewayAccessGroup -ComputerGroupType 0 -ComputerGroup "$GroupsName"
        New-Item -Path "RDS:\GatewayServer\CAP" -Name "RDG_CAP_$GroupsName" -UserGroups $GatewayAccessGroup -AuthMethod 1
    }
    Write-Verbose "Configured CAP & RAP Policies on: $($config.RDGatewayServer01)"  -Verbose

    read-host "Configuring CAP & RAP on $($config.RDGatewayServer01) error? Re-run this part of the script before continue"

    # Create WebAccess DNS-Record
    Import-Module DNSServer
    $IPWebAccess01 = [System.Net.Dns]::GetHostAddresses("$($config.WebAccessServer01)")[0].IPAddressToString
    Add-DnsServerResourceRecordA -ComputerName $config.DomainController -Name $config.RDWebAccessDNSInternalName -ZoneName $config.RDWebAccessDNSInternalZone -AllowUpdateAny -IPv4Address $IPWebAccess01
    Write-Verbose "Configured WebAccess DNS-Record"  -Verbose

    # Redirect to RDWeb (IIS)
    Invoke-Command -ComputerName $config.WebAccessServer01 -ArgumentList $config.RDWebAccessDNSInternalName, $config.RDWebAccessDNSInternalZone  -ScriptBlock {
        $RDWebAccessDNSInternalName = $args[0]
        $RDWebAccessDNSInternalZone = $args[1]
        $siteName = "Default Web Site"
        Import-Module webAdministration
        Set-WebConfiguration system.webServer/httpRedirect "IIS:\sites\$siteName" -Value @{enabled="true";destination="https://$RDWebAccessDNSInternalName.$RDWebAccessDNSInternalZone/RDWeb";exactDestination="true";httpResponseStatus="Found"} 
    } #end Redirect to RDWeb
    Write-Verbose "Configured RDWeb Redirect"  -Verbose

} #end if $config.MultiDeployment

#region Default Configuration Parameters
##### Default Configuration Parameters ##### 

# Set Access Group for RDS Farm
Set-RDSessionCollectionConfiguration -CollectionName $config.DesktopCollectionName -UserGroup $config.RDSAccessGroup -ConnectionBroker $config.ConnectionBroker01
Write-Verbose "Configured Access for $($config.RDSAccessGroup)"  -Verbose

# Set Access Group for RDS02 Farm
Set-RDSessionCollectionConfiguration -CollectionName $config.DesktopCollectionName2 -UserGroup $config.RDSAccessGroup2 -ConnectionBroker $config.ConnectionBroker01
Write-Verbose "Configured Access for $($config.RDSAccessGroup2)"  -Verbose

# Set Access Group for RDS03 Farm
Set-RDSessionCollectionConfiguration -CollectionName $config.DesktopCollectionName3 -UserGroup $config.RDSAccessGroup3 -ConnectionBroker $config.ConnectionBroker01
Write-Verbose "Configured Access for $($config.RDSAccessGroup3)"  -Verbose

# Set Profile Disk 
Set-RDSessionCollectionConfiguration -CollectionName $config.DesktopCollectionName -EnableUserProfileDisk -MaxUserProfileDiskSizeGB "20" -DiskPath $config.ProfileDiskPath -ConnectionBroker $config.ConnectionBroker01
Write-Verbose "Configured ProfileDisk"  -Verbose

# Set Profile Disk RDSH02
Set-RDSessionCollectionConfiguration -CollectionName $config.DesktopCollectionName2 -EnableUserProfileDisk -MaxUserProfileDiskSizeGB "20" -DiskPath $config.ProfileDiskPath2 -ConnectionBroker $config.ConnectionBroker01
Write-Verbose "Configured ProfileDisk"  -Verbose

# Set Profile Disk RDSH03
Set-RDSessionCollectionConfiguration -CollectionName $config.DesktopCollectionName3 -EnableUserProfileDisk -MaxUserProfileDiskSizeGB "20" -DiskPath $config.ProfileDiskPath3 -ConnectionBroker $config.ConnectionBroker01
Write-Verbose "Configured ProfileDisk"  -Verbose

# RDS Licencing
Add-RDServer -Server $config.LICserver -Role "RDS-LICENSING" -ConnectionBroker $config.ConnectionBroker01
Write-Verbose "Installed RDS Licence Server: $($config.LICserver)"  -Verbose
Set-RDLicenseConfiguration -LicenseServer $config.LICserver -Mode $config.LICmode -ConnectionBroker $config.ConnectionBroker01 -Force
Write-Verbose "Configured RDS Licening"  -Verbose

# Set Certificates
$Password = ConvertTo-SecureString -String $config.CertPassword -AsPlainText -Force 
Set-RDCertificate -Role RDPublishing -ImportPath $config.CertPath  -Password $Password -ConnectionBroker $config.ConnectionBroker01 -Force
Set-RDCertificate -Role RDRedirector -ImportPath $config.CertPath -Password $Password -ConnectionBroker $config.ConnectionBroker01 -Force
Set-RDCertificate -Role RDWebAccess -ImportPath $config.CertPath -Password $Password -ConnectionBroker $config.ConnectionBroker01 -Force
Set-RDCertificate -Role RDGateway -ImportPath $config.CertPath  -Password $Password -ConnectionBroker $config.ConnectionBroker01 -Force
Write-Verbose "Configured SSL Certificates"  -Verbose

# Configure WebAccess (when RDBroker is available, no Gateway will be used)
Set-RDDeploymentGatewayConfiguration -GatewayMode Custom -GatewayExternalFqdn $config.GatewayExternalFqdn -LogonMethod Password -UseCachedCredentials $True -BypassLocal $True -ConnectionBroker $config.ConnectionBroker01 -Force
Write-Verbose "Configured Gateway Mapping"  -Verbose

# Create TXT WebFeed DNS Record - Create RemoteAccess connection via e-Mail address
Add-DnsServerResourceRecord -ZoneName $config.RDWebAccessDNSInternalZone -Name "_msradc" -Txt -DescriptiveText "https://$($config.RDWebAccessDNSInternalName).$($config.RDWebAccessDNSInternalZone)/RDWeb/Feed"
Write-Verbose "Created TXT WebFeed DNS Record"  -Verbose

# Create RDS Broker DNS-Record
Import-Module DNSServer
$IPBroker01 = [System.Net.Dns]::GetHostAddresses("$($config.ConnectionBroker01)")[0].IPAddressToString
Add-DnsServerResourceRecordA -ComputerName $config.DomainController  -Name $config.RDBrokerDNSInternalName -ZoneName $config.RDBrokerDNSInternalZone -AllowUpdateAny -IPv4Address $IPBroker01
Write-Verbose "Configured RDSBroker DNS-Record"  -Verbose

#Change RDPublishedName
#https://gallery.technet.microsoft.com/Change-published-FQDN-for-2a029b80
Invoke-WebRequest -Uri "https://gallery.technet.microsoft.com/Change-published-FQDN-for-2a029b80/file/103829/2/Set-RDPublishedName.ps1" -OutFile "c:\rds\Set-RDPublishedName.ps1"
#Invoke-WebRequest -Uri "https://github.com/dwj7738/My-Powershell-Repository/blob/master/Scripts/Set-RDPublishedName.ps1" -OutFile "c:\rds\Set-RDPublishedName.ps1"

Copy-Item "c:\rds\Set-RDPublishedName.ps1" -Destination "\\$($config.ConnectionBroker01)\c$"
Invoke-Command -ComputerName $config.ConnectionBroker01 -ArgumentList $config.RDBrokerDNSInternalName, $config.RDBrokerDNSInternalZone -ScriptBlock {
    $RDBrokerDNSInternalName = $args[0]
    $RDBrokerDNSInternalZone = $args[1]
    Set-Location C:\
    .\Set-RDPublishedName.ps1 -ClientAccessName "$RDBrokerDNSInternalName.$RDBrokerDNSInternalZone"
    Remove-Item "C:\Set-RDPublishedName.ps1"
}
Write-Verbose "Configured RDPublisher Name"  -Verbose
#endregion Default Configuration Parameters


Write-Verbose "Stop logging" -Verbose
$EndDate = (Get-Date)
Write-Verbose "Elapsed Time: $(($EndDate-$StartDate).TotalSeconds) Seconds" -Verbose
Write-Verbose "Elapsed Time: $(($EndDate-$StartDate).TotalMinutes) Minutes" -Verbose