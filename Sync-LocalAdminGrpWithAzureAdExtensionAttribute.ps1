<#
    .SYNOPSIS
    Sync-LocalAdminGrpWithAzureAdExtensionAttribute

    .DESCRIPTION
    Syncs the local admin group with the Users provided in the AzureAD Device ExtensionAttribute 

    .PARAMETER Name
    -

    .INPUTS
    None.

    .OUTPUTS
    Logfile

    .Changelog
    Created: LosFlaIT (https://losfla.com/)

    27.04.2023 - LosFla - Ver. 1.0: Initial Version

#>


#region parameters

$ScriptName = 'Sync-LocalAdminGrpWithAzureAdExtensionAttribute'
$ScriptVer = '1.0'

$exceptionList = @("S-1-5-21-..." # WinNT://WORKGROUP/$($env:COMPUTERNAME)/Administrator
                    # add the SIDs of the accounts in the local admin group you want to exclude during filtering
                  )


# Populate with the App Registration details and Tenant ID
$appid = ''
$tenantid = ''
$secret = ''

$AzureADextensionAttribute = 'extensionAttribute1'

#endregion


#region functions
function Write-Log
{
    param
    (
      [Parameter(ValueFromPipeline)]
      [string]$Inhalt
      
    )

    $LogFile = "$env:SystemDrive\Logs\$ScriptName.log"
    $MaxFileSize = 3145728 # Maximum size of log file in bytes (3 MB)
    $DateNow = Get-Date -Format 'yyyyMMdd' # current date
    $LogFileName = "$ScriptName_$DateNow.log" # new log file name
    $LogFilePath = "$env:SystemDrive\Logs\$LogFileName" # path to new log file
    
    # Check if log file exists and its size
    if (Test-Path -Path $LogFile) {
        $FileSize = (Get-Item -Path $LogFile).Length
        if ($FileSize -ge $MaxFileSize) {
            # Rename current log file to new log file name
            Rename-Item -Path $LogFile -NewName $LogFileName
            
            # Create a new log file
            New-Item -Path $LogFile -ItemType File
        }
    } else {
        # Create a new log file
        New-Item -Path $LogFile -ItemType File
    }
    
    # Join string for logfile
    $FileInp = "$(Get-Date -Format 'dd.MM.yyyy HH:mm:ss') | $Inhalt"
    
    # Append content to logfile
    Add-Content -Path $LogFile -Value $FileInp
}

function Convert-AzureAdObjectIdToSid {
<#
.SYNOPSIS
Convert an Azure AD Object ID to SID
 
.DESCRIPTION
Converts an Azure AD Object ID to a SID.
Author: Oliver Kieselbach (oliverkieselbach.com)
The script is provided "AS IS" with no warranties.
 
.PARAMETER ObjectID
The Object ID to convert
#>

    param([String] $ObjectId)

    $bytes = [Guid]::Parse($ObjectId).ToByteArray()
    $array = New-Object 'UInt32[]' 4

    [Buffer]::BlockCopy($bytes, 0, $array, 0, 16)
    $sid = "S-1-12-1-$array".Replace(' ', '-')

    return $sid
}

function Convert-AzureAdSidToObjectId {
<#
.SYNOPSIS
Convert a Azure AD SID to Object ID
 
.DESCRIPTION
Converts an Azure AD SID to Object ID.
Author: Oliver Kieselbach (oliverkieselbach.com)
The script is provided "AS IS" with no warranties.
 
.PARAMETER ObjectID
The SID to convert
#>

    param([String] $Sid)

    $text = $sid.Replace('S-1-12-1-', '')
    $array = [UInt32[]]$text.Split('-')

    $bytes = New-Object 'Byte[]' 16
    [Buffer]::BlockCopy($array, 0, $bytes, 0, 16)
    [Guid]$guid = $bytes

    return $guid
}

function Get-LocalAdminsWithSID {

    $groupName = (Get-LocalGroup -SID 'S-1-5-32-544').Name

    $group = [ADSI]"WinNT://./$groupName,group"
    $members = $group.Invoke("Members") | foreach {
        $member = $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)
        $sidBytes = $_.GetType().InvokeMember("ObjectSID", 'GetProperty', $null, $_, $null)
        $sid = [System.Security.Principal.SecurityIdentifier]::new($sidBytes, 0).Value
        New-Object PSObject -Property @{
            Member = $member
            SID = $sid
        }
    }

    $members
}

function Get-SerialNumber {
    (Get-CimInstance Win32_BIOS).SerialNumber
}


function Get-AzureADDeviceIdFromSN {
    
    $pageUrl = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$filter=serialNumber eq '$(Get-SerialNumber)'"

    # Retrieve first page of devices
    $devices = Invoke-MgGraphRequest -uri $pageUrl

    if ($devices.value.Count -gt 1 -or $devices.value.Count -eq 0){
        throw "Error while retrieving IntuneDeviceId"
    }

    $devices.value.azureADDeviceId
}


function Get-AzureADDeviceFromMDMDeviceId {
    param(
        [Parameter(mandatory=$true)]
        $deviceId 
    )
    
    $pageUrl = "https://graph.microsoft.com/v1.0/devices?`$filter=deviceId eq '$deviceId'" #deviceManagement/managedDevices?`$filter=serialNumber eq '$(Get-SerialNumber)'

    # Retrieve first page of devices
    $devices = Invoke-MgGraphRequest -uri $pageUrl

    if ($devices.value.Count -gt 1 -or $devices.value.Count -eq 0){
        throw "Error while retrieving IntuneDeviceId"
    }

    $devices.value | ForEach-Object {[pscustomobject]$_}
}

#endregion


#region main
"##### script start #####" | Write-Log
"current user: $env:USERNAME" | Write-Log
"script version: $ScriptVer" | Write-Log


#check/import required modules
if (((Get-Module -ListAvailable).Name) -notmatch 'Microsoft.Graph.Identity.DirectoryManagement'){
    try{
        Install-Module Microsoft.Graph.Identity.DirectoryManagement -ErrorAction Stop -Force
        Write-Output "successfully installed Microsoft.Graph module" | Write-Log
    }
    catch {
        "Error was $_" | Write-Log
        $line = $_.InvocationInfo.ScriptLineNumber
        "Error was in Line $line" | Write-Log
    }
}

try{
    Import-Module 'Microsoft.Graph.Identity.DirectoryManagement' -Force -ErrorAction Stop
}
catch{
    "Error was $_" | Write-Log
    $line = $_.InvocationInfo.ScriptLineNumber
    "Error was in Line $line" | Write-Log
}

$body =  @{
    Grant_Type    = "client_credentials"
    Scope         = 'https://graph.microsoft.com/.default'
    Client_Id     = $appid
    Client_Secret = $secret
}

try{
    $connection = Invoke-RestMethod `
        -Uri "https://login.microsoftonline.com/$tenantid/oauth2/v2.0/token" `
        -Method POST `
        -Body $body -ErrorAction Stop
    Write-Output "succesfully triggered invoke rest method" | Write-Log
}
catch
{
        "Error was $_" | Write-Log
        $line = $_.InvocationInfo.ScriptLineNumber
        "Error was in Line $line" | Write-Log
}

$token = $connection.access_token


#connect to Microsoft Graph
try{
    Connect-MgGraph -AccessToken $token -ErrorAction Stop
    Write-Output "successfully connected to Microsft Graph" | Write-Log
}
catch
{
        "Error was $_" | Write-Log
        $line = $_.InvocationInfo.ScriptLineNumber
        "Error was in Line $line" | Write-Log
}


#get device with extension Attribute via Microsoft Graph
try{
    $deviceId = Get-AzureADDeviceIdFromSN
    $AzureCompObj = Get-AzureADDeviceFromMDMDeviceId -deviceId $deviceId -ErrorAction Stop
}
catch
{
        "Error was $_" | Write-Log
        $line = $_.InvocationInfo.ScriptLineNumber
        "Error was in Line $line" | Write-Log
}


$LocalAdminsFromAzAd = $AzureCompObj.extensionAttributes."$($AzureADextensionAttribute)"

# compare LocalAdminsFromAzAd with LocalAdminsFromLocalGrp and maintain localAdmGrp

# get local Administrators from local group
$localAdmins = Get-LocalAdminsWithSID

#merge exceptionList and admins from extensionAttribute (AAD)
$shouldBeAdmins = $exceptionList + $LocalAdminsFromAzAd

#check if user in extension attribute is existing
#convert UserID from Azure extension attribute to SID
$MailRegex = "[a-z0-9!#\$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#\$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"

try{
    $shouldBeAdmins = $shouldBeAdmins | ForEach-Object {    
                                                            if($_ -match $MailRegex) { 
                                                                $uri = "https://graph.microsoft.com/v1.0/users/$_"
                                                                $GraphUser = Invoke-MgGraphRequest -uri $uri
                                                                $convertedSID = Convert-AzureAdObjectIdToSid -ObjectId $GraphUser.id 
                                                                "$convertedSID"
                                                            } 
                                                            else { $_ } 
                                                       }
}
catch{
    "Error was $_" | Write-Log
    $line = $_.InvocationInfo.ScriptLineNumber
    "Error was in Line $line" | Write-Log
    exit 1
}


#remove local admins that are not assigned to the device in azure (extensionAttribute) or on exception list
foreach($item in $localAdmins.SID){
    
    if(($item -notin $shouldBeAdmins)){
        
        try{
            "trying to remove group member $item from local admin group..." | Write-Log
            Remove-LocalGroupMember -SID 'S-1-5-32-544' -Member $item -ErrorAction Stop
            "successfully removed $item from local admin group" | Write-Log
        }
        catch{
            "Error was $_" | Write-Log
            $line = $_.InvocationInfo.ScriptLineNumber
            "Error was in Line $line" | Write-Log
        }
    }
}


#add local admins that are not assigned to the device yet
foreach($item in $shouldBeAdmins){
    
    if($item -notin $localAdmins.SID -and $item -ne $null){

        try{
            #add SID to local admin group
            "trying to add group member $item to local admin group..." | Write-Log
            Add-LocalGroupMember -SID 'S-1-5-32-544' -Member $item -ErrorAction Stop
            "successfully added $item to local admin group" | Write-Log
        }
        catch{
            "Error was $_" | Write-Log
            $line = $_.InvocationInfo.ScriptLineNumber
            "Error was in Line $line" | Write-Log
        }
    }
}


"##### script end #####" | Write-Log
#endregion
