#requires -version 4
<#
.SYNOPSIS
  Script to remove an entry from an ExtensionAttribute on a Device in Azure AD
.DESCRIPTION
  This Script removes the entry in the defined extensionAttribute on a Device Object in Azure AD.
  It is a console script, which means that you have to run it from a powershell console to see the output.
.PARAMETER 
    none
.INPUTS
    DeviceId from AzureAd
    This Parameter will be queried in the console
.OUTPUTS
  yes/no
  Output will be shown in the console.
.NOTES
  Version:        1.0
  Author:         LosFla (http://www.losfla.com/)
  Creation Date:  2023/06/05
  Purpose/Change: Initial script development
  
.EXAMPLE
  .\Clear-ExtensionAttributeOnAadDevice.ps1
#>

#region variables
$ExtensionAttributeName = 'ExtensionAttribute1' # Name of the ExtensionAttribute you want to clear

#endregion


function Set-AadDeviceExtensionAttribute
{
    [CmdletBinding()]
    param(
        [Parameter(Position=2,mandatory=$true)]
        $AzureAdDevice,
        [Parameter(Position=0,mandatory=$true)]
        [string] $ExtensionAttributeName,
        [Parameter(Position=1,mandatory=$false)]
        $ExtensionAttributeValue = $null
        
    )

    # write ExtensionAttribute to Azure AD
    $uri = $null
    $uri = "https://graph.microsoft.com/beta/devices/$($AzureAdDevice.id)"

    $json = @{
        "extensionAttributes" = @{
            $($ExtensionAttributeName) = $ExtensionAttributeValue
        }
    } | ConvertTo-Json

    try{
        Invoke-MgGraphRequest -Uri $uri -Body $json -Method PATCH -ContentType "application/json"
        
    }
    catch{
        throw $_
    }
}

#check user input
$RegexObjectId = "[A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]+-[A-Za-z0-9]"

# DeviceId
$DeviceId = Read-Host "Please enter the objectId of the device you want to clear (You can retrieve it from AzureAd)"

if(!($DeviceId -match $RegexObjectId)){
    
    Write-Host "input doesn't match the expected ObjectId format" -ForegroundColor Red
    Write-Host "Hint: please enter the ObjectId in the following format:" -ForegroundColor Yellow
    Write-Host "  e.g.: 1958d935-8ace-4a96-b7f1-4886ef9a3f54" -ForegroundColor Yellow

    # Press any key to continue...
    Write-Host 'Press any key to continue...'
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')

    exit 1
}

try{
    Import-Module Microsoft.Graph.Identity.DirectoryManagement -ErrorAction Stop
}
catch{
    "Error was $_"
    $line = $_.InvocationInfo.ScriptLineNumber
    "Error was in Line $line"
}

# connect to GraphApi
try{
    Connect-mgGraph -Scopes Device.Read.All, Directory.ReadWrite.All, Directory.AccessAsUser.All -ErrorAction Stop
}
catch{
    "Error was $_"
    $line = $_.InvocationInfo.ScriptLineNumber
    "Error was in Line $line"
}

# get the device obj
try{
    $AzureAdDevice = Get-MgDevice -DeviceId $DeviceId
}
catch{
    "Error was $_"
    $line = $_.InvocationInfo.ScriptLineNumber
    "Error was in Line $line"
    exit 1
}

$uri = $null
$uri = "https://graph.microsoft.com/beta/devices/" + $AzureAdDevice.id

try{
    $DeviceObj = $null
    $DeviceObj = Invoke-MgGraphRequest -Uri $uri -Method GET
}
catch{
    Write-Error "Error was $_"
    $line = $_.InvocationInfo.ScriptLineNumber
    Write-Error "Error was in Line $line"
}

if($DeviceObj -eq $null){
    Write-Error "no device object found with id: $($AzureAdDevice.id)"
    exit 2
}

# remove ExtensionAttribute from AzureAd device object

try{
    Set-AadDeviceExtensionAttribute -AzureAdDevice $DeviceObj `
                                    -ExtensionAttributeName $ExtensionAttributeName `
                                    -ErrorAction Stop
    Write-Host "Successfully cleared the value of the ExtensionAttribute $($ExtensionAttributeName) on the Device oject in Azure AD" -ForegroundColor Green
}
catch{
    Write-Error "Error was $_"
    $line = $_.InvocationInfo.ScriptLineNumber
    Write-Error "Error was in Line $line"
}
