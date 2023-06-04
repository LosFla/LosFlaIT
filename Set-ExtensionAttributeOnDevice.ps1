# define variables
$ExtensionAttributeName = 'extensionAttribute1' # choose from extensionAttribute1 - extensionAttribute15
$ExtensionAttributeValue = 'Test123'
$DeviceId = ''

# import modules
try{
    Import-Module Microsoft.Graph.Identity.DirectoryManagement -ErrorAction Stop
}
catch{
    "Error was $_"
    $line = $_.InvocationInfo.ScriptLineNumber
    "Error was in Line $line"
}

# connect to GraphApi
# access rights to connect
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
    $AzureADJoinedDevice = Get-MgDevice -DeviceId $DeviceId
}
catch{
    "Error was $_"
    $line = $_.InvocationInfo.ScriptLineNumber
    "Error was in Line $line"
}

# create json
$uri = $null
$uri = "https://graph.microsoft.com/beta/devices/" + $AzureADJoinedDevice.id

$json = @{
    "extensionAttributes" = @{
    $ExtensionAttributeName = $ExtensionAttributeValue
        }
} | ConvertTo-Json

# invoke Graph API request
try{
    Invoke-MgGraphRequest -Uri $uri -Body $json -Method PATCH -ContentType "application/json"
}
catch{
    "Error was $_"
    $line = $_.InvocationInfo.ScriptLineNumber
    "Error was in Line $line"
}
