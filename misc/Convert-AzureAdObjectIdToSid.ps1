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

$objectId = "8227700f-e02b-4eb4-8e9f-52e1f33515ef"
$sid = Convert-AzureAdObjectIdToSid -ObjectId $objectId
Write-Output $sid

# Output:

# S-1-12-1-1943430372-1249052806-2496021943-3034400218