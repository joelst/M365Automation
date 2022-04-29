<#
New-DesktopShortcutCleanup.ps1

Proactive remediation for cleaning up duplicate Edge and Teams shortcuts on the desktop

Adapted from https://workplaceascode.com/2020/11/10/3-incredible-proactive-remediation-scripts/?msclkid=0258573dc75711ec966399840296c0d2


#>

# is this running as detect or remediate?
$mode = $MyInvocation.MyCommand.Name.Split(".")[0]

if ($mode -eq "detect") {

    $OneDrive = @()

    # Define Variables
    $Lang = (Get-WinSystemLocale).LCID

    if ($Lang -ne "1034") {
        #United States (EN-US)
        $PP = "$env:SystemDrive\Users\"
        $PPU = (Get-ChildItem -Path $PP | Where-Object { ($_.Name -notlike "default*") } | Where-Object { ($_.Name -ne "public") }).FullName
        foreach ($OneDrive in $PPU) {
            # Find $OneDrive
            $OneDriveLocations = (Get-ChildItem -Path $PPU -Filter "OneDrive*" -ErrorAction SilentlyContinue).FullName
        }
    }
    elseif ($Lang -eq "1034") {
        #Dutch (NL-NL)
        $PP = "$env:SystemDrive\Gebruikers\"
        $PPU = (Get-ChildItem -Path $PP | Where-Object { ($_.Name -notlike "default*") } | Where-Object { ($_.Name -ne "publiek") }).FullName
        foreach ($OneDrive in $PPU) {
            #Find $OneDrive
            $OneDriveLocations = (Get-ChildItem -Path $PPU -Filter "OneDrive*" -ErrorAction SilentlyContinue).FullName
        }
    
    }
    try {
        foreach ($OneDriveLocation in $OneDriveLocations) {
            $Icons = @()
            $AllEdgeIcons = New-Object PSobject
            $AllTeamsIcons = New-Object PSobject
            $EdgeIcons = (Get-ChildItem -Path $OneDriveLocation -Filter "Microsoft Edge*.lnk" -Recurse -ErrorAction SilentlyContinue)
            $TeamsIcons = (Get-ChildItem -Path $OneDriveLocation -Filter "Microsoft Teams*.lnk" -Recurse -ErrorAction SilentlyContinue)
 
            $AllEdgeIcons | Add-Member -MemberType NoteProperty -Name "Fullname" -Value $EdgeIcons.fullname
            $AllTeamsIcons | Add-Member -MemberType NoteProperty -Name "Fullname" -Value $TeamsIcons.fullname

            $icons += $EdgeIcons
            $icons += $TeamsIcons
        }
    

        if (($icons.count -gt "0")) {
            #Start remediation
            Write-Host "Start remediation"
            exit 1
        }
        else {
            #No remediation required    
            Write-Host "No remediation"
            exit 0
        }   
    }
    catch {
        $errMsg = $_.Exception.Message
        Write-Error $errMsg
        exit 1
    }
}
else {
    $OneDrive = @()
    $Cleandedicons = "unkown"

    # Define Variables
    $Lang = (Get-WinSystemLocale).LCID

    if ($Lang -ne "1034") {
        #United States (EN-US)
        $PP = "$env:SystemDrive\Users\"
        $PPU = (Get-ChildItem -Path $PP | Where-Object { ($_.Name -notlike "default*") } | Where-Object { ($_.Name -ne "public") }).FullName
        foreach ($OneDrive in $PPU) {
            #Find $OneDrive
            $OneDriveLocations = (Get-ChildItem -Path $PPU -Filter "OneDrive*" -ErrorAction SilentlyContinue).FullName
        }
    }
    elseif ($Lang -eq "1034") {
        #Dutch (NL-NL)
        $PP = "$env:SystemDrive\Gebruikers\"
        $PPU = (Get-ChildItem -Path $PP | Where-Object { ($_.Name -notlike "default*") } | Where-Object { ($_.Name -ne "publiek") }).FullName
        foreach ($OneDrive in $PPU) {
            #Find $OneDrive
            $OneDriveLocations = (Get-ChildItem -Path $PPU -Filter "OneDrive*" -ErrorAction SilentlyContinue).FullName
        }
    
    }
    try {
        foreach ($OneDriveLocation in $OneDriveLocations) {
        
            $Icons = @()
            $AllEdgeIcons = New-Object PSobject
            $AllTeamsIcons = New-Object PSobject
            $EdgeIcons = (Get-ChildItem -Path $OneDriveLocation -Filter "Microsoft Edge*.lnk" -Recurse -ErrorAction SilentlyContinue)
            $TeamsIcons = (Get-ChildItem -Path $OneDriveLocation -Filter "Microsoft Teams*.lnk" -Recurse -ErrorAction SilentlyContinue)
            $AllEdgeIcons | Add-Member -MemberType NoteProperty -Name "Fullname" -Value $EdgeIcons.fullname
            $AllTeamsIcons | Add-Member -MemberType NoteProperty -Name "Fullname" -Value $TeamsIcons.fullname

            $icons += $EdgeIcons
            $icons += $TeamsIcons

            if (($icons.Count -gt "0")) {
                #Below necessary for Intune as of 10/2019 will only remediate Exit Code 1
            
                foreach ($Item in $Icons) {
                    Write-Host The item ($item).fullname is removed -ForegroundColor Red
                    Remove-Item $Item.FullName -Force 
                    $Cleandedicons = "Yes"
                }


            }

        }
        if ($Cleandedicons -eq "Yes") {

            Add-Type -AssemblyName System.Windows.Forms
            $global:balmsg = New-Object System.Windows.Forms.NotifyIcon
            $path = (Get-Process -Id $pid).Path
            $balmsg.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($path)
            $balmsg.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Info
            $balmsg.BalloonTipText = 'We removed the duplicated icons of Microsoft Teams or Edge'
            $balmsg.BalloonTipTitle = "Keep your desktop clean"
            $balmsg.Visible = $true
            $balmsg.ShowBalloonTip(40000)
        }      
    }
    catch {
        $errMsg = $_.Exception.Message
        Write-Error $errMsg
        exit 1
    }
}