$ProfileAge = 45 # max profile age in days

try {

    # Get all User profile folders older than X days
    $LastAccessedFolder = Get-ChildItem "C:\Users" |  Where-Object {$_ -notlike "*Windows*" -and $_ -notlike "*default*" -and $_ -notlike "*Public*" -and $_ -notlike "*Admin*" -and $_ -notlike "*2"} | Where-Object LastWriteTime -le (Get-Date).AddDays(-$ProfileAge)
    $LastAccessedFolder | ForEach-Object {Write-Output "Profile: $($_.Name), LastUpdated $($_.LastWriteTime), $(Get-Date)"}
    
    # Filter the list of folders to only include those that are not associated with local user accounts
    #$Profiles_notLocal = $LastAccessedFolder | Where-Object { $_.Name -notin $(Get-LocalUser).Name }

    # Retrieve a list of user profiles and filter to only include the old ones
    $ProfilesToRemove = Get-CimInstance -Class Win32_UserProfile | Where-Object { $_.LocalPath -in $($LastAccessedFolder.FullName) }

    if ($ProfilesToRemove) {
        Write-Output "$(Get-Date) $($ProfilesToRemove.RefCount()) profiles to remove."
        # Removing all old profiles
        $ProfilesToRemove | ForEach-Object { Write-Output "$(Get-Date) Removing $($_)"; Remove-CimInstance -ErrorAction Continue }
    } else {
        Write-Output "$(Get-Date) No profiles older than $ProfileAge days found. "
    }

} 
catch {
    Write-Output "$(Get-Date) Error occurred."
    Write-Error $_
}