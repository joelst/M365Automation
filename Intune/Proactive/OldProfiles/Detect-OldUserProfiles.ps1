$ProfileAge = 45 # max profile age in days

try {

    # Get all User profile folders older than X days
    $LastAccessedFolder = Get-ChildItem "C:\Users" |  Where-Object {$_ -notlike "*Windows*" -and $_ -notlike "*default*" -and $_ -notlike "*Public*" -and $_ -notlike "*Admin*"} | Where-Object LastWriteTime -lt (Get-Date).AddDays(-$ProfileAge)

    $LastAccessedFolder | ForEach-Object {Write-Output "$($_.Name), $($_.LastWriteTime), $(Get-Date)"}

    # Filter the list of folders to only include those that are not associated with local user accounts
    $Profiles_notLocal = $LastAccessedFolder | Where-Object { $_.Name -notin $(Get-LocalUser).Name }

    # Retrieve a list of user profiles and filter to only include the old ones
    $ProfilesToRemove = Get-CimInstance -Class Win32_UserProfile | Where-Object { $_.LocalPath -in $($Profiles_notLocal.FullName) }

    if ($ProfilesToRemove) {
        foreach ($profile in $ProfilesToRemove) {
            Write-Output " $(Get-Date) Old profiles ($profile.LastWriteTime) : $($profile.LocalPath)"
        }
        Exit 1

    } else {
        Write-Output " $(Get-Date) No profiles older than $ProfileAge days found."

        Exit 0
    }

}
catch {
    Write-Error $_
}