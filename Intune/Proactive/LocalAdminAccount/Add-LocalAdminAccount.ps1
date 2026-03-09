# Define username
$Username = "localadmin"

# Check if user exists
if (-not (Get-LocalUser -Name $Username -ErrorAction SilentlyContinue)) {
    # Generate a random complex 16-character password
    Add-Type -AssemblyName System.Web
    $Password = [System.Web.Security.Membership]::GeneratePassword(16, 4)

    # Create the user
    $SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force
    New-LocalUser -Name $Username -Password $SecurePassword -FullName "Local Administrator" -Description "Local admin account created by Intune" -PasswordNeverExpires:$true

    # Add user to Administrators group
    Add-LocalGroupMember -Group "Administrators" -Member $Username

}

# Optional: Output status
Write-Output "User '$Username' checked/created successfully."
return 0
