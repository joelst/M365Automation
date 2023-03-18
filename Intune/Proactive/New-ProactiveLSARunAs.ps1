<# 

Proactive remediation to enabled LSA RunAsPPL

Adapted from https://github.com/richeaston/Intune-Proactive-Remediation/tree/main/LSA-Secret-Protection



#>

$mode = $MyInvocation.MyCommand.Name.Split(".")[0]

if ($mode -eq "detect") {

    try {
        $lsa = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RunAsPPL -ErrorAction SilentlyContinue
        if ($LSA) {
            $secure = Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RunAsPPL
            if ($secure -eq 1) {
                Write-Output "All Good"
                Exit 0
            }
            else {
                Write-Output "Not Secure!"
                Exit 1
            }
        }
        else {
            Write-Output "Not Secure!"
            exit 1
        }
    }
    catch {
        $errMsg = $_.Exception.Message
        Write-Output $errMsg
        exit 1
    }



}
else {

    Try {
        $lsa = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RunAsPPL -ErrorAction SilentlyContinue
        if ($lsa) {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RunAsPPL -Value 1 -Force
        }
        else {
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RunAsPPL -PropertyType DWORD -Value 1 -Force -Verbose
        }
        Write-Output "Secure!"
        exit 0
    }
    Catch {
        $errMsg = $_.Exception.Message
        Write-Output $errMsg
        exit 1
    }


}