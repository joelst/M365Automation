# Microsoft Endpoint Manager (Intune) App Factory tools
It is extremely important to automate package updates to ensure application security updates are applied with as little manual effort as possible.

This repo was heavily inspired heavily by https://github.com/aaronparker and the scripts here: https://github.com/aaronparker/intune/tree/main/Apps

This is also another excellent solution using chocolatey here: https://github.com/FlorianSLZ/scloud/tree/main/intune-win32-deployment

## Scripts

This repo is a growing list of application package and management scripts. The goal is to build one script file with a defintion file that includes all packages to build and publish all applications. For each defined package has a its own script. The `Update-AllPackages.ps1` script will run all of the scripts. 

I started on the Windows packages and have a need for a similar solution for macOS packages.

## Update catalog

The Windows scripts use Winget, because I'm been contributing to winget package manifests and can provide updates quickly. Chocolatey, Evergreen, and other tools may also be used to accomplish similar tasks.

## Troubleshooting package installation failures

The primary reason seems to be that the file version does not match the package version exactly. By default, the scripts create a detection rule that compares the package version to the executable version. This has been true with *Adobe Acrobat DC package version (21.011.20039)* is not greater than or equal to the *Acrobat.exe version (21.11.20039.0)* and the agent will mark the installation as failed. In this case the application does install correctly but Endpoint Manager reports an error. To fix the error, update the detection rule manually with the correct Acrobat.exe version and reinstall.

## Potential Work Areas

- Automatically publishing superceded updates. If older version found, read assignment, apply assignment to new package and set it to supercede old package.
- Consolidate to a single script (or PowerShell module) and use JSON or CSV to define all packages.
- Extract and or test GUID or File version validation locally before creating the package.
- Create a standardized icon repository system instead of using random links.

## Contributing

Feel free to submit a pull request or create an issue with suggestions.
