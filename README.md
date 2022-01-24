# Microsoft Endpoint Manager (Intune) App Factory tools

This repo was heavily inspired heavily by https://github.com/aaronparker and the scripts here: https://github.com/aaronparker/intune/tree/main/Apps
Another similar solution is: https://github.com/FlorianSLZ/scloud/tree/main/intune-win32-deployment

## Scripts

This repo is a growing list of application package scripts. The goal is to build one script file with a defintion file that includes all packages to build and publish all applications. For each defined package has a its own script. The `Update-AllPackages.ps1` script will run all of the scripts. 

I have only started on the Windows packages and have a need for a similar solution for macOS packages.

## Update catalog

The Windows scripts rely heavily on Winget instead of Evergreen. I chose to use winget instead of Evergreen is because I'm been contributing to winget package manifests and can provide updates quickly to manifests if needed.

# Contributing

Feel free to submit a pull request or create an issue with suggestions.
