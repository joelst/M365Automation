# Microsoft Endpoint Manager (Intune) App Factory tools

This repo was heavily inspired heavily by https://github.com/aaronparker and the scripts here: https://github.com/aaronparker/intune/tree/main/Apps

## Scripts

TheI'm building a list of applications to package and then adjusting the core script to eventually build a pipeline that will publish all applications in the factory. For now there is a script for each application with a `Update-AllPackages.ps1` script to run all of the scripts. 

I have only started on the Windows packages and have a need for a similar solution for macOS packages.

## Update catalog

The Windows scripts rely heavily on Winget instead of Evergreen. I chose to use winget instead of Evergreen is because I'm been contributing to winget package manifests and can provide updates quickly to manifests if needed.

# Contributing

Feel free to submit a pull request or create an issue with suggestions.
