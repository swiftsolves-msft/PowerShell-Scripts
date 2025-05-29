#Requires -Modules Az.Accounts, Az.ConnectedMachine

<#
.SYNOPSIS
    Checks all Azure Arc-connected machines in a specified subscription and resource group for a specific extension and removes it if found.

.DESCRIPTION
    This script sets the Azure context to a specified subscription, retrieves all Azure Arc-connected machines in a given resource group,
    and for each machine, checks if the specified extension (default: "MicrosoftDefenderForSQL") exists. If the extension is present,
    it initiates its removal asynchronously.

.PARAMETER subscriptionId
    The ID of the Azure subscription to target. This parameter is mandatory.

.PARAMETER resourceGroupName
    The name of the resource group containing the Azure Arc-connected machines. This parameter is mandatory.

.PARAMETER extensionName
    The name of the extension to check and remove. Defaults to "MicrosoftDefenderForSQL".

.EXAMPLE
    .\Remove-ArcExtension.ps1 -subscriptionId "your-subscription-id" -resourceGroupName "your-resource-group"
    Runs the script with the default extension name "MicrosoftDefenderForSQL".

.EXAMPLE
    .\Remove-ArcExtension.ps1 -subscriptionId "your-subscription-id" -resourceGroupName "your-resource-group" -extensionName "CustomExtension"
    Runs the script targeting a custom extension named "CustomExtension".
#>

param (
    [Parameter(Mandatory = $true)]
    [string]$subscriptionId,

    [Parameter(Mandatory = $true)]
    [string]$resourceGroupName,

    [string]$extensionName = "MicrosoftDefenderForSQL"
)

# Record the start time for logging
$startTime = Get-Date
Write-Output "Script started at $startTime"

# Set the Azure context to the specified subscription
try {
    Set-AzContext -SubscriptionId $subscriptionId -ErrorAction Stop | Out-Null
    Write-Output "Successfully set Azure context to subscription: $subscriptionId"
} catch {
    Write-Error "Failed to set Azure context: $_"
    exit 1
}

# Retrieve all Azure Arc-connected machines in the specified resource group
try {
    $machines = Get-AzConnectedMachine -ResourceGroupName $resourceGroupName
} catch {
    Write-Error "Failed to retrieve Azure Arc-connected machines: $_"
    exit 1
}

# Check if any machines were found
if ($machines.Count -eq 0) {
    Write-Output "No Azure Arc-connected machines found in resource group $resourceGroupName."
    exit 0
}

# Iterate through each Azure Arc-connected machine
foreach ($machine in $machines) {
    $machineName = $machine.Name
    Write-Output "Processing machine: $machineName"

    # Verify if the extension exists on the Arc-enabled server
    $extension = Get-AzConnectedMachineExtension -ResourceGroupName $resourceGroupName -MachineName $machineName -Name $extensionName -ErrorAction SilentlyContinue

    if ($null -eq $extension) {
        Write-Output "Extension $extensionName not found on machine $machineName in resource group $resourceGroupName."
    } else {
        # Uninstall the extension
        Write-Output "Uninstalling extension $extensionName from machine $machineName..."
        try {
            Remove-AzConnectedMachineExtension -ResourceGroupName $resourceGroupName -MachineName $machineName -Name $extensionName -ErrorAction Stop -NoWait
            Write-Output "Extension $extensionName uninstallation initiated successfully for machine $machineName."
        } catch {
            Write-Error "Failed to initiate uninstallation for machine ${machineName}: $_"
        }
    }
}

# Record the end time and calculate duration
$endTime = Get-Date
$duration = $endTime - $startTime
Write-Output "Script completed at $endTime. Duration: ${duration.TotalSeconds} seconds"