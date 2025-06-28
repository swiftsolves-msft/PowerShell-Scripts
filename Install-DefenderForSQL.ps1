#Requires -Modules Az.Accounts, Az.ConnectedMachine

<#
.SYNOPSIS
    Installs the Defender for SQL extension on Azure Arc-connected machines in a specified subscription and resource group, with optional tag-based filtering.

.DESCRIPTION
    This script sets the Azure context to a specified subscription, retrieves all Azure Arc-connected machines in a given resource group,
    optionally filters them based on a tag name and value, displays the list of machines to be processed, and prompts the user to proceed.
    If confirmed, it checks each machine for the Defender for SQL extension and installs it if not present.

.PARAMETER subscriptionId
    The ID of the Azure subscription to target. This parameter is mandatory.

.PARAMETER resourceGroupName
    The name of the resource group containing the Azure Arc-connected machines. This parameter is mandatory.

.PARAMETER tagName
    The name of the tag to filter machines. Optional.

.PARAMETER tagValue
    The value of the tag to filter machines. Optional.

.EXAMPLE
    .\Install-DefenderForSQL.ps1 -subscriptionId "your-subscription-id" -resourceGroupName "your-resource-group"
    Runs the script without tag filtering.

.EXAMPLE
    .\Install-DefenderForSQL.ps1 -subscriptionId "your-subscription-id" -resourceGroupName "your-resource-group" -tagName "Environment" -tagValue "Production"
    Runs the script with tag filtering for machines tagged with "Environment=Production".
#>

param (
    [Parameter(Mandatory = $true)]
    [string]$subscriptionId,

    [Parameter(Mandatory = $true)]
    [string]$resourceGroupName,

    [string]$tagName,

    [string]$tagValue
)

# Record the start time for logging
$startTime = Get-Date
Write-Output "Script started at $startTime"

# Function to check available extensions for troubleshooting
function Get-AvailableDefenderExtensions {
    param($Location, $ResourceGroupName, $MachineName)
    try {
        Write-Output "Checking available extensions for Arc machine: $MachineName in location: $Location"
        
        # For Arc machines, we should check what extensions are actually available
        # This is different from VM extensions
        try {
            # Try to get existing extensions on the machine to see what's possible
            $existingExtensions = Get-AzConnectedMachineExtension -ResourceGroupName $ResourceGroupName -MachineName $MachineName -ErrorAction SilentlyContinue
            if ($existingExtensions) {
                Write-Output "Existing extensions on machine ${MachineName}:"
                $existingExtensions | ForEach-Object { Write-Output "  - Name: $($_.Name), Type: $($_.TypePropertiesType), Publisher: $($_.Publisher)" }
            }
        } catch {
            Write-Output "Could not retrieve existing extensions for machine ${MachineName}"
        }
        
        # Check for common Defender extension types that work with Arc machines
        Write-Output "Common Defender extension types for Arc machines:"
        Write-Output "  - Microsoft.Azure.AzureDefenderForSQL/AdvancedThreatProtection.Windows"
        Write-Output "  - Microsoft.Azure.Security/MicrosoftDefenderForSQL" 
        Write-Output "  - Microsoft.Azure.AzureDefenderForServers/MDE.Windows"
        
    } catch {
        Write-Warning "Could not retrieve extension information: $_"
    }
}

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

# Filter machines based on optional tag name and value
if ($tagName -and $tagValue) {
    $machines = $machines | Where-Object { $_.Tags[$tagName] -eq $tagValue }
}

# Check if any machines match the criteria
if ($machines.Count -eq 0) {
    Write-Output "No Azure Arc-connected machines found matching the criteria."
    exit 0
}

# Check available extensions in the first machine's location for troubleshooting
if ($machines.Count -gt 0) {
    Get-AvailableDefenderExtensions -Location $machines[0].Location -ResourceGroupName $resourceGroupName -MachineName $machines[0].Name
}

# Display the list of machines to be processed
Write-Output "The following machines will be processed:"
foreach ($machine in $machines) {
    Write-Output $machine.Name
}

# Prompt the user to proceed with the installation
$proceed = Read-Host "Do you want to proceed with the installation? (yes/no)"
if ($proceed.ToLower() -eq "yes") {
    $extensionName = "MicrosoftDefenderForSQL"
    foreach ($machine in $machines) {
        $machineName = $machine.Name
        Write-Output "Processing machine: $machineName"

        # Check if the extension already exists (check for both possible names)
        $extension = Get-AzConnectedMachineExtension -ResourceGroupName $resourceGroupName -MachineName $machineName -Name $extensionName -ErrorAction SilentlyContinue
        $defenderSQLExtension = Get-AzConnectedMachineExtension -ResourceGroupName $resourceGroupName -MachineName $machineName -ErrorAction SilentlyContinue | Where-Object { 
            ($_.TypePropertiesType -eq "AdvancedThreatProtection.Windows" -and $_.Publisher -eq "Microsoft.Azure.AzureDefenderForSQL") -or
            ($_.Name -like "*DefenderForSQL*")
        }
        
        if ($null -ne $extension -or $null -ne $defenderSQLExtension) {
            if ($null -ne $defenderSQLExtension) {
                Write-Output "Defender for SQL extension already exists on machine ${machineName}:"
                Write-Output "  - Name: $($defenderSQLExtension.Name)"
                Write-Output "  - Type: $($defenderSQLExtension.TypePropertiesType)"
                Write-Output "  - Publisher: $($defenderSQLExtension.Publisher)"
                Write-Output "  - Status: $($defenderSQLExtension.ProvisioningState)"
            } else {
                Write-Output "Extension $extensionName already exists on machine ${machineName}."
            }
        } else {
            Write-Output "Installing extension $extensionName on machine $machineName..."
            
            # Get the machine's location for the extension installation
            $machineLocation = $machine.Location
            Write-Output "Installing extension in location: $machineLocation"
            
            # Try different extension configurations that work with Arc machines
            $extensionConfigs = @(
                @{
                    Publisher = "Microsoft.Azure.AzureDefenderForSQL"
                    Type = "AdvancedThreatProtection.Windows"
                    Version = "2.0"
                },
                @{
                    Publisher = "Microsoft.Azure.Security"
                    Type = "MicrosoftDefenderForSQL"
                    Version = "1.0"
                },
                @{
                    Publisher = "Microsoft.Azure.AzureDefenderForServers"
                    Type = "MDE.Windows" 
                    Version = "1.0"
                }
            )
            
            $installed = $false
            foreach ($config in $extensionConfigs) {
                if ($installed) { break }
                
                try {
                    Write-Output "Trying Publisher: $($config.Publisher), Type: $($config.Type)"
                    # Use the correct extension name based on the publisher/type combination
                    $currentExtensionName = if ($config.Publisher -eq "Microsoft.Azure.AzureDefenderForSQL") { "MicrosoftDefenderForSQL" } else { $extensionName }
                    
                    New-AzConnectedMachineExtension -ResourceGroupName $resourceGroupName -MachineName $machineName -Name $currentExtensionName -Publisher $config.Publisher -ExtensionType $config.Type -Location $machineLocation -TypeHandlerVersion $config.Version -ErrorAction Stop
                    Write-Output "Extension $currentExtensionName installed successfully on machine $machineName using $($config.Publisher)/$($config.Type)."
                    $installed = $true
                } catch {
                    Write-Warning "Failed with Publisher: $($config.Publisher), Type: $($config.Type) - $_"
                }
            }
            
            if (-not $installed) {
                Write-Error "Failed to install any Defender extension on machine ${machineName}. Please check if Defender for SQL is available for Arc machines in your region."
            }
        }
    }
} else {
    Write-Output "Installation cancelled."
    exit 0
}

# Record the end time and calculate duration
$endTime = Get-Date
$duration = $endTime - $startTime
Write-Output "Script completed at $endTime. Duration: ${duration.TotalSeconds} seconds"