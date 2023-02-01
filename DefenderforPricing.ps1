
$Free = 'Free'
$Standard = 'Standard'

$subs = Get-AzSubscription

foreach($sub in $subs){

    # set a particular subscription context to search for VMs
    Set-AzContext -Subscription $Sub.Id

    Get-AzSecurityPricing -Name CloudPosture
    # Set-AzSecurityPricing -Name CloudPosture -PricingTier $Free

    # Set-AzSecurityPricing -Name VirtualMachines -PricingTier $
    # Set-AzSecurityPricing -Name SqlServers -PricingTier $
    # Set-AzSecurityPricing -Name AppServices -PricingTier $
    # Set-AzSecurityPricing -Name StorageAccounts -PricingTier $
    # Set-AzSecurityPricing -Name SqlServerVirtualMachines -PricingTier $
    # Set-AzSecurityPricing -Name KeyVaults -PricingTier $
    # Set-AzSecurityPricing -Name Dns -PricingTier $
    # Set-AzSecurityPricing -Name Arm -PricingTier $
    # Set-AzSecurityPricing -Name OpenSourceRelationalDatabases -PricingTier $
    # Set-AzSecurityPricing -Name CosmosDbs -PricingTier $
    # Set-AzSecurityPricing -Name Containers -PricingTier $
}