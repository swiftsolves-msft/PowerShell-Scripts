# get all Azure subscriptions to check
$Subs = Get-AzSubscription

# For each subscription check Public Ips and Metrics
foreach($sub in $subs){

    #Set Azure Subscription Contect to current subscription in loop
    Set-AzContext -Subscription $sub.Id

    # Check for Policy Assignment: 'Defender for Containers provisioning AKS Security Profile' using Defintion: Configure Azure Kubernetes Service clusters to enable Defender profile
    $result1 = Get-AzPolicyAssignment -Name 'Defender for Containers provisioning AKS Security Profile'

    If($result1 -eq $null){
    
        # Policy Name: Configure Azure Kubernetes Service clusters to enable Defender profile	
        $Policy = Get-AzPolicyDefinition -Name '64def556-fbad-4622-930e-72d1d5589bf5'
        New-AzPolicyAssignment -Name 'Defender for Containers provisioning AKS Security Profile' -PolicyDefinition $Policy -Scope "/subscriptions/$($sub.Id)" -IdentityType 'SystemAssigned' -Location 'eastus'

    }

    # Check for Policy Assignment: 'Defender for Containers provisioning ARC k8s Enabled' using Defintion: [Preview]: Configure Azure Arc enabled Kubernetes clusters to install Microsoft Defender for Cloud extension	
    $result2 = Get-AzPolicyAssignment -Name 'Defender for Containers provisioning ARC k8s Enabled'

    If($result2 -eq $null){
    
        # Policy Name: [Preview]: Configure Azure Arc enabled Kubernetes clusters to install Microsoft Defender for Cloud extension		
        $Policy = Get-AzPolicyDefinition -Name '0adc5395-9169-4b9b-8687-af838d69410a'
        New-AzPolicyAssignment -Name 'Defender for Containers provisioning ARC k8s Enabled' -PolicyDefinition $Policy -Scope "/subscriptions/$($sub.Id)" -IdentityType 'SystemAssigned' -Location 'eastus'


    }

    # Check for Policy Assignment: 'Defender for Containers provisioning Azure Policy Addon for Kub' using Defintion: Deploy Azure Policy Add-on to Azure Kubernetes Service clusters
    $result3 = Get-AzPolicyAssignment -Name 'Defender for Containers provisioning Azure Policy Addon for Kub'

    If($result3 -eq $null){
    
        # Policy Name: Deploy Azure Policy Add-on to Azure Kubernetes Service clusters		
        $Policy = Get-AzPolicyDefinition -Name '708b60a6-d253-4fe0-9114-4be4c00f012c'
        New-AzPolicyAssignment -Name 'Defender for Containers provisioning Azure Policy Addon for Kub' -PolicyDefinition $Policy -Scope "/subscriptions/$($sub.Id)" -IdentityType 'SystemAssigned' -Location 'eastus'


    }

    # Check for Policy Assignment: 'Defender for Containers provisioning Policy extension for Arc-e' using Defintion: [Preview]: Configure Azure Arc enabled Kubernetes clusters to install the Azure Policy extension
    $result4 = Get-AzPolicyAssignment -Name 'Defender for Containers provisioning Policy extension for Arc-e'

    If($result4 -eq $null){
    
        # Policy Name: [Preview]: Configure Azure Arc enabled Kubernetes clusters to install the Azure Policy extension		
        $Policy = Get-AzPolicyDefinition -Name 'a8eff44f-8c92-45c3-a3fb-9880802d67a7'
        New-AzPolicyAssignment -Name 'Defender for Containers provisioning Policy extension for Arc-e' -PolicyDefinition $Policy -Scope "/subscriptions/$($sub.Id)" -IdentityType 'SystemAssigned' -Location 'eastus'

    }


}