## REQS ## You will need ARMClient, Az modules installed. User running script should be Security Admin over Subscriptions


<# 
NOTES: 

 The next time you return to the ASC integrations page of the Azure portal, the Enable for Linux machines button won't be shown. 

 Link: https://docs.microsoft.com/en-us/azure/security-center/security-center-wdatp?tabs=linux#existing-users-of-azure-defender-and-microsoft-defender-for-endpoint-for-windows

#>

#Login into Azure enviroment
Login-AzAccount
ARMClient.exe azlogin

# PUT call body to enable the ASC-MDE Linux
$payload1 = "{'name': 'WDATP_EXCLUDE_LINUX_PUBLIC_PREVIEW','type': 'Microsoft.Security/settings','kind': 'DataExportSettings','properties': {'enabled': false}}"

# gather all subscriptions
$subs = Get-AzSubscription

# For each subscription check and set ASC-MDE Linux setting. get\put and invoke REST GET WDATP_EXCLUDE_LINUX_PUBLIC_PREVIEW API
Foreach ($sub in $subs){

    # Set subscription context

    #Subscription Id
    $subid = $sub.Id

    Set-AzContext -SubscriptionId $subid

    # ARM Call URL invoke REST WDATP_EXCLUDE_LINUX_PUBLIC_PREVIEW API
    $armcall = "/subscriptions/" + $subid + "/providers/Microsoft.Security/settings/WDATP_EXCLUDE_LINUX_PUBLIC_PREVIEW?api-version=2021-07-01"

    # Make ARM Client call for GET WDATP_EXCLUDE_LINUX_PUBLIC_PREVIEW API
    $check = armclient GET $armcall

    # Convert from JSON to Table
    $check = $check | ConvertFrom-Json

    #write out results
    Write-Host -ForegroundColor Magenta "Subscription: " $sub.Name " - " $subid " - Is Linux ASC-MDE NOT Integrated?: " $check.properties.enabled

    #Check to see if ASC-MDE Linuc is NOT Integrated or Excluded = true > WDATP_EXCLUDE_LINUX_PUBLIC_PREVIEW
    if ($check.properties.enabled -eq $true) {

        # Make ARM Client call for PUT WDATP_EXCLUDE_LINUX_PUBLIC_PREVIEW API
        # Update Subscription and ASC to False to exclude setting
        armclient PUT $armcall $payload1
    
    }

}