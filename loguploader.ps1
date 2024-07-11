function Send-AzMonitorCustomLogs {
    <#
    .SYNOPSIS
    Sends custom logs to a specific table in Azure Monitor.
    
    .DESCRIPTION
    Script to send data to a data collection endpoint which is a unique connection point for your subscription.
    The payload sent to Azure Monitor must be in JSON format. A data collection rule is needed in your Azure tenant that understands the format of the source data, potentially filters and transforms it for the target table, and then directs it to a specific table in a specific workspace.
    You can modify the target table and workspace by modifying the data collection rule without any change to the REST API call or source data.
    
    .PARAMETER LogPath
    Path to the log file or folder to read logs from and send them to Azure Monitor.
    
    .PARAMETER appId
    Azure Active Directory application to authenticate against the API to send logs to Azure Monitor data collection endpoint.
    This script supports the Client Credential Grant Flow.

    .PARAMETER appSecret
    Secret text to use with the Azure Active Directory application to authenticate against the API for the Client Credential Grant Flow.

    .PARAMETER TenantId
    ID of Tenant
    
    .PARAMETER DcrImmutableId
    Immutable ID of the data collection rule used to process events flowing to an Azure Monitor data table.
    
    .PARAMETER DceURI
    Uri of the data collection endpoint used to host the data collection rule.

    .PARAMETER StreamName
    Name of stream to send data to before being procesed and sent to an Azure Monitor data table.
    
    .PARAMETER TimestampField
    Specific field available in your custom log to select as the main timestamp. This will be the TimeGenerated field in your table. By default, this script uses a current timestamp.
    
    .PARAMETER ShowProgressBar
    Show a PowerShell progress bar. Disabled by default.

    .EXAMPLE
    PS> . .\Send-AzMonitorCustomLogs.ps1
    PS> Send-AzMonitorCustomLogs -LogPath C:\WinEvents.json -appId 'XXXX' -appSecret 'XXXXXX' -TenantId 'XXXXXX' -DcrImmutableId 'dcr-XXXX' -DceURI 'https://XXXX.westus2-1.ingest.monitor.azure.com' -StreamName 'Custom-WindowsEvent' -TimestampField 'TimeCreated'
    
    .EXAMPLE
    PS> . .\Send-AzMonitorCustomLogs.ps1
    PS> Send-AzMonitorCustomLogs -LogPath C:\WinEvents.json -appId 'XXXX' -appSecret 'XXXXXX' -TenantId 'XXXXXX' -DcrImmutableId 'dcr-XXXX' -DceURI 'https://XXXX.westus2-1.ingest.monitor.azure.com' -StreamName 'Custom-WindowsEvent' -TimestampField 'TimeCreated' -Debug
    
    .EXAMPLE
    PS> . .\Send-AzMonitorCustomLogs.ps1
    PS> Send-AzMonitorCustomLogs -LogPath C:\WinEventsFolder\ -appId 'XXXX' -appSecret 'XXXXXX' -TenantId 'XXXXXX' -DcrImmutableId 'dcr-XXXX' -DceURI 'https://XXXX.westus2-1.ingest.monitor.azure.com' -StreamName 'Custom-WindowsEvent' -TimestampField 'TimeCreated' -Debug
    #    PS> Send-AzMonitorCustomLogs -LogPath .\origlog\ -appId 'XXXXXX' -appSecret 'XXXXXX' -TenantId 'XXXXXX' -DcrImmutableId 'XXXXXX' -DceURI 'https://apt-rtyj.eastus-1.ingest.monitor.azure.com' -StreamName 'Custom-CyberAPT_CL' -TimestampField 'EventTime'
    # Send-AzMonitorCustomLogs -LogPath .\origlog\ -appId 'XXXXXX' -appSecret 'XXXXXX' -TenantId 'XXXXXX' -DcrImmutableId 'XXXXXX' -DceURI 'https://apt-rtyj.eastus-1.ingest.monitor.azure.com' -StreamName 'Custom-WindowsEvent' -TimestampField 'EventTime'


    .NOTES
    # Author: Roberto Rodriguez (@Cyb3rWard0g)
    # License: MIT

    # Reference:
    # https://docs.microsoft.com/en-us/azure/azure-monitor/logs/custom-logs-overview
    # https://docs.microsoft.com/en-us/azure/azure-monitor/logs/tutorial-custom-logs-api#send-sample-data
    # https://securitytidbits.wordpress.com/2017/04/14/powershell-and-gzip-compression/

    # Custom Logs Limit
    # Maximum size of API call: 1MB for both compressed and uncompressed data
    # Maximum data/minute per DCR: 1 GB for both compressed and uncompressed data. Retry after the duration listed in the Retry-After header in the response.
    # Maximum requests/minute per DCR: 6,000. Retry after the duration listed in the Retry-After header in the response.

    .LINK
    https://github.com/OTRF/Security-Datasets
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateScript({
                foreach ($f in $_) {
                    if ( -Not ($f | Test-Path) ) {
                        throw "File or folder does not exist"
                    }
                }
                return $true
            })]
        [string[]]$LogPath,

        [Parameter(Mandatory = $true)]
        [string]$appId,

        [Parameter(Mandatory = $true)]
        [string]$appSecret,

        [Parameter(Mandatory = $true)]
        [string]$TenantId,

        [Parameter(Mandatory = $true)]
        [string]$DcrImmutableId,

        [Parameter(Mandatory = $true)]
        [string]$DceURI,

        [Parameter(Mandatory = $true)]
        [string]$StreamName,

        [Parameter(Mandatory = $false)]
        [string]$TimestampField,

        [Parameter(Mandatory = $false)]
        [switch]$ShowProgressBar
    )

    If ($PSBoundParameters['Debug']) {
        $DebugPreference = 'Continue'
    }

    @("[+] Automatic log uploader is starting. Creator: Roberto Rodriguez @Cyb3rWard0g / License: MIT")

    # Aggregate files from input paths
    $all_datasets = @()
    foreach ($file in $LogPath) {
        if ((Get-Item $file) -is [system.io.fileinfo]) {
            $all_datasets += (Resolve-Path -Path $file)
        }
        elseif ((Get-Item $file) -is [System.IO.DirectoryInfo]) {
            $folderfiles = Get-ChildItem -Path $file -Recurse -Include *.json
            $all_datasets += $folderfiles
        }
    }

    write-Host "*******************************************"
    Write-Host "[+] Obtaining access token.."
    ## Obtain a bearer token used to authenticate against the data collection endpoint
    $scope = [System.Web.HttpUtility]::UrlEncode("https://monitor.azure.com//.default")   
    $body = "client_id=$appId&scope=$scope&client_secret=$appSecret&grant_type=client_credentials";
    $headers = @{"Content-Type" = "application/x-www-form-urlencoded" };
    $uri = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
    $bearerToken = (Invoke-RestMethod -Uri $uri -Method "Post" -Body $body -Headers $headers).access_token
    Write-Debug $bearerToken

    Function Send-DataToDCE($payload, $size) {
        write-debug "############ Sending Data ############"
        write-debug "JSON array size: $($size/1mb) MBs"
        
        # Initialize Headers and URI for POST request to the Data Collection Endpoint (DCE)
        $headers = @{"Authorization" = "Bearer $bearerToken"; "Content-Type" = "application/json" }
        $uri = "$DceURI/dataCollectionRules/$DcrImmutableId/streams/$StreamName`?api-version=2021-11-01-preview"
        #$uri = "$DceURI/dataCollectionRules/$DcrImmutableId/streams/$StreamName`?api-version=2021-12-01-preview"
        
        # Showing payload for troubleshooting purposes
        Write-Debug ($payload | ConvertFrom-Json | ConvertTo-Json)
        
        # Sending data to Data Collection Endpoint (DCE) -> Data Collection Rule (DCR) -> Azure Monitor table
        Invoke-RestMethod -Uri $uri -Method "Post" -Body (@($payload | ConvertFrom-Json | ConvertTo-Json)) -Headers $headers | Out-Null
    }

    # Maximum size of API call: 1MB for both compressed and uncompressed data
    $APILimitBytes = 1mb
    $currentTime = Get-Date

    foreach ($dataset in $all_datasets) {
        $total_file_size = (get-item -Path $dataset).Length
        $json_records = @()
        $json_array_current_size = 0
        $event_count = 0
        $total_size = 0
 
        # Create ReadLines Iterator and get total number of lines
        $readLineIterator = [System.IO.File]::ReadLines($dataset)
        $numberOfLines = [Linq.Enumerable]::Count($readLineIterator)

        write-Host "*******************************************"
        Write-Host "[+] Processing $dataset"
        Write-Host "[+] Dataset Size: $($total_file_size/1mb) MBs"
        Write-Host "[+] Number of events to process: $numberOfLines"
        Write-Host "[+] Current time: $currentTime"


        # Read each JSON object from file
        foreach ($line in $readLineIterator) {
            
            if ($currentTime.AddMinutes(50) -lt (Get-Date)) {
                ## Obtain a bearer token used to authenticate against the data collection endpoint
                Write-Host "[+] The bearer token is close to be expired. It's time to renew the token... " -NoNewline
                $scope = [System.Web.HttpUtility]::UrlEncode("https://monitor.azure.com//.default")   
                $body = "client_id=$appId&scope=$scope&client_secret=$appSecret&grant_type=client_credentials";
                $headers = @{"Content-Type" = "application/x-www-form-urlencoded" };
                $uri = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
                $bearerToken = (Invoke-RestMethod -Uri $uri -Method "Post" -Body $body -Headers $headers).access_token
                $currentTime = Get-Date
                Write-Host "Completed" -ForegroundColor White -BackgroundColor Green
            }

            # Increase event number
            $event_count += 1


            # Update progress bar with current event count
            if ($ShowProgressBar) { Write-Progress -Activity "Processing files" -status "Processing $dataset" -percentComplete ($event_count / $numberOfLines * 100) }

            write-debug "############ Event $event_count ###############"
            if ($TimestampField) {
                $Timestamp = $line | Convertfrom-json | Select-Object -ExpandProperty $TimestampField
            }
            else {
                $Timestamp = Get-Date ([datetime]::UtcNow) -Format O
            }

            # Creating Dictionary for Log entry
            $log_entry = [ordered]@{
                TimeGenerated = $Timestamp
                RawEventData  = $line
            }

            # Processing Log entry as a compressed JSON object
            $message = $log_entry | ConvertTo-Json -Compress
            Write-Debug "Processing log entry: $($message.Length) bytes"
            
            # Getting proposed and current JSON array size
            $json_array_current_size = ([System.Text.Encoding]::UTF8.GetBytes(@($json_records | Convertfrom-json | ConvertTo-Json))).Length
            $json_array_proposed_size = ([System.Text.Encoding]::UTF8.GetBytes(@(($json_records + $message) | Convertfrom-json | ConvertTo-Json))).Length
            Write-Debug "Current size of JSON array: $json_array_current_size bytes"

            if ($json_array_proposed_size -le $APILimitBytes) {
                $json_records += $message
                $json_array_current_size = $json_array_proposed_size
                write-debug "New size of JSON array: $json_array_current_size bytes"
            }
            else {
                write-debug "Sending current JSON array before processing more log entries.."
                Send-DataToDCE -payload $json_records -size $json_array_current_size
                # Keeping track of how much data we are sending over
                $total_size += $json_array_current_size

                # There are more events to process..
                write-debug "######## Resetting JSON Array ########"
                $json_records = @($message)

                $json_array_current_size = ([System.Text.Encoding]::UTF8.GetBytes(@($json_records | Convertfrom-json | ConvertTo-Json))).Length
                Write-Debug "Starting JSON array with size: $json_array_current_size bytes"
            }
           
            if ($event_count -eq $numberOfLines) {
                write-debug "##### Last log entry in $dataset #######"
                Send-DataToDCE -payload $json_records -size $json_array_current_size
                # Keeping track of how much data we are sending over
                $total_size += $json_array_current_size
            }
        }
        Write-Host "[+] Finished processing dataset"
        Write-Host "[+] Number of events processed: $event_count"
        Write-Host "[+] Total data sent: $($total_size/1mb) MBs"
        write-Host "*******************************************"
    }
}


function Load-Module ($m) {

    # If module is imported - do nothing
    if (Get-Module | Where-Object { $_.Name -eq $m }) {
        write-host "[+] Module $m is already imported. " -NoNewline
        write-host "Completed" -ForegroundColor White -BackgroundColor Green
    }
    else {

        # If module is not imported, but available on disk then import
        if (Get-Module -ListAvailable | Where-Object { $_.Name -eq $m }) {
            write-host "[+] $m is available, loading... " -NoNewline
            Import-Module $m 
            write-host "Completed" -ForegroundColor White -BackgroundColor Green
        }
        else {

            # If module is not imported, not available on disk, but is in online gallery then install and import
            if (Find-Module -Name $m | Where-Object { $_.Name -eq $m }) {
                write-host "[+] $m is not available, installing... " -NoNewline
                Install-Module -Name $m -Force -Verbose -Scope CurrentUser
                write-host "Completed" -ForegroundColor White -BackgroundColor Green
                write-host "[+] $m is now available, loading... " -NoNewline
                Import-Module $m 
                write-host "Completed" -ForegroundColor White -BackgroundColor Green
            }
            else {

                # If the module is not imported, not available and not in the online gallery then abort
                write-host "[!!!] Module $m not imported, not available and not in an online gallery, exiting." -BackgroundColor Red -ForegroundColor White
                EXIT 1
            }
        }
    }
}



Push-Location (Split-Path $MyInvocation.MyCommand.Path)

Load-Module Microsoft.Graph.Applications
Load-Module Az.OperationalInsights
Load-Module Az.SecurityInsights
Load-Module Az.Accounts
Load-Module Az.Resources

Write-Host "[+] Authenticating... " -NoNewline
Connect-AzAccount -ErrorAction Stop | Out-Null

write-host "Completed" -ForegroundColor White -BackgroundColor Green
$tokenExpiryDate = (Get-Date).AddHours(1)

Add-Type -AssemblyName System.Web

$tempSub = Read-Host "Please enter your Azure subscription id"
if (!($tempSub -eq "")) {
    $subscriptionId = $tempSub
}
else {
    Write-Host "[!] Subscription Id can't be empty. Exiting now." -BackgroundColor Red -ForegroundColor White
    Exit
}

Write-Host "*******************************************"
Write-Host "[+] Setting variables... " -NoNewline



$resourceGroup = "rg-sent-adv-hunting"
$workspaceName = "sent-adv-hunting"
$fuctionName = "fWindowsEvent"
$location = "westeurope"

$original_file = '.\orig\apt29_evals_day1_manual_2020-05-01225525.json'
$destination_file = '.\apt29.json'
$day1date = "2020-05-01"
$day2date = "2020-05-02"
## Azure AD Graph's globally unique appId is 00000002-0000-0000-c000-000000000000 identified by the ResourceAppId
$graphResourceId = "00000002-0000-0000-c000-000000000000"
$appDisplayName = "app-sent-adv-hunting"
$newResourceAccess = @{  
    ResourceAppId  = $graphResourceId; 
    ResourceAccess = @( 
        @{ 
            # User.Read scope (delegated permission) to sign-in and read user profile 
            id   = "311a71cc-e848-46a1-bdf8-97ff7156d8e6";  
            type = "Scope"; 
        }
    ) 
}

$subs = Get-AzSubscription -SubscriptionId $subscriptionId -ErrorAction Stop 

if ($null -eq $subs) {
    Write-Host "[!!!] Can't get a subscription by id. Exiting now." -BackgroundColor Red -ForegroundColor White
    Exit
}


$subscriptionId = $subs.Id
$tenantId = $subs.TenantId
$workspaceResourceId = "/subscriptions/" + $subscriptionId + "/resourcegroups/" + $resourceGroup + "/providers/microsoft.operationalinsights/workspaces/" + $workspaceName
$alertRuleName = "RTLO technique detected"
$dceName = "sent-adv-hunting-dce"
$dcrName = "sent-adv-hunting-dcr"
$endpointDceUri = "https://management.azure.com/subscriptions/" + $subscriptionId + "/resourceGroups/" + $resourceGroup + "/providers/Microsoft.Insights/dataCollectionEndpoints/" + $dceName + "?api-version=2021-09-01-preview"
$dcrUri = "https://management.azure.com/subscriptions/" + $subscriptionId + "/resourceGroups/" + $resourceGroup + "/providers/Microsoft.Insights/dataCollectionRules/" + $dcrName + "?api-version=2021-09-01-preview"
$functionUri = "https://management.azure.com/subscriptions/" + $subscriptionId + "/resourcegroups/" + $resourceGroup + "/providers/Microsoft.OperationalInsights/workspaces/" + $workspaceName + "/savedSearches/" + $fuctionName + "/?api-version=2020-08-01"
$dcrId = "/subscriptions/" + $subscriptionId + "/resourceGroups/" + $resourceGroup + "/providers/Microsoft.Insights/dataCollectionRules/" + $dcrName
$dceId = "/subscriptions/" + $subscriptionId + "/resourceGroups/" + $resourceGroup + "/providers/Microsoft.Insights/dataCollectionEndpoints/" + $dceName
$roleContributorId="b24988ac-6180-42a0-ab88-20f7382dd24c"
$roleMonitoringPublisherId="3913510d-42f4-4e42-8a64-420c390055eb"

Write-Host "Completed" -ForegroundColor White -BackgroundColor Green

Write-Host "[+] Connecting to Microsoft Graph API... " -NoNewline
Connect-MgGraph -TenantId $tenantId -Scopes "Application.ReadWrite.All" | Out-Null
Write-Host "Completed" -ForegroundColor White -BackgroundColor Green

# Create the resource group if needed
try {
    Get-AzResourceGroup -Name $resourceGroup -ErrorAction Stop | Out-Null
    Write-Host "[+] Resource Group already exists."

}
catch {
    Write-Host "[+] Creating a new resource group... " -NoNewline
    New-AzResourceGroup -Name $resourceGroup -Location $location | Out-Null
    Write-Host "Completed" -ForegroundColor White -BackgroundColor Green
}

# Create the workspace
try {
    $ws = Get-AzOperationalInsightsWorkspace -Name $workspaceName -ResourceGroupName $resourceGroup -ErrorAction Stop -WarningAction Ignore
    Write-Host "[+] Log Analytics workspace already exists."
    $workspaceId = $ws.CustomerId
}
catch {
    Write-Host "[+] Creating a new log analytics workspace... " -NoNewline
    $ws = New-AzOperationalInsightsWorkspace -Location $location -Name $workspaceName -Sku PerGB2018 -ResourceGroupName $resourceGroup -RetentionInDays 90 -WarningAction Ignore
    Start-Sleep 60
    Write-Host "Completed" -ForegroundColor White -BackgroundColor Green
    $workspaceId = $ws.CustomerId
}

#Enable Sentinel
$solution = "SecurityInsights"
$packs = ""
$packs = Get-AzOperationalInsightsIntelligencePack -ResourceGroupName $resourceGroup -WorkspaceName $workspaceName -WarningAction Ignore

if (!(($packs | Where-Object { $_.Name -eq 'SecurityInsights' }).Enabled)) {
    Write-Host "[+] Enabling Microsoft Sentinel for the workspace... " -NoNewline
    Set-AzOperationalInsightsIntelligencePack -ResourceGroupName $resourceGroup -WorkspaceName $workspaceName -IntelligencePackName $solution -Enabled $true | Out-Null
    Start-Sleep 60
    Write-Host "Completed" -ForegroundColor White -BackgroundColor Green
}
else {
    Write-Host "[+] Microsoft Sentinel is already deployed."
}


#Register a new app for REST API
try {
    $app = Get-MgApplication -Filter "DisplayName eq '$appDisplayName' " -ErrorAction Stop
    if ($null -eq $app) { 
        throw "No application found" 
    }
    Write-Host "[+] Azure AD App Registration already exists. Recreating... " -NoNewline
    Remove-MgApplication -ApplicationId $app.Id | Out-Null

    $appRegistration = New-MgApplication -DisplayName $appDisplayName 
    $applicationID = $appRegistration.Id
    Start-Sleep -Seconds 15
    Write-Host "Completed" -ForegroundColor White -BackgroundColor Green
    
    Write-Host "[+] Creating a new app secret... " -NoNewline
    $appSecret = Add-MgApplicationPassword -ApplicationId $appRegistration.Id
    $appSecretValue = $appSecret.SecretText
    Write-Host "Completed" -ForegroundColor White -BackgroundColor Green

    Write-Host "[+] Assigning app permissions... " -NoNewline
    $app = Get-MgApplication -ApplicationId $applicationID
    ## Get the existing permissions of the application
    $existingResourceAccess = $app.RequiredResourceAccess
    ## If the app has no existing permissions, or no existing permissions from our new permissions resource
    if ( ([string]::IsNullOrEmpty($existingResourceAccess) ) -or ($existingResourceAccess | Where-Object { $_.ResourceAppId -eq $graphResourceId } -eq $null) ) {
        $existingResourceAccess += $newResourceAccess
        Update-MgApplication -ApplicationId $applicationID -RequiredResourceAccess $existingResourceAccess | Out-Null
    }
    ## If the app already has existing permissions from our new permissions resource
    else {
        $newResourceAccess.ResourceAccess += $existingResourceAccess.ResourceAccess
        Update-MgApplication -ApplicationId $applicationId -RequiredResourceAccess $newResourceAccess | Out-Null
    }

    Write-Host "Completed" -ForegroundColor White -BackgroundColor Green

}
catch {
    Write-Host "[+] Creating a new Azure AD App Registration... " -NoNewline
    $appRegistration = New-MgApplication -DisplayName $appDisplayName #-Oauth2AllowImplicitFlow $false -AvailableToOtherTenants $false 
    $applicationID = $appRegistration.Id
    Start-Sleep -Seconds 15
    Write-Host "Completed" -ForegroundColor White -BackgroundColor Green
    
    Write-Host "[+] Creating a new app secret... " -NoNewline
    $appSecret = Add-MgApplicationPassword -ApplicationId $appRegistration.Id
    $appSecretValue = $appSecret.SecretText
    Write-Host "Completed" -ForegroundColor White -BackgroundColor Green


    #add permissions read
    Write-Host "[+] Assigning app permissions... " -NoNewline
    $app = Get-MgApplication -ApplicationId $applicationID
    ## Get the existing permissions of the application
    $existingResourceAccess = $app.RequiredResourceAccess

    ## If the app has no existing permissions, or no existing permissions from our new permissions resource
    if ( ([string]::IsNullOrEmpty($existingResourceAccess) ) -or ($existingResourceAccess | Where-Object { $_.ResourceAppId -eq $graphResourceId } -eq $null) ) {
        $existingResourceAccess += $newResourceAccess
        Update-MgApplication -ApplicationId $applicationID -RequiredResourceAccess $existingResourceAccess | Out-Null
    }
    ## If the app already has existing permissions from our new permissions resource
    else {
        $newResourceAccess.ResourceAccess += $existingResourceAccess.ResourceAccess
        Update-MgApplication -ApplicationId $applicationId -RequiredResourceAccess $newResourceAccess | Out-Null
    }
    Write-Host "Completed" -ForegroundColor White -BackgroundColor Green
}

#create service principal for the app
$aid = $app.AppId
$sp = Get-MgServicePrincipal -Filter "AppId eq '$aid'"

if ($null -eq $sp) {
    Write-Host "[+] Creating a new service principal for the app registration... " -NoNewline
    $sp = New-MgServicePrincipal -AppId $app.AppId 
    Start-Sleep 30
    Write-Host "Completed" -ForegroundColor White -BackgroundColor Green
}
else {
    Write-Host "[+] Service principal for the app registration already exists."
}



#Assign Contributor and Monitoring Metrics Publisher role for the resource group
Write-Host "[+] Assigning Resource Group Contributor role... " -NoNewline
#New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -AppRoleId $roleContributorId 

New-AzRoleAssignment -ObjectId $sp.Id -RoleDefinitionName Contributor -ResourceGroupName $resourceGroup -WarningAction Ignore | Out-Null
Write-Host "Completed" -ForegroundColor White -BackgroundColor Green

Write-Host "[+] Assigning Monitoring Metrics Publisher role... " -NoNewline
New-AzRoleAssignment -ObjectId $sp.Id -RoleDefinitionName "Monitoring Metrics Publisher" -ResourceGroupName $resourceGroup -WarningAction Ignore | Out-Null
start-sleep 30
Write-Host "Completed" -ForegroundColor White -BackgroundColor Green



Write-Host "[+] Gathering the bearer token... " -NoNewline
#$scope = [System.Web.HttpUtility]::UrlEncode("https://monitor.azure.com//.default")   
$scope = [System.Web.HttpUtility]::UrlEncode("https://management.core.windows.net//.default")   
$body = "client_id=$aid&scope=$scope&client_secret=$appSecretValue&grant_type=client_credentials";
$headers = @{"Content-Type" = "application/x-www-form-urlencoded" };
$uriLogin = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
$bearerToken = (Invoke-RestMethod -Uri $uriLogin -Method "Post" -Body $body -Headers $headers).access_token
$headers = @{"Authorization" = "Bearer $bearerToken"; "Content-Type" = "application/json" };
Write-Host "Completed" -ForegroundColor White -BackgroundColor Green

# Creating/validating DCE
$dcePayload = @{
    location   = $location
    properties = @{
        networkAcls = @{
            publicNetworkAccess = "Enabled"
        }
    }
}
$dcePayloadJson = $dcePayload | ConvertTo-Json 

try {
    $dceObject = Invoke-RestMethod -Uri $endpointDceUri -Method "Get" -Headers $headers;
    $dceLogIngestionEndpoint = $dceObject.properties.logsIngestion.endpoint
    if (($null -eq $dceLogIngestionEndpoint) -or ($dceLogIngestionEndpoint -eq "")) {
        # Create DataCollection Endpoint
        # PUT https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Insights/dataCollectionEndpoints/{dataCollectionEndpointName}?api-version=2021-04-01
        Write-Host "[+] Creating a new DCE... " -NoNewline
        $dceCreateResponse = Invoke-RestMethod -Uri $endpointDceUri -Method "Put" -Body $dcePayloadJson -Headers $headers;
        $dceObject = Invoke-RestMethod -Uri $endpointDceUri -Method "Get" -Headers $headers;
        $dceLogIngestionEndpoint = $dceObject.properties.logsIngestion.endpoint
        Write-Host "Completed" -ForegroundColor White -BackgroundColor Green
    }
    else {
        Write-Host "[+] DCE already exists."
    }
}
catch {

    # Create DataCollection Endpoint
    # PUT https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Insights/dataCollectionEndpoints/{dataCollectionEndpointName}?api-version=2021-04-01
    Write-Host "[+] Creating a new DCE... " -NoNewline
    $dceCreateResponse = Invoke-RestMethod -Uri $endpointDceUri -Method "Put" -Body $dcePayloadJson -Headers $headers;
    $dceObject = Invoke-RestMethod -Uri $endpointDceUri -Method "Get" -Headers $headers;
    $dceLogIngestionEndpoint = $dceObject.properties.logsIngestion.endpoint
    Write-Host "Completed" -ForegroundColor White -BackgroundColor Green
}




# Creating/validating DCR
$dcrPayload = @{
    location   = $location
    properties = @{
        dataCollectionEndpointId = "$dceId"
        streamDeclarations       = @{
            "Custom-WindowsEvent" = @{
                columns = 
                @(
                    @{
                        name = "TimeGenerated"
                        type = "datetime"
                    },
                    @{
                        name = "RawEventData"
                        type = "string"
                    }
                )
                    
            }
        }
        dataSources              = @{}
        destinations             = @{
            logAnalytics = @(@{
                    workspaceResourceId = "$workspaceResourceId"
                    name                = "$workspaceName"
                }
            )
        }
        dataFlows                = @(@{
                streams      = @("Custom-WindowsEvent")
                destinations = @("$workspaceName")
                transformkql = "source | extend EventData = parse_json(RawEventData) | extend Channel=tostring(EventData.Channel),Computer=tostring(EventData.Hostname),EventID=toint(EventData.EventID),EventLevel=toint(EventData.Level),Provider=tostring(EventData.SourceName),Task=toint(EventData.Task),Type='WindowsEvent'| project TimeGenerated,Channel,Computer,EventData,EventID,EventLevel,Provider,Task,Type"
                outputStream = "Microsoft-WindowsEvent"
            }
        )
    }
}

$dcrPayloadJson = $dcrPayload | ConvertTo-Json -Depth 10

try {
    $dcrObject = Invoke-RestMethod -Uri $dcrUri -Method "Get" -Headers $headers;
    $dcrImmutableId = $dcrObject.properties.immutableId
    $correctDcrWorkspace = $dcrObject.properties.destinations.logAnalytics | Where-Object { $_.workspaceId -eq $workspaceId }

    if (($null -eq $dcrImmutableId) -or ($dcrImmutableId -eq "")) {
        # Create a new DCR 
        Write-Host "[+] Creating a new DCR... " -NoNewline
        $dcrCreateResponse = Invoke-RestMethod -Uri $dcrUri -Method "Put" -Body $dcrPayloadJson -Headers $headers;
        $dcrImmutableId = $dcrCreateResponse.properties.immutableId
        Write-Host "Completed" -ForegroundColor White -BackgroundColor Green
    }
    elseif ($correctDcrWorkspace.name -ne $workspaceName) {
        Write-Host "[+] Workspace has changed. Recreating DCR... " -NoNewline
        $dcrCreateResponse = Invoke-RestMethod -Uri $dcrUri -Method "DELETE" -Headers $headers;
        Start-Sleep 15
        $dcrCreateResponse = Invoke-RestMethod -Uri $dcrUri -Method "Put" -Body $dcrPayloadJson -Headers $headers;
        $dcrImmutableId = $dcrCreateResponse.properties.immutableId
        Write-Host "Completed" -ForegroundColor White -BackgroundColor Green
    }
    else {
        Write-Host "[+] DCR already exists."
    }
}
catch {
    # Create a new DCR 
    Write-Host "[+] Creating a new DCR... " -NoNewline
    $dcrCreateResponse = Invoke-RestMethod -Uri $dcrUri -Method "Put" -Body $dcrPayloadJson -Headers $headers;
    $dcrImmutableId = $dcrCreateResponse.properties.immutableId
    Write-Host "Completed" -ForegroundColor White -BackgroundColor Green
}



# replace 2 days from apt logs

if (!(Test-Path $destination_file -PathType Leaf)) {
    Write-Host "[+] Replacing dates in the original file... " -NoNewline
    (Get-Content $original_file) | Foreach-Object {
        $_ -replace $day1date, ((Get-Date).AddDays(-3)).ToString("yyyy-MM-dd") `
            -replace $day2date, ((Get-Date).AddDays(-2)).ToString("yyyy-MM-dd")
    } | Set-Content $destination_file
    Write-Host "Completed" -ForegroundColor White -BackgroundColor Green
}
else {
    Write-Host "[+] The original log file has already been processed, and all dates were replaced."

}


Do {
    $Answer = Read-Host -Prompt 'Do you want to start APT29 dataset log uploading? Please note that it will take up to 3 hours. (y/n)'
}
Until ($Answer -eq 'y' -or $Answer -eq 'n')

if ($Answer -eq 'y') {
    Send-AzMonitorCustomLogs -LogPath $destination_file -appId $app.AppId -appSecret $appSecretValue -TenantId $tenantId -DcrImmutableId $dcrImmutableId -DceURI $dceLogIngestionEndpoint -StreamName 'Custom-WindowsEvent' -TimestampField 'EventTime'  -ShowProgressBar
}


Write-Host "[+] Gathering the bearer token for function creation... " -NoNewline
#$scope = [System.Web.HttpUtility]::UrlEncode("https://monitor.azure.com//.default")   
$scope = [System.Web.HttpUtility]::UrlEncode("https://management.azure.com//.default")   
$body = "client_id=$aid&scope=$scope&client_secret=$appSecretValue&grant_type=client_credentials";
$headers = @{"Content-Type" = "application/x-www-form-urlencoded" };
$uriLogin = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
$bearerToken = (Invoke-RestMethod -Uri $uriLogin -Method "Post" -Body $body -Headers $headers).access_token
$headers = @{"Authorization" = "Bearer $bearerToken"; "Content-Type" = "application/json" };
Write-Host "Completed" -ForegroundColor White -BackgroundColor Green

# Creating/validating function
$funcPayload = @{
    properties = @{
        category      = "SentAdvHunting"
        displayName   = "fWindowsEvent"
        version       = 2
        functionAlias = "fWindowsEvent"
        query         = "WindowsEvent | extend _timestamp_ = todatetime(EventData.['@timestamp']) | project-rename TimeIngested = TimeGenerated, TimeGenerated = _timestamp_"
    }
}


$funcPayloadJson = $funcPayload | ConvertTo-Json -Depth 10

try {
    $functionObject = Invoke-RestMethod -Uri $functionUri -Method "Get" -Headers $headers;
    $functionId = $functionObject.id
    
    if (($null -eq $functionId) -or ($functionId -eq "")) {
        Write-Host "[+] Creating a new function... " -NoNewline
        $functionCreateResponse = Invoke-RestMethod -Uri $functionUri -Method "Put" -Body $funcPayloadJson -Headers $headers;
        $functionId = $functionCreateResponse.id
    
        if (($null -eq $functionId) -or ($functionId -eq "")) {
            Write-Host "[!] Error! Function wasn't created." -ForegroundColor White -BackgroundColor Red
            Exit
        }
        else {
            Start-Sleep 30
            Write-Host "Completed" -ForegroundColor White -BackgroundColor Green
        }
    }  
    else {
        Write-Host "[+] The function fWindowsEvent already exists."
    }
}
catch {
    # Create a new function
    Write-Host "[+] Creating a new function... " -NoNewline
    $functionCreateResponse = Invoke-RestMethod -Uri $functionUri -Method "Put" -Body $funcPayloadJson -Headers $headers;
    $functionId = $functionCreateResponse.id
    
    if (($null -eq $functionId) -or ($functionId -eq "")) {
        Write-Host "[!] Error! The function fWindowsEvent wasn't created." -ForegroundColor White -BackgroundColor Red
        Exit
    }
    else {
        Start-Sleep 30
        Write-Host "Completed" -ForegroundColor White -BackgroundColor Green
    }
}

if ((Get-Date) -gt $tokenExpiryDate)
{
    Do {
        $Answer = Read-Host -Prompt 'Your authentication token is expired. You have to re-authenticate to proceed. Are you ready to do it now? (y/n)'
    }
    Until ($Answer -eq 'y' -or $Answer -eq 'n')

    if ($Answer -eq 'y') {
        Connect-AzAccount -ErrorAction Stop | Out-Null
    }
}


#Sentinel's analytic rule creation
$alertRule = ""
$alertRule = Get-AzSentinelAlertRule -ResourceGroupName $resourceGroup -WorkspaceName $workspaceName | Where-Object { $_.DisplayName -eq "$alertRuleName" }

if (($null -eq $alertRule) -or ($alertRule -eq "")) {
    Write-Host "[+] Creating Microsoft Sentinel analytics rule... " -NoNewline
    $alertRule = New-AzSentinelAlertRule -ResourceGroupName $resourceGroup -WorkspaceName $workspaceName -Scheduled -Enabled -DisplayName $alertRuleName -Severity High -Query "fWindowsEvent | where EventID == 4688 | extend NewProcessName =  tostring(EventData.NewProcessName) | where NewProcessName contains ' ' " -QueryFrequency (New-TimeSpan -Hours 1) -QueryPeriod (New-TimeSpan -Days 10) -TriggerThreshold 0 -SuppressionEnabled -SuppressionDuration (New-TimeSpan -Hours 23)
    if (!($null -eq $alertRule))
    {
       Write-Host "Completed" -ForegroundColor White -BackgroundColor Green
    }
}
else {
    Write-Host "[+] Microsoft Sentinel analytics rule is already created."
}



Pop-Location
