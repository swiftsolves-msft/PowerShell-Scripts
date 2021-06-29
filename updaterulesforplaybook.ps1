<#
    .DESCRIPTION
        A script to update all the scheduled sentinel rules to use a specific logic app | useful for a notification or ticket scenario | Use prior to Automation Rules
    .NOTES
        AUTHOR: Nathan Swift
        LASTEDIT: June 29, 2021
        FUTURES: 
        PREREQS: https://www.powershellgallery.com/packages/Az.SecurityInsights/1.0.0
#>

#variables for logic app and azure sentinel workspace
$logicappname = ""
$logicapprgname = ""
$sentinelrgname = ""
$sentinelworkspacename = ""

# load LogicApp playbook Object infromation needed to set on Sentinel Rules
$LogicAppResourceId = Get-AzLogicApp -ResourceGroupName $logicapprgname -Name $logicappname
$LogicAppTriggerUri = Get-AzLogicAppTriggerCallbackUrl -ResourceGroupName $logicapprgname -Name $logicappname -TriggerName "When_a_response_to_an_Azure_Sentinel_alert_is_triggered"

# filtering on only scheduled KQL alaert types
$AlertRules = Get-AzSentinelAlertRule -ResourceGroupName $sentinelrgname -WorkspaceName $sentinelworkspacename | Where-Object {$_.Kind -eq "Scheduled"}

# loop through the alert rules for each alert rule of type scheduled
foreach($AlertRule in $AlertRules) {

    Write-Host "Attempting to Update Rule: " $AlertRule.DisplayName

    # Add a new playbook autopmation to the alert rule firing
    $AlertRuleAction = New-AzSentinelAlertRuleAction -ResourceGroupName $sentinelrgname -WorkspaceName $sentinelworkspacename -AlertRuleId $AlertRule.name -LogicAppResourceId ($LogicAppResourceId.Id) -TriggerUri ($LogicAppTriggerUri.Value)
    
    ## could use similar logic here to update existing playbook with another one: https://docs.microsoft.com/en-us/powershell/module/az.securityinsights/update-azsentinelalertruleaction?view=azps-6.0.0

    Write-Host "Rule: " $AlertRule.DisplayName " LogicAppPlaybook Added as Action: " $AlertRuleAction.LogicAppResourceId


}