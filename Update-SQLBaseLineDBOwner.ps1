# Example as is script, please test before using

$ruleid = "VA1258" 
$exemptdata = @( 'wallstreetkid', 'wizkid', 'sampler')

# Point to the local function created for a wrapper for Express Configuration of SQL DB Vulnerability Assessment
## .psm1 wrapper can be found here: https://learn.microsoft.com/en-us/azure/defender-for-cloud/express-configuration-sql-commands
Import-Module .\SqlVulnerabilityAssessmentCommands.psm1

Connect-AzAccount

$Subs = Get-AzSubscription

# Loop through all subscriptions
Foreach ($Sub in $Subs) {

    # Set the subscription context
    Set-AzContext -Subscription $Sub.Id

    # Get all SQL servers and databases
    $SQLs = Get-AzResource -ResourceType "Microsoft.Sql/servers/databases"

    # Loop through all SQL servers and databases
    foreach ($SQL in $SQLs) { 

        # in the results of the Get-AzResource command the SQL server and database are concatenated with a /, we split them here
        $serverName = $SQL.Name.Split("/")[0]
        $databaseName = $SQL.Name.Split("/")[1]

        # try for classic baseline assessment, in classic there is a storage account referenced, if the sql server\db is in express it will error and we move to the catch
        try {

            # using a -ErrorAction Stop to catch the error and move to the catch block
            Set-AzSqlDatabaseVulnerabilityAssessmentRuleBaseline -ServerName $serverName -DatabaseName $databaseName -RuleId $ruleid -ResourceGroupName $sql.ResourceGroupName -BaselineResult $exemptdata  -ErrorAction Stop
            
        }

        # if you are using a express configuration for the baseline then an erro occurs stating a lack of a storage account, we then try the PS Wrapper commands we imported earlier to update the baseline exempt
        catch {
            Set-SqlVulnerabilityAssessmentBaseline -SubscriptionId $Sub.Id -ResourceGroupName $sql.ResourceGroupName -ServerName $serverName -DatabaseName $databaseName -Body '{
                "properties": {
                "latestScan": false,
                "results": {
                    "VA1258": [
                        [
                            "wallstreetkid"
                        ],
                        [
                            "wizkid"
                        ],
                        [
                            "sampler"
                        ]
                    ]
                }
                }
            }'
        }

    }

    # Untested with SQL MI and databases, remove commentsfor testing and possible further refinement
    <#

    $SQLMIs = Get-AzResource -ResourceType "Microsoft.Sql/managedInstances/databases"

    foreach ($SQLMI in $SQLMIs) { 

        $instanceName = $SQL.Name.Split("/")[0]
        $databaseName = $SQL.Name.Split("/")[1]
        Set-AzSqlInstanceDatabaseVulnerabilityAssessmentRuleBaseline -InstanceName $instanceName -DatabaseName $databaseName -RuleId $ruleid -ResourceGroupName $sql.ResourceGroupName -BaselineResult $exemptdata
        
    }

    #>

}