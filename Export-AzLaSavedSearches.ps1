Login-AzAccount


$rgname = "YOUR RG NAME"
$workspacename = "YOUR WORKSPACE NAME"


$savedsearches = Get-AzOperationalInsightsSavedSearch -ResourceGroupName $rgname -WorkspaceName $workspacename

$LogFilePath = "c:\temp\kql\"

foreach ($savedsearch in $savedsearches.Value) {


    $savedkql = $savedsearch.Properties.Query
    $filename = $savedsearch.Properties.Category + '_-_' + $savedsearch.Properties.DisplayName

    $LogFile = $LogFilePath + $filename + ".txt"
    
    try {
        $run = Write-Output $savedkql | Out-File -FilePath $LogFile -ErrorAction Stop
    }
    catch {
        $newguid = New-Guid
        $filename = $savedsearch.Properties.Category + '_-_' + $newguid
    
        $LogFile = $LogFilePath + $filename + ".txt"
        $run = Write-Output $savedkql | Out-File -FilePath $LogFile
    }

}