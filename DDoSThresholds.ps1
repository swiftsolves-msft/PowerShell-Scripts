# Outputfile for ddos thresholds

$path = "C:\temp\ddosthresholds.txt"
$csvpath = "C:\temp\ddosthresholds.csv"
$outputFile = $path

#Set and apply 1st line of csv headers
$string = "PublicIpName,SYN-PPSThreshold,TCP-PPSThreshold,UDP-PPSThreshold,AzureSubscription,AttachedType,ResourceAttachedName,PublicIpResourceId"
$string | Out-File $outputFile -append -force

# get all Azure subscriptions to check
$Subs = Get-AzSubscription

# For each subscription check Public Ips and Metrics
foreach($sub in $subs){

    #Set Azure Subscription Contect to current subscription in loop
    Set-AzContext -Subscription $sub.Id

    # get all Pulic IP Addresses
    $PIPs = Get-AzPublicIpAddress

    #Check for each public IP for DDoS Metrics and record
    foreach($PIP in $PIPs){

        # Check for SYN,TCP,UDP Thresholds in Azure Metrics
        $syntrigger = (Get-AzMetric -ResourceId $PIP.Id -MetricName DDoSTriggerSYNPackets).Data
        $tcptrigger = (Get-AzMetric -ResourceId $PIP.Id -MetricName DDoSTriggerTCPPackets).Data
        $udptrigger = (Get-AzMetric -ResourceId $PIP.Id -MetricName DDoSTriggerUDPPackets).Data

        # Check IF the metric has data if so then write and record maximium threshold. ## NOTE you could add other fields like TimeStamp, Minimum, Average, Total, Count - not sure these contain data ?
        if($syntrigger -ne $null){
    
            Write-Host $PIP.Name " SYN Packets to Trigger" -ForegroundColor Cyan

            #grab the latest entry from last hour at array item 59
            Write-Host "Max " $syntrigger[59].Maximum
    
        }

        if($tcptrigger -ne $null){
    
            Write-Host $PIP.Name " TCP Packets to Trigger" -ForegroundColor Yellow

            #grab the latest entry from last hour at array item 59
            Write-Host "Max " $tcptrigger[59].Maximum
    
        }

        if($tcptrigger -ne $null){
    
            Write-Host $PIP.Name " UDP Packets to Trigger" -ForegroundColor Green

            #grab the latest entry from last hour at array item 59
            Write-Host "Max " $udptrigger[59].Maximum
    
            #Write into and append into output file
            $string = "$($PIP.Name),$($syntrigger[59].Maximum),$($tcptrigger[59].Maximum),$($udptrigger[59].Maximum),$($Sub.Name),$(($PIP.IpConfiguration.Id).Split('/')[7]),$(($PIP.IpConfiguration.Id).Split('/')[8]),$($PIP.Id)"
            $string | Out-File $outputFile -append -force
        }

    }

}

# Once done import the data into excel

$CSV = Import-Csv -Path $path
$CSV | Export-Csv -Path $csvpath -NoTypeInformation
