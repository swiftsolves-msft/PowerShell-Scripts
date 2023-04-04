Add-Type -AssemblyName System.Web

$appid = 'APP ID'
$tenantId = 'TENANT ID'
$appSecret = 'APP SECRET'

$dcrImmutableId = 'DCR ID HERE'
$dceEndpoint = 'https://DCEENDPOINT.LOCATION-1.ingest.monitor.azure.com'
$streamName = 'STREAM NAME_CL'


$scope = [System.Web.HttpUtility]::UrlEncode("https://monitor.azure.com//.default")
$body = "client_id=$appId&scope=$scope&client_secret=$appSecret&grant_type=client_credentials"
$headers = @{
    'Content-Type' = 'application/x-www-form-urlencoded'
}

$uri = "https://login.microsoftonline.com/$tenantid/oauth2/v2.0/token"

$bearerToken = (Invoke-RestMethod -Uri $uri -Method "Post" -Body $body -Headers $headers).access_token

$staticData = @"
[{ "sourcetype" : "zscalernss-web", "TimeGenerated":"2023-02-17 22:55:01", "act":"Blocked", "reason":"Blocked", "app":"HTTPS", "dhost":"www.etsy.com", "dst":"104.94.233.143", "src":"40.83.138.250", "sourceTranslatedAddress":"10.2.3.4", "in":"50", "out":"10", "request":"www.1etsy.com/dac/common/web-toolkit/scoped/scoped_responsive_base.20220526203537%2csite-chrome/deprecated/global-nav.20220526203537%2ccommon/web-toolkit/a11y_colors/overrides.20220526203537.css", "requestContext":"www.1etsy.com/c/clothing-and-shoes?ref=catnav-10923", "outcome":"200", "requestClientApplication":"Mozilla/5.0 (Windows NT 6.2; Win64; x64; rv:16.0.1) Gecko/20121011 Firefox/21.0.1", "requestMethod":"GET", "suser":"test3@bd-dev.com", "spriv":"Road Warrior", "externalId":"8106135709380313090", "fileType":"GZIP ", "destinationServiceName":"Etsy", "cat":"Professional Services", "deviceDirection":"1", "cn1":"10", "cn1Label":"riskscore", "cs1":"General Group", "cs1Label":"dept", "cs2":"Phishing", "cs2Label":"urlcat", "cs3":"None", "cs3Label":"malwareclass", "cs4":"None", "cs4Label":"malwarecat", "cs5":"Bad_Threat", "cs5Label":"threatname", "cs6":"None", "cs6Label":"md5hash",  "rulelabel":"None", "ruletype":"None", "urlclass":"Advanced Security Risk", "DeviceVendor":"Zscaler" , "DeviceProduct":"NSSWeblog" ,"devicemodel":"Virtual Machine" , "flexString1":"Virtual Machine", "flexString1Label":"devicemodel",  "flexString2":"Advanced Security Risk", "flexString2Label":"urlclass"},{ "sourcetype" : "zscalernss-web", "TimeGenerated":"2023-02-17 22:55:02", "act":"Allowed", "reason":"Allowed", "app":"HTTP_PROXY", "dhost":"c.bing.com", "dst":"204.79.197.200", "src":"40.90.198.229", "sourceTranslatedAddress":"40.90.198.229", "in":"6500", "out":"110", "request":"c.bing.com:443", "requestContext":"None", "outcome":"200", "requestClientApplication":"Windows Microsoft Windows 10 Pro ZTunnel/1.0", "requestMethod":"CONNECT", "suser":"testuser2@bd-dev.com", "spriv":"Road Warrior", "externalId":"7093275726860451849", "fileType":"None", "destinationServiceName":"SharePoint", "cat":"Web Search", "deviceDirection":"1", "cn1":"0", "cn1Label":"riskscore", "cs1":"Service Admin", "cs1Label":"dept", "cs2":"Web Search", "cs2Label":"urlcat", "cs3":"None", "cs3Label":"malwareclass", "cs4":"None", "cs4Label":"malwarecat", "cs5":"None", "cs5Label":"threatname", "cs6":"None", "cs6Label":"md5hash",  "rulelabel":"None", "ruletype":"None", "urlclass":"Business Use", "DeviceVendor":"Zscaler" , "DeviceProduct":"NSSWeblog" , "devicemodel":"Lenovo" ,  "flexString1":"Lenovo", "flexString1Label":"devicemodel",  "flexString2":"Advanced Security Risk", "flexString2Label":"urlclass" },{ "sourcetype" : "zscalernss-web", "TimeGenerated":"2023-02-17 22:55:03", "act":"Blocked", "reason":"Access denied due to bad server certificate", "app":"HTTP_PROXY", "dhost":"hm.baidu.com", "dst":"103.235.46.191", "src":"52.233.90.167", "sourceTranslatedAddress":"52.233.90.167", "in":"65", "out":"55", "request":"ps.eyeota.net/pixel?pid=gdomg51&t=gif&cat=Economy&us_privacy=&random=1654532044229.2", "requestContext":"None", "outcome":"200", "requestClientApplication":"Windows Microsoft Windows 10 Pro ZTunnel/1.0", "requestMethod":"CONNECT", "suser":"test1@bd-dev.com", "spriv":"Road Warrior", "externalId":"9346135709564534789", "fileType":"None ", "destinationServiceName":"General Browsing", "cat":"Web Search", "deviceDirection":"1", "cn1":"0", "cn1Label":"riskscore", "cs1":"General Group", "cs1Label":"dept", "cs2":"Adware/Spyware Sites", "cs2Label":"urlcat", "cs3":"None", "cs3Label":"malwareclass", "cs4":"None", "cs4Label":"malwarecat", "cs5":"None", "cs5Label":"threatname", "cs6":"None", "cs6Label":"md5hash",  "rulelabel":"Inspect_All", "ruletype":"SSLPol", "urlclass":"Business Use", "DeviceVendor":"Zscaler" , "DeviceProduct":"NSSWeblog" ,"devicemodel":"macbookpro",  "flexString1":"macbookpro", "flexString1Label":"devicemodel",  "flexString2":"Advanced Security Risk", "flexString2Label":"urlclass" }]
"@;


$body = $staticData;
$headers = @{"Authorization"="Bearer $bearerToken";"Content-Type"="application/json"};
$uri = "$dceEndpoint/dataCollectionRules/$dcrImmutableId/streams/$streamName" + "?api-version=2021-11-01-preview"
$uploadResponse = Invoke-RestMethod -Uri $uri -Method "Post" -Body $body -Headers $headers