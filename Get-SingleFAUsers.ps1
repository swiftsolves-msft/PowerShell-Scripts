# Run once if the Graph modules are not installed:
# Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Beta.Reports -Scope CurrentUser -Force

$connection = @{
    Scopes        = "AuditLog.Read.All"
    TenantId      = "ENTER HERE"
    UseDeviceCode = $true
}
Connect-MgGraph @connection

$since = (Get-Date).ToUniversalTime().AddDays(-30).ToString("yyyy-MM-ddTHH:mm:ssZ")
$arm = "797f4846-ba00-4fd7-ba43-dac1f8f63013"
$filter = "createdDateTime ge $since and signInEventTypes/any(t: t eq 'interactiveUser' or t eq 'nonInteractiveUser')"

Get-MgBetaAuditLogSignIn -Filter $filter -All |
    Where-Object {
        $_.ResourceId -eq $arm -and
        $_.AuthenticationRequirement -eq "singleFactorAuthentication" -and
        $_.Status.ErrorCode -eq 0
    } |
    Group-Object UserPrincipalName |
    Select-Object Name, Count, @{
        Name = "Apps"
        Expression = {
            ($_.Group.AppDisplayName | Sort-Object -Unique) -join ", "
        }
    } |
    Sort-Object Count -Descending