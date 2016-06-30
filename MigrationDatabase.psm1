##########################################################################################################
#Utility and Support Functions
##########################################################################################################
function Get-DataTableType
{
[cmdletbinding()]
param(
    $type
)
$types = @(
    'System.Boolean',
    'System.Byte[]',
    'System.Byte',
    'System.Char',
    'System.Datetime',
    'System.Decimal',
    'System.Double',
    'System.Guid',
    'System.Int16',
    'System.Int32',
    'System.Int64',
    'System.Single',
    'System.UInt16',
    'System.UInt32',
    'System.UInt64'
)
if ($types -contains $type)
{ 
    Write-Output "$type" 
} else {
    Write-Output 'System.String' 
} 
}#Function Get-Type
function Convert-PSObjectToDataTable 
{ 
<# 
.SYNOPSIS 
Creates a DataTable for an object 
.DESCRIPTION 
Creates a DataTable based on an objects properties. 
.INPUTS 
Object 
    Any object can be piped to Out-DataTable 
.OUTPUTS 
   System.Data.DataTable 
.EXAMPLE 
$dt = Get-psdrive| Out-DataTable 
This example creates a DataTable from the properties of Get-psdrive and assigns output to $dt variable 
.NOTES 
Adapted from script by Marc van Orsouw see link 
Version History 
v1.0  - Chad Miller - Initial Release 
v1.1  - Chad Miller - Fixed Issue with Properties 
v1.2  - Chad Miller - Added setting column datatype by property as suggested by emp0 
v1.3  - Chad Miller - Corrected issue with setting datatype on empty properties 
v1.4  - Chad Miller - Corrected issue with DBNull 
v1.5  - Chad Miller - Updated example 
v1.6  - Chad Miller - Added column datatype logic with default to string 
v1.7 - Chad Miller - Fixed issue with IsArray 
.LINK 
http://thepowershellguy.com/blogs/posh/archive/2007/01/21/powershell-gui-scripblock-monitor-script.aspx 
#> 
    [CmdletBinding()] 
    param([Parameter(Position=0, Mandatory=$true, ValueFromPipeline = $true)] [PSObject[]]$InputObject) 
 
    Begin 
    { 
        $dt = new-object Data.datatable   
        $First = $true  
    } 
    Process 
    { 
        foreach ($object in $InputObject) 
        { 
            $DR = $DT.NewRow()   
            foreach($property in $object.PsObject.get_properties()) 
            {   
                if ($first) 
                {   
                    $Col =  new-object Data.DataColumn   
                    $Col.ColumnName = $property.Name.ToString()   
                    if ($property.value) 
                    { 
                        if ($property.value -isnot [System.DBNull]) { 
                            $Col.DataType = [System.Type]::GetType("$(Get-DataTableType $property.TypeNameOfValue)") 
                         } 
                    } 
                    $DT.Columns.Add($Col) 
                }   
                if ($property.Gettype().IsArray) { 
                    $DR.Item($property.Name) =$property.value | ConvertTo-XML -AS String -NoTypeInformation -Depth 1 
                }   
               else { 
                    if ($property.value) {
                        $DR.Item($property.Name) = $property.value 
                    } 
                    else {
                        $DR.Item($property.Name) = [DBNull]::Value
                    }
                } 
            }   
            $DT.Rows.Add($DR)   
            $First = $false 
        } 
    }  
      
    End 
    { 
        Write-Output @(,($dt)) 
    } 
 
} #Out-DataTable
function Import-DataTableToSQLBulkCopy
{
[cmdletbinding(SupportsShouldProcess,ConfirmImpact = 'High')]
param
(
[Parameter(Mandatory)]
[string]$SQLTable
,
[Parameter(Mandatory)]
[string]$SQLConnectionName
,
[Parameter(Mandatory)]
[System.Data.DataTable]$DataTable
,
[switch]$ValidateColumnMappings
,
[switch]$TruncateSQLTable
)
$SQLConnection = @($SQLConnections | Where-Object -FilterScript {$_.Name -eq $SQLConnectionName})
switch ($SQLConnection.Count)
{
    1
    {
        $SQLConnection = $SQLConnection[0]
    }
    0
    {
        $message = "No SQL Connection found for SQLConnectionName $SQLConnectionName"
        $NoSQLConnectionError = New-ErrorRecord -Exception System.Management.Automation.RuntimeException -ErrorCategory InvalidArgument -TargetObject $SQLConnectionName -ErrorId 1 -Message $message
        Write-Log -Message $message -ErrorLog
        $PSCmdlet.ThrowTerminatingError($NoSQLConnectionError)
    }
    Default 
    {
        $message = "Ambiguous SQL Connection(s) found for SQLConnectionName $SQLConnectionName"
        $AmbSQLConnectionError = New-ErrorRecord -Exception System.Management.Automation.RuntimeException -ErrorCategory InvalidArgument -TargetObject $SQLConnectionName -ErrorId 1 -Message $message
        Write-Log -Message $message -ErrorLog
        $PSCmdlet.ThrowTerminatingError($AmbSQLConnectionError)
    }
}
$PropertyNames = $DataTable.Columns.ColumnName
#Validate the Columns (compare table columns to datatable object columns)
if ($ValidateColumnMappings)
{
    $TableColumnsQuery = "SELECT name FROM sys.columns WHERE object_id = OBJECT_ID('$($SQLTable)')"
    try
    {
        $message = "Get $SQLTable Column List to validate columns for bulk import"
        Write-Log -Message $message -EntryType Attempting 
        $SQLTableColumns = Invoke-SQLServerQuery -sql $TableColumnsQuery -connection $SQLConnection -ErrorAction Stop | Select-Object -ExpandProperty Name -ErrorAction Stop
        Write-Log -Message $message -EntryType Succeeded 
    }
    catch
    {
        $MyError = $_
        Write-Log -Message $($myerror.ToString()) -ErrorLog
        Write-Log -Message $message -EntryType Failed -Verbose -ErrorLog
        $PSCmdlet.ThrowTerminatingError($myerror)
    }
    $comparisonResults = @(Compare-Object -ReferenceObject $SQLTableColumns -DifferenceObject $PropertyNames -CaseSensitive -ErrorAction Stop)
    if ($comparisonResults.count -ne 0)
    {
        Write-Verbose $comparisonResults
        $error = New-ErrorRecord -Exception System.NotSupportedException -Message "SQL Table $SQLTable columns and DataTable columns do not match." -ErrorCategory InvalidData -TargetObject $SQLTable -ErrorId "1"
        $PSCmdlet.ThrowTerminatingError($error)
    }
}
#Truncate the Staging Table if requested
if ($TruncateSQLTable -and $PSCmdlet.ShouldProcess($SQLTable,'Truncate Table'))
{
    try
    {
        $message = "Truncate Table $SQLTable in Database $($SQLConnection.Database)."
        Write-Log -Message $message -EntryType Attempting 
        Invoke-SQLServerQuery -sql "TRUNCATE TABLE $SQLTable" -connection $SQLConnection -ErrorAction Stop
        Write-Log -Message $message -EntryType Succeeded
    }
    catch
    {
        $MyError = $_
        Write-Log -Message $($myerror.ToString()) -ErrorLog
        Write-Log -Message $message -EntryType Failed -Verbose -ErrorLog
        $PSCmdlet.ThrowTerminatingError($myerror)
    }
}

#Do the Bulk Insert into the Staging Table
$bulkCopy = new-object ("Data.SqlClient.SqlBulkCopy") $($SQLConnection.ConnectionString)
$bulkCopy.ColumnMappings.Clear()
$PropertyNames | foreach {$bulkCopy.ColumnMappings.Add($_,$_) | out-null} 
$bulkCopy.BatchSize = $DataTable.Rows.Count
$bulkCopy.BulkCopyTimeout = 0
$bulkCopy.DestinationTableName = $SQLTable
$bulkCopy.WriteToServer($DataTable)
$bulkCopy.BatchSize = $null
$bulkCopy.ColumnMappings.Clear()
$bulkCopy.Close()
$bulkCopy.Dispose()
}
##########################################################################################################
#Initial Database Configuration
##########################################################################################################
function Initialize-Database
{
[cmdletbinding()]
param
(
[string]$Database = 'MigrationPAndT'
,
[string]$ComputerName = $(hostname.exe)
)
Import-Module -Global -Name POSH_Ado_SQLServer
$SQLServerConnection = New-SQLServerConnection -server $ComputerName
#Add code to check for DB existence: select name from sys.databases
$checkDBs = 'SELECT name FROM sys.databases'
$ExistingDatabases = Invoke-SQLServerQuery -sql $checkDBs -connection $SQLServerConnection
if ($Database -notin $ExistingDatabases)
{
    #Create DB
    $dbcreate = "CREATE DATABASE $Database"
    Invoke-SQLServerQuery -sql $dbcreate -connection $SQLServerConnection
}
#Add Database to SQLServerConnection
$SQLServerConnection.Close()
$SQLServerConnection = New-SQLServerConnection -server $ComputerName -database $Database
#CreateTables
$CreateTableQueries = get-childitem -Path $PSScriptRoot -Filter "CreateTable*.sql"
$ExistingTables = 'SELECT name FROM sys.Tables'
foreach ($query in $CreateTableQueries)
{
    #$TableName = $query.Name.Split('CreateTable')[]
    $sql = Get-Content -Path $query.FullName -Raw
    Invoke-SQLServerQuery -sql $sql -connection $SQLServerConnection
}
}#Function Initialize-SQLDatabase
function Export-AzureADUser
{
[cmdletbinding()]
param
(
)
#Get Data from Azure AD
$SourceOrganization = Get-MsolDomain | Where-Object -FilterScript {$_.IsInitial -eq $true} | Select-Object -ExpandProperty Name
$RawActiveAzureADUsers = Get-MsolUser -All
$RawDeletedAzureADUsers = Get-MsolUser -ReturnDeletedUsers -All
$AllAzureADUsers = $RawActiveAzureADUsers + $RawDeletedAzureADUsers
$MVAttributes = @('AlternateEmailAddresses','AlternateMobilePhones','ProxyAddresses')
$SVAttributes = @('BlockCredential','City','CloudExchangeRecipientDisplayType','Country','Department','DisplayName','Fax','FirstName','ImmutableId','IsBlackberryUser','IsLicensed','LastDirSyncTime','LastName','LastPasswordChangeTimestamp','LicenseReconciliationNeeded','LiveId','MobilePhone','MSExchRecipientTypeDetails','MSRtcSipDeploymentLocator','MSRtcSipPrimaryUserAddress','Office','OverallProvisioningStatus','PasswordNeverExpires','PasswordResetNotRequiredDuringActivate','PhoneNumber','PostalCode','PreferredLanguage','ReleaseTrack','SignInName','SoftDeletionTimestamp','State','StreetAddress','StrongPasswordRequired','StsRefreshTokensValidFrom','Title','UsageLocation','UserLandingPageIdentifierForO365Shell','UserPrincipalName','UserThemeIdentifierForO365Shell','UserType','ValidationStatus','WhenCreated')
$propertyset = Get-CSVExportPropertySet -Delimiter '|' -MultiValuedAttributes $MVAttributes -ScalarAttributes $SVAttributes
$propertyset += @{n='Licenses';e={($_.Licenses | Select-Object -ExpandProperty AccountSkuID) -join '|'}}
$propertyset += @{n='ObjectId';e={$_.ObjectID.guid}}
$propertyset += @{n='ServiceStatus';e={$($_.Licenses | Select-Object -ExpandProperty ServiceStatus | ForEach-Object {"$($_.ServicePlan.ServiceName)=$($_.ProvisioningStatus)"}) -join '|'}}
$propertyset += @{n='SourceOrganization';e={$SourceOrganization}}
$AzureADUsersExport = @($AllAzureADUsers | Select-Object -Property $propertyset)
Write-Output $AzureADUsersExport
}
function Export-ADUser
{
[cmdletbinding()]
param
(
[parameter(Mandatory)]
$SourceAD
,
$Filter
,
$Properties = $(Get-OneShellVariableValue -Name AllADAttributesToRetrieve)
,
$PropertySet
)
#Get Data from Active Directory
#$SourceAD = 'esgc'
Push-Location
Set-Location "$($SourceAD):\"
$RawADUsers = Get-ADUser -LDAPFilter '(&((sAMAccountType=805306368))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' -Properties  $Properties | Select-Object -Property $Properties -ErrorAction SilentlyContinue
Pop-Location
$MVAttributes = @('msExchPoliciesExcluded','msexchextensioncustomattribute1','msexchextensioncustomattribute2','msexchextensioncustomattribute3','msexchextensioncustomattribute4','msexchextensioncustomattribute5','memberof','proxyAddresses')
$SVAttributes = @('altRecipient','forwardingAddress','msExchGenericForwardingAddress','cn','userPrincipalName','sAMAccountName','CanonicalName','GivenName','SurName','DistinguishedName','ObjectGUID','displayName','employeeNumber','employeeID','Mail','mailNickname','homeMDB','homeMTA','msExchHomeServerName','legacyExchangeDN','msExchArchiveGUID','msExchArchiveName','msExchMailboxGUID','msExchMasterAccountSID','msExchUserCulture','targetAddress','msExchRecipientDisplayType','msExchRecipientTypeDetails','msExchRemoteRecipientType','msExchVersion','extensionattribute1','extensionattribute2','extensionattribute3','extensionattribute4','extensionattribute5','extensionattribute6','extensionattribute7','extensionattribute8','extensionattribute9','extensionattribute10','extensionattribute11','extensionattribute12','extensionattribute13','extensionattribute14','extensionattribute15','canonicalname','department','deliverandRedirect','distinguishedName','msExchHideFromAddressLists','msExchUsageLocation','c','co','country','physicalDeliveryOfficeName')
$propertyset = Get-CSVExportPropertySet -Delimiter '|' -MultiValuedAttributes $MVAttributes -ScalarAttributes $SVAttributes 
$propertyset += @{n='mS-DS-ConsistencyGuid';e={(Get-GuidFromByteArray -GuidByteArray $_.'mS-DS-ConsistencyGuid').guid}}
$propertyset += @{n='msExchMailboxGUID';e={(Get-GuidFromByteArray -GuidByteArray $_.msExchMailboxGUID).guid}}
$propertyset += @{n='msExchArchiveGUID';e={(Get-GuidFromByteArray -GuidByteArray $_.msExchArchiveGUID).guid}}
$propertyset += @{n='SourceOrganization';e={$SourceAD}}
$ADUsersexport = @($RawADUsers | Select-Object -Property $propertyset -ExcludeProperty msExchMailboxGUID,msExchArchiveGUID -ErrorAction SilentlyContinue) #,CanonicalName,DistinguishedName)
Write-Output $ADUsersexport
}
function Get-SourceData
{
#Get latest data from SQL 
$SourceData = Invoke-Sqlcmd -Query 'Select * from dbo.MigrationCandidateList' @Global:InvokeSQLParams | Select-Object -Property * -ExcludeProperty Item
}