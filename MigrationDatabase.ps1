function Get-DataTableType 
{ 
    param($type) 
 
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
'System.UInt64') 
 
    if ( $types -contains $type ) { 
        Write-Output "$type" 
    } 
    else { 
        Write-Output 'System.String' 
         
    } 
} #Get-Type 
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
[string]$SQLTable
,
$Database = $MigrationDatabaseSQLDB
,
[string]$ConnectionString = $ConnectionString
,
[System.Data.DataTable]$DataTable
,
[switch]$ValidateColumnMappings
,
[switch]$TruncateSQLTable
)
$PropertyNames = $DataTable.Columns.ColumnName
if ($ValidateColumnMappings)
{
    $TableColumnsQuery = "SELECT name FROM sys.columns WHERE object_id = OBJECT_ID('$($SQLTable)')"
    try
    {
        $message = "Get $SQLTable Column List to validate columns for bulk import"
        Write-Log -Message $message -EntryType Attempting 
        $SQLTableColumns = Invoke-Sqlcmd -Query $TableColumnsQuery @InvokeSQLCMDParams -ErrorAction Stop | Select-Object -ExpandProperty Name -ErrorAction Stop
        Write-Log -Message $message -EntryType Succeeded 
    }
    catch
    {
        $MyError = $error[0]
        Write-Log -Message $($myerror.ToString()) -ErrorLog
        Write-Log -Message $message -EntryType Failed -Verbose -ErrorLog
        $PSCmdlet.ThrowTerminatingError($myerror)
    }
    $comparisonResults = @(Compare-Object -ReferenceObject $SQLTableColumns -DifferenceObject $PropertyNames -CaseSensitive)
    if ($comparisonResults.count -ne 0)
    {
        Write-Verbose $comparisonResults
        $error = New-ErrorRecord -Exception System.NotSupportedException -Message "SQL Table $SQLTable and export data from this function do not match." -ErrorCategory InvalidData -TargetObject $SQLTable -ErrorId "1"
        $PSCmdlet.ThrowTerminatingError($error)
    }
}
#Truncate the Staging Table
if ($TruncateSQLTable -and $PSCmdlet.ShouldProcess($SQLTable,'Truncate Table'))
{
    Invoke-Sqlcmd @InvokeSQLCMDParams -query "TRUNCATE TABLE $SQLTable"
}

#Do the Bulk Insert into the Staging Table
$bulkCopy.ColumnMappings.Clear()
$PropertyNames | foreach {$bulkCopy.ColumnMappings.Add($_,$_) | out-null} 
$bulkCopy.BatchSize = $DataTable.Rows.Count
$bulkCopy.BulkCopyTimeout = 0
$bulkCopy.DestinationTableName = $SQLTable
$bulkCopy.WriteToServer($DataTable)
$bulkCopy.BatchSize = $null
$bulkCopy.ColumnMappings.Clear()
}
function Initialize-SQLConnection
{
[cmdletbinding()]
param
(
$Database = 'MigrationPAndT'
,
[string]$ComputerName= 'USGVLW10-01'
,
[string]$Instance
)
import-module SQLPS -DisableNameChecking -Force -Global
[string]$Global:MigrationDatabaseSQLServer=$ComputerName
[string]$Global:MigrationDatabaseSQLDB=$Database
#Setup Invoke-SQLCMDParams
$Global:InvokeSQLCMDParams=@{
    ServerInstance = $MigrationDatabaseSQLServer
    Database = $MigrationDatabaseSQLDB
}
#Setup SQL Connection String for non-InvokeSQLCmd activities
$Global:SQLConnectionString = "Server=$MigrationDatabaseSQLServer,1433;Database=$MigrationDatabaseSQLDB;Trusted_Connection=True;Connection Timeout=30;"
$Global:bulkCopy = new-object ("Data.SqlClient.SqlBulkCopy") $Global:SQLConnectionString
$Global:bulkCopy.BulkCopyTimeout = 0
}
function Export-AzureUsers
{
param(
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
#Compare Retrieved Data with Table Columns and alert admin of problems
$AzureADUsersExport
}
function Initialize-SQLDatabase
{
[cmdletbinding()]
param
(
[string]$SQLDatabase = 'MigrationPAndT'
,
[string]$ComputerName = $(hostname.exe)

)
import-module SQLPS 
[string]$MigrationDatabaseSQLServer=$SQLServer
[string]$MigrationDatabaseSQLDB='MigrationPAndT'
$InvokeSQLParams=@{
    ServerInstance = $MigrationDatabaseSQLServer
}
#Create DB
$dbcreate = "CREATE DATABASE $MigrationDatabaseSQLDB"
Invoke-Sqlcmd -Query $dbcreate @InvokeSQLParams
#Add DB to InvokeSQLParams
$InvokeSQLParams.Database = $MigrationDatabaseSQLDB
#CreateTables
$query = Get-Content -Path C:\Users\mike\OneDrive\Projects\Emdeon\CreateAzureUsersStagingTable.sql -Raw
Invoke-Sqlcmd -Query $query @InvokeSQLParams
}
function Get-SourceData
{
#Get latest data from SQL 
$SourceData = Invoke-Sqlcmd -Query 'Select * from dbo.MigrationCandidateList' @Global:InvokeSQLParams | Select-Object -Property * -ExcludeProperty Item
}

