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
}#Function Get-DataTableType
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
param
(
[Parameter(Position=0, Mandatory=$true, ValueFromPipeline = $true)]
[PSObject[]]$InputObject
) 
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
            if ($property.Gettype().IsArray) 
            {
                    $DR.Item($property.Name) =$property.value | ConvertTo-XML -AS String -NoTypeInformation -Depth 1
            }
            else
            {
                if ($property.value)
                {
                    $DR.Item($property.Name) = $property.value
                }
                else
                {
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
}#Convert-PSObjectToDataTable
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
        Write-Output $comparisonResults
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
}#Import-DataTableToSQLBulkCopy
function New-PermissionExportObject
{
[cmdletbinding()]
param(
[parameter(Mandatory)]
$TargetMailbox
,
[parameter(Mandatory)]
[string]$PermissionHolderIdentity
,
[parameter(Mandatory)]
[ValidateSet('FullAccess','SendOnBehalf','SendAs','None')]
$PermissionType
,
[parameter()]
[ValidateSet('Direct','GroupMembership','None')]
[string]$AssignmentType = 'Direct'
,
$PermissionGroupObjectGUID
)
[pscustomobject]@{
    TargetObjectGUID = $TargetMailbox.Guid.Guid
    TargetDistinguishedName = $TargetMailbox.DistinguishedName
    TargetPrimarySMTPAddress = $TargetMailbox.PrimarySmtpAddress.ToString()
    TargetRecipientType = $TargetMailbox.RecipientType
    TargetRecipientTypeDetails = $TargetMailbox.RecipientTypeDetails
    PermissionType = $PermissionType
    PermissionAssignmentType = $AssignmentType
    PermissionGroupObjectGUID = $PermissionGroupObjectGUID
    PermissionHolderIdentity = $PermissionHolderIdentity
}
}
##########################################################################################################
#Initial Database Configuration
##########################################################################################################
function Initialize-MigrationDatabase
{
[cmdletbinding()]
param
(
[string]$Database = 'MigrationPAndT'
,
[string]$ComputerName = $(hostname.exe)
)
$SQLServerConnection = New-SQLServerConnection -server $ComputerName
#Add code to check for DB existence: select name from sys.databases
$ExistingDatabasesQuery = 'SELECT name FROM sys.databases'
$ExistingDatabases = Invoke-SQLServerQuery -sql $ExistingDatabasesQuery -connection $SQLServerConnection | Select-Object -ExpandProperty Name
$ExistingDatabasesJoin = $ExistingDatabases -join ';'
Write-Log -Message "Existing Databases on Server $Computername are: $ExistingDatabasesJoin" -EntryType Notification
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
$CreateTableQueries = get-childitem -Path $PSScriptRoot -Filter "CreateTable_*.sql"
$ExistingTablesQuery = 'SELECT name FROM sys.Tables'
$ExistingTables = Invoke-SQLServerQuery -sql $ExistingTablesQuery -connection $SQLServerConnection | Select-Object -ExpandProperty Name
$ExistingTablesJoin = $ExistingTables -join ';'
Write-Log -Message "Existing Tables in Database $Database are: $ExistingTablesJoin" -EntryType Notification
foreach ($query in $CreateTableQueries)
{
    $TableName = $query.Name.Split('_')[1].split('.')[0]
    if ($TableName -notin $ExistingTables)
    {
        $message = "Create $TableName in $Database"
        try
        {
            Write-Log -Message $message -EntryType Attempting
            $sql = Get-Content -Path $query.FullName -Raw -ErrorAction Stop
            Invoke-SQLServerQuery -sql $sql -connection $SQLServerConnection -ErrorAction Stop
            Write-Log -Message $message -EntryType Succeeded
        }
        catch
        {
            $MyError = $_
            Write-Log -Message $message -EntryType Failed -ErrorLog -Verbose
            Write-Log -Message $MyError.tostring() -ErrorLog
        }
    }
    
}
}#Function Initialize-MigrationDatabase
##########################################################################################################
#Export From Source Systems Functions
##########################################################################################################
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
#$Filter
#,
$Properties = @(Get-OneShellVariable -Name ADUserAttributes | Select-Object -ExpandProperty Value)
#,
#$PropertySet
)
Connect-ADInstance -ActiveDirectoryInstance $SourceAD > $null
#Get Data from Active Directory
Push-Location
Set-Location "$($SourceAD):\"
$RawADUsers = Get-ADUser -LDAPFilter '(&((sAMAccountType=805306368))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' -Properties  $Properties | Select-Object -Property $Properties -ErrorAction SilentlyContinue
Pop-Location
$MVAttributes = @('msExchPoliciesExcluded','msexchextensioncustomattribute1','msexchextensioncustomattribute2','msexchextensioncustomattribute3','msexchextensioncustomattribute4','msexchextensioncustomattribute5','memberof','proxyAddresses')
$SVAttributes = @('createTimeStamp','modifyTimeStamp','msExchWhenMailboxCreated','whenCreated','whenChanged','AccountExpirationDate','LastLogonDate','altRecipient','forwardingAddress','msExchGenericForwardingAddress','cn','userPrincipalName','sAMAccountName','CanonicalName','GivenName','SurName','DistinguishedName','displayName','employeeNumber','employeeID','enabled','Mail','mailNickname','homeMDB','homeMTA','msExchHomeServerName','legacyExchangeDN','msExchArchiveName','msExchMasterAccountSID','msExchUserCulture','targetAddress','msExchRecipientDisplayType','msExchRecipientTypeDetails','msExchRemoteRecipientType','msExchVersion','extensionattribute1','extensionattribute2','extensionattribute3','extensionattribute4','extensionattribute5','extensionattribute6','extensionattribute7','extensionattribute8','extensionattribute9','extensionattribute10','extensionattribute11','extensionattribute12','extensionattribute13','extensionattribute14','extensionattribute15','canonicalname','department','deliverandRedirect','distinguishedName','msExchHideFromAddressLists','msExchUsageLocation','c','co','country','physicalDeliveryOfficeName','company','city','notes')
$propertyset = Get-CSVExportPropertySet -Delimiter '|' -MultiValuedAttributes $MVAttributes -ScalarAttributes $SVAttributes 
$propertyset += @{n='mS-DS-ConsistencyGuid';e={(Get-GuidFromByteArray -GuidByteArray $_.'mS-DS-ConsistencyGuid').guid}}
$propertyset += @{n='msExchMailboxGUID';e={(Get-GuidFromByteArray -GuidByteArray $_.msExchMailboxGUID).guid}}
$propertyset += @{n='msExchArchiveGUID';e={(Get-GuidFromByteArray -GuidByteArray $_.msExchArchiveGUID).guid}}
$propertyset += @{n='ObjectGUID';e={$_.ObjectGUID.guid}}
$propertyset += @{n='SourceOrganization';e={$SourceAD}}
$ADUsersexport = @($RawADUsers | Select-Object -Property $propertyset -ErrorAction SilentlyContinue) # -ExcludeProperty ObjectGUID,msExchMailboxGUID,msExchArchiveGUID,CanonicalName,DistinguishedName)
Write-Output $ADUsersexport
}
function Export-ExchangeRecipient
{
[cmdletbinding()]
param
(
[parameter(Mandatory)]
$ExchangeOrganization
#,
#$Filter
#,
#$PropertySet
)
Connect-Exchange -ExchangeOrganization $ExchangeOrganization > $null
$Splat = @{
    ResultSize = 'Unlimited'
}
$RawRecipients = Invoke-ExchangeCommand -ExchangeOrganization $ExchangeOrganization -cmdlet 'Get-Recipient' -splat $Splat
$MVAttributes = @('AddressListMembership','Capabilities','ExtensionCustomAttribute1','ExtensionCustomAttribute2','ExtensionCustomAttribute3','ExtensionCustomAttribute4','ExtensionCustomAttribute5','EmailAddresses','ManagedBy','ObjectClass','PoliciesExcluded','PoliciesIncluded')
$SVAttributes = @('ActiveSyncMailboxPolicy','ActiveSyncMailboxPolicyIsDefaulted','AddressBookPolicy','Alias','ArchiveDatabase','ArchiveState','AuthenticationType','City','Company','CountryOrRegion','CustomAttribute1','CustomAttribute10','CustomAttribute11','CustomAttribute12','CustomAttribute13','CustomAttribute14','CustomAttribute15','CustomAttribute2','CustomAttribute3','CustomAttribute4','CustomAttribute5','CustomAttribute6','CustomAttribute7','CustomAttribute8','CustomAttribute9','Database','DatabaseName','Department','DisplayName','DistinguishedName','EmailAddressPolicyEnabled','ExchangeVersion','ExpansionServer','ExternalDirectoryObjectId','ExternalEmailAddress','FirstName','HasActiveSyncDevicePartnership','HiddenFromAddressListsEnabled','Identity','IsValid','IsValidSecurityPrincipal','LastName','LitigationHoldEnabled','MailboxMoveBatchName','MailboxMoveFlags','MailboxMoveRemoteHostName','MailboxMoveSourceMDB','MailboxMoveStatus','MailboxMoveTargetMDB','ManagedFolderMailboxPolicy','Manager','Name','Notes','ObjectCategory','Office','OrganizationalUnit','OrganizationId','OriginatingServer','OwaMailboxPolicy','Phone','PostalCode','PrimarySmtpAddress','PSComputerName','PSShowComputerName','RecipientType','RecipientTypeDetails','ResourceType','RetentionPolicy','SamAccountName','ServerLegacyDN','ServerName','SharingPolicy','SKUAssigned','StateOrProvince','StorageGroupName','Title','UMEnabled','UMMailboxPolicy','UMRecipientDialPlanId','UsageLocation','WhenChanged','WhenChangedUTC','WhenCreated','WhenCreatedUTC','WhenMailboxCreated','WindowsLiveID')
$propertyset = Get-CSVExportPropertySet -Delimiter '|' -MultiValuedAttributes $MVAttributes -ScalarAttributes $SVAttributes 
$propertyset += @{n='Guid';e={$_.GUID.guid}}
$propertyset += @{n='ArchiveGuid';e={$_.ArchiveGuid.guid}}
$propertyset += @{n='SourceOrganization';e={$ExchangeOrganization}}
$ExchangeRecipientsExport = @($RawRecipients | Select-Object -Property $propertyset) #-ErrorAction SilentlyContinue
Write-Output $ExchangeRecipientsExport
}
function Export-MailboxStatistics
{
[cmdletbinding()]
param
(
[parameter(Mandatory)]
$ExchangeOrganization
#,
#$Filter
#,
#$PropertySet
)
Connect-Exchange -ExchangeOrganization $ExchangeOrganization > $null
$GetMailboxDatabaseSplat = @{
    Status = $true
    ErrorAction = 'Stop'
}
$MailboxDatabases = Invoke-ExchangeCommand -ExchangeOrganization $ExchangeOrganization -cmdlet 'Get-MailboxDatabase' -splat $GetMailboxDatabaseSplat
$MountedMailboxDatabases = $MailboxDatabases | Where-Object -FilterScript {$_.Mounted -eq $true}
$RawMailboxStatistics = @(
    foreach ($mmd in $MountedMailboxDatabases)
    {
        $GetMailboxStatisticsSplat = @{Database = $mmd.name}
        Invoke-ExchangeCommand -ExchangeOrganization $ExchangeOrganization -cmdlet 'Get-MailboxStatistics' -splat $GetMailboxStatisticsSplat
    }
)
# $MVAttributes = @() # None needed for this data
$SVAttributes = @('AssociatedItemCount','Database','DatabaseName','DeletedItemCount','DisconnectDate','DisconnectReason','DisplayName','IsArchiveMailbox','IsQuarantined','IsValid','ItemCount','LastLoggedOnUserAccount','LastLogoffTime','LastLogonTime','LegacyDN','MailboxGuid','MailboxTableIdentifier','MapiIdentity','ObjectClass','ServerName','StorageLimitStatus','TotalItemSize','TotalDeletedItemSize')
$propertyset = Get-CSVExportPropertySet -Delimiter '|' -ScalarAttributes $SVAttributes 
$PropertySet += @{n='TotalItemSizeInBytes';e={$_.TotalItemSize.ToString().split(('(',')'))[1].replace(',','').replace(' bytes','') -as [long]}}
$PropertySet += @{n='TotalDeletedItemSizeInBytes';e={$_.TotalDeletedItemSize.ToString().split(('(',')'))[1].replace(',','').replace(' bytes','') -as [long]}}
$PropertySet += @{n='TotalItemSizeInGB';e={[math]::Round(($_.TotalItemSize.ToString().split(('(',')'))[1].replace(',','').replace(' bytes','') -as [single])/1GB,3)}}
$PropertySet += @{n='TotalDeletedItemSizeInGB';e={[math]::Round(($_.TotalDeletedItemSize.ToString().split(('(',')'))[1].replace(',','').replace(' bytes','') -as [single])/1GB,3)}}
$propertyset += @{n='Identity';e={$_.Identity.guid}}
$propertyset += @{n='MailboxGuid';e={$_.MailboxGuid.guid}}
$propertyset += @{n='SourceOrganization';e={$ExchangeOrganization}}
$MailboxStatisticsExport = @($RawMailboxStatistics | Select-Object -Property $propertyset -ExcludeProperty Identity,MailboxGuid) #-ErrorAction SilentlyContinue
Write-Output $MailboxStatisticsExport
}
Function Export-Permissions
{
#ToDo
#Add an attribute to the permission object which indicates if the target/permholder were in the mailboxes scope
#switch ExchangeOrganization to a dynamic parameter
#use get-group and/or get-user when get-recipient fails to get an object
#move code to add additional attributes to export object to a new function or update the existin function
[cmdletbinding(DefaultParameterSetName = 'AllMailboxes')]
param(
    [string]$ExchangeOrganization
    ,
    [parameter(ParameterSetName = 'Scoped',Mandatory)]
    [string[]]$Identity
    ,
    [Parameter(ParameterSetName = 'AllMailboxes',Mandatory)]
    [boolean]$AllMailboxes = $true
    ,
    [parameter()]
    [string[]]$ExcludedIdentities
    ,
    [boolean]$IncludeSendOnBehalf = $true
    ,
    [boolean]$IncludeFullAccess = $true
    ,
    [boolean]$IncludeSendAs = $true
    ,
    [boolean]$expandGroups = $true
    ,
    [boolean]$dropExpandedGroups = $false
)
Connect-Exchange -ExchangeOrganization $ExchangeOrganization > $null
#Region GetInScopeMailboxes
switch ($PSCmdlet.ParameterSetName)
{
    'Scoped'
    { 
        Write-Log -Message "Operation: Scoped Permission retrieval with $($Identity.Count) Identities provided." -Verbose
        $message = "Retrieve mailbox object for each provided Identity in Exchange Organization $ExchangeOrganization."
        Write-Log -Message $message -EntryType Attempting -Verbose
        $Set = @($Identity | % {
                $splat = @{Identity = $_}
                Invoke-ExchangeCommand -ExchangeOrganization $ExchangeOrganization -cmdlet 'Get-Mailbox' -splat $splat
            }
        )
        Write-Log -Message $message -EntryType Succeeded -Verbose
    }
    'AllMailboxes'
    {
        Write-Log -Message "Operation: Permission retrieval for all mailboxes." -Verbose
        $message = "Retrieve all available mailbox objects in Exchange Organization $ExchangeOrganization."
        Write-Log -Message $message -EntryType Attempting -Verbose
        $splat = @{ResultSize = 'Unlimited'}
        $Set = @(Invoke-ExchangeCommand -ExchangeOrganization $ExchangeOrganization -cmdlet 'Get-Mailbox' -splat $splat)
        Write-Log -Message $message -EntryType Succeeded -Verbose
    }
}
#EndRegion GetInScopeMailboxes
if ($PSBoundParameters.ContainsKey('ExcludedIdentities'))
{
    $excludedPermissionHolders = @(
        $ExcludedIdentities | ForEach-Object {
            $splat = @{
                Identity = $_
                ErrorAction = 'SilentlyContinue'
            }
            Invoke-ExchangeCommand -ExchangeOrganization $ExchangeOrganization -cmdlet 'Get-Recipient' -splat $splat
        }
    )
    $excludedPermissionHoldersGUIDHash = $excludedPermissionHolders | Group-Object -Property GUID -AsString -AsHashTable
}
#ADSI Adapter: http://social.technet.microsoft.com/wiki/contents/articles/4231.working-with-active-directory-using-powershell-adsi-adapter.aspx
$dse = [ADSI]"LDAP://Rootdse"
$ext = [ADSI]("LDAP://CN=Extended-Rights," + $dse.ConfigurationNamingContext)
$dn = [ADSI]"LDAP://$($dse.DefaultNamingContext)"
$dsLookFor = new-object System.DirectoryServices.DirectorySearcher($dn)
$permission = "Send As"
$right = $ext.psbase.Children | ? { $_.DisplayName -eq $permission }
$CanonicalNameHash = @{}
$DomainPrincipalHash = @{}
$DistinguishedNameHash = $Set | Group-Object -AsHashTable -Property DistinguishedName -AsString
$MissingOrAmbiguousRecipients = @()
$mailboxCounter = 0
$setSize = $set.count
Foreach ($mailbox in $Set)
{
    if ($PSBoundParameters.ContainsKey('ExcludedIdentities'))
    {
        if ($excludedPermissionHoldersGUIDHash.ContainsKey($mailbox.guid.Guid))
        {
            continue
        }
    }
    #GatherPermissions
	#Progress Activity
    if($setSize -gt 0){
        $mailboxCounter++
        Write-Progress -Activity "Retrieving Permissions" -status "Items processed: $($mailboxCounter) of $($setSize)" -percentComplete (($mailboxCounter / $setSize)*100)
    }
    $ID = $mailbox.PrimarySMTPAddress.ToString();
    $message = "Collect permissions for $($ID)"
	Write-Log -Message $message -EntryType Attempting -Verbose
    $rawPermissions = @(
        #Get Delegate Users (actual permissions are stored in the mailbox . . . so these are not true delegates just a likely correlation to delegates) This section should also check if the grantsendonbehalfto permission holder is a group, because it can be . . .
        If ($IncludeSendOnBehalf)
        {
            $sbPermissionHolders = $mailbox.grantsendonbehalfto.ToArray()
            foreach ($sb in $sbPermissionHolders)
            {
                New-PermissionExportObject -TargetMailbox $mailbox -PermissionHolderIdentity $sb -PermissionType SendOnBehalf -AssignmentType Direct
            }
        }
        #Get Full Access Users
        If ($IncludeFullAccess)
        {
            $faPermissionHolders = @(
                $splat = @{Identity = $ID; ErrorAction = 'SilentlyContinue'}
                Invoke-ExchangeCommand -ExchangeOrganization $ExchangeOrganization -cmdlet 'Get-MailboxPermission' -splat $splat |
                Where-Object -FilterScript {
                    ($_.AccessRights -like �*FullAccess*�) -and 
                    ($_.IsInherited -eq $false) -and -not 
                    ($_.User -like �NT AUTHORITY\SELF�) -and -not 
                    ($_.User -like "S-1-5*")
                } | Select-Object -ExpandProperty User
            )
            foreach ($fa in $faPermissionHolders)
            {
                New-PermissionExportObject -TargetMailbox $mailbox -PermissionHolderIdentity $fa -PermissionType FullAccess -AssignmentType Direct
            }
        }
        #Get Send As Users
        If ($IncludeSendAs)
        {
            $userDN = [ADSI]("LDAP://$($mailbox.DistinguishedName)")
            $saPermissionHolders = @(
                $userDN.psbase.ObjectSecurity.Access | Where-Object -FilterScript { $_.ObjectType -eq [GUID]$right.RightsGuid.Value } | 
                Select-Object -ExpandProperty identityreference | Where-Object -FilterScript {$_ -notlike "NT AUTHORITY\SELF"}
            )
            foreach ($sa in $saPermissionHolders)
            {
                New-PermissionExportObject -TargetMailbox $mailbox -PermissionHolderIdentity $sa -PermissionType SendAs -AssignmentType Direct
            }
		}
    )
    #compile permissions information and permission holders identity details
    foreach ($rp in $rawPermissions)
    {
        $Recipient = @()
        switch ($rp.PermissionType)
        {
            'SendOnBehalf' #uses CanonicalName format!?!
            {
                if ($CanonicalNameHash.ContainsKey($rp.PermissionHolderIdentity))
                {
                    $Recipient = @($CanonicalNameHash.$($rp.PermissionHolderIdentity))
                }
            }
            Default #both SendAs and FullAccess use Domain\SecurityPrincipal format
            {
                if ($DomainPrincipalHash.ContainsKey($rp.PermissionHolderIdentity))
                {
                    $Recipient = @($DomainPrincipalHash.$($rp.PermissionHolderIdentity))
                }
            }
        }
        if ($Recipient.Count -eq 0)
        {
            $splat = @{Identity = $rp.PermissionHolderIdentity; ErrorAction = 'SilentlyContinue'}
            $Recipient = @(Invoke-ExchangeCommand -ExchangeOrganization $ExchangeOrganization -cmdlet 'Get-Recipient' -splat $splat)
        }
        switch ($Recipient.Count)
        {
            1
            {
                $Recipient = $Recipient[0]
                $MorePermissionExportProperties = @{
                    PermissionHolderObjectGUID = $Recipient.guid.Guid
                    PermissionHolderDistinguishedName = $Recipient.DistinguishedName
                    PermissionHolderPrimarySMTPAddress = $Recipient.PrimarySmtpAddress.ToString()
                    PermissionHolderRecipientType = $Recipient.RecipientType
                    PermissionHolderRecipientTypeDetails = $Recipient.RecipientTypeDetails
                }
                Add-Member -InputObject $rp -NotePropertyMembers $MorePermissionExportProperties
                switch ($rp.permissionType) {
                    'SendOnBehalf' {$CanonicalNameHash.$($rp.PermissionHolderIdentity) = $Recipient}
                    Default {$DomainPrincipalHash.$($rp.PermissionHolderIdentity) = $Recipient}
                }
            }#1
            Default
            {
                $MissingOrAmbiguousRecipients += $rp.PermissionHolderIdentity
                $MorePermissionExportProperties = @{
                    PermissionHolderObjectGUID = $null
                    PermissionHolderDistinguishedName = $null
                    PermissionHolderPrimarySMTPAddress = $null
                    PermissionHolderRecipientType = $null
                    PermissionHolderRecipientTypeDetails = $null
                }
                Add-Member -InputObject $rp -NotePropertyMembers $MorePermissionExportProperties
            }#Default
        }#switch Recipient.Count
    }#foreach Rp in RawPermissions
    if ($expandGroups)
    {
        #enumerate groups: http://stackoverflow.com/questions/8055338/listing-users-in-ad-group-recursively-with-powershell-script-without-cmdlets/8055996#8055996
        $expandedPermissions = @(
            $groupPerms = @($rawPermissions | Where-Object -FilterScript {$_.PermissionHolderRecipientTypeDetails -like '*Group*'})
            foreach ($gp in $groupPerms)
            {
                $dsLookFor.Filter = "(&(memberof:1.2.840.113556.1.4.1941:=$($gp.PermissionHolderDistinguishedName))(objectCategory=user))" 
                $dsLookFor.SearchScope = "subtree" 
                $lstUsr = $dsLookFor.findall()
                foreach ($u in $lstUsr)
                {
                    $uDN = $u.Properties.distinguishedname
                    if ($DistinguishedNameHash.ContainsKey("$uDN"))
                    {$Recipient = @($DistinguishedNameHash."$uDN")}
                    else
                    {
                        $splat = @{Identity = "$uDN"; ErrorAction = 'SilentlyContinue'}
                        $Recipient = @(Invoke-ExchangeCommand -ExchangeOrganization $ExchangeOrganization -cmdlet 'Get-Recipient' -splat $splat)
                    }
                    switch ($Recipient.count)
                    {
                        1
                        {
                            $Recipient = $Recipient[0]
                            $GPEOParams = @{
                                TargetMailbox = $Mailbox
                                PermissionHolderIdentity = $Recipient.DistinguishedName
                                PermissionType = $gp.PermissionType
                                AssignmentType = 'GroupMembership'
                                PermissionGroupObjectGUID = $gp.PermissionHolderObjectGUID 
                            }
                            $rawEP = New-PermissionExportObject @GPEOParams
                            $MorePermissionExportProperties = @{
                                PermissionHolderObjectGUID = $Recipient.guid.Guid
                                PermissionHolderDistinguishedName = $Recipient.DistinguishedName
                                PermissionHolderPrimarySMTPAddress = $Recipient.PrimarySmtpAddress.ToString()
                                PermissionHolderRecipientType = $Recipient.RecipientType
                                PermissionHolderRecipientTypeDetails = $Recipient.RecipientTypeDetails
                            }
                            Add-Member -InputObject $rawEP -NotePropertyMembers $MorePermissionExportProperties
                            Write-Output $rawEP
                            $DistinguishedNameHash.$uDN = $Recipient
                        }#1
                        Default
                        {
                            $MissingOrAmbiguousRecipients += $rp.PermissionHolderIdentity
                        }#Default
                    }#switch Recipient.Count
                }#foreach u in lstusr
            }#foreach gp in groupPerms
        )#expandedPermissions
        if ($dropExpandedGroups)
        {
            $rawPermissions = $rawPermissions | Where-Object -FilterScript {$_.PermissionHolderRecipientTypeDetails -notlike '*group*'}
        }
    }
    #combine and remove and self permissions that came in through expansion or otherwise
    if ($expandedPermissions.Count -ge 1)
    {$AllPermissionsOutput = $expandedPermissions + $rawPermissions | Where-Object -FilterScript {$_.TargetObjectGUID -ne $_.PermissionHolderObjectGUID}}
    else
    {$AllPermissionsOutput = $rawPermissions | Where-Object -FilterScript {$_.TargetObjectGUID -ne $_.PermissionHolderObjectGUID}}
    #remove permissions from excludedPermissionHolders if needed
    if ($PSBoundParameters.ContainsKey('ExcludedIdentities'))
    {
        $AllPermissionsOutput = @(
            $AllPermissionsOutput | Where-Object -FilterScript {
                ($_.permissionHolderObjectGUID -eq $null) -or
                (-not $excludedPermissionHoldersGUIDHash.ContainsKey($_.PermissionHolderObjectGUID))
            }
        )
    }
    if ($AllPermissionsOutput.Count -eq 0)
    {
        $GPEOParams = @{
            TargetMailbox = $mailbox
            PermissionHolderIdentity = 'Not Applicable'
            PermissionType = 'None'
            AssignmentType = 'None'
        }
        $NonPerm = New-PermissionExportObject @GPEOParams
        $MorePermissionExportProperties = @{
            PermissionHolderObjectGUID = $null
            PermissionHolderDistinguishedName = $null
            PermissionHolderPrimarySMTPAddress = 'None'
            PermissionHolderRecipientType = $null
            PermissionHolderRecipientTypeDetails = $null
        }
        Add-Member -InputObject $NonPerm -NotePropertyMembers $MorePermissionExportProperties
        Write-Output $NonPerm
    }
    else
    {
        Write-Output $AllPermissionsOutput
    }
    Write-Log -Message $message -EntryType Succeeded -Verbose
}#Foreach mailbox in set
    if ($MissingOrAmbiguousRecipients.count -ge 1)
    {
        $MissingOrAmbiguousRecipients = $MissingOrAmbiguousRecipients | Sort-Object | Select-Object -Unique
        $joinedIDs = $MissingOrAmbiguousRecipients -join '|'
        Write-Log -Message "The following identities are missing (as recipient objects) or ambiguous: $joinedIDs" -EntryType Notification -Verbose -ErrorLog
    }
}
function Import-OBCScriptOutputFromCSV
{
[cmdletbinding()]
param(
[parameter(Mandatory)]
$Path
)
$files = @(Get-ChildItem -Path $Path -Filter OBC-*.csv)
$obcOutputs = @{}
foreach ($file in $files)
{
    $importedname = $file.BaseName.replace('-','')
    $obcOutputs.$importedname = Import-Csv -Path $file.FullName
}
Write-Output $obcOutputs
}
##########################################################################################################
#OneShell Data Access Functions
##########################################################################################################
function Get-SourceData
{
#Get latest data from SQL 
$SourceData = Invoke-Sqlcmd -Query 'Select * from dbo.MigrationCandidateList' @Global:InvokeSQLParams | Select-Object -Property * -ExcludeProperty Item
}
