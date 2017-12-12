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
    }
#end Function Get-DataTableType
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
    }
#end function Convert-PSObjectToDataTable
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
        #[System.Data.DataTable]
        $DataTable
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
                $MyError = New-ErrorRecord -Exception System.NotSupportedException -Message "SQL Table $SQLTable columns and DataTable columns do not match." -ErrorCategory InvalidData -TargetObject $SQLTable -ErrorId "1"
                $PSCmdlet.ThrowTerminatingError($MyError)
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
        $PropertyNames | ForEach-Object {$bulkCopy.ColumnMappings.Add($_,$_) | out-null} 
        $bulkCopy.BatchSize = $DataTable.Rows.Count
        $bulkCopy.BulkCopyTimeout = 0
        $bulkCopy.DestinationTableName = $SQLTable
        $bulkCopy.WriteToServer($DataTable)
        $bulkCopy.BatchSize = $null
        $bulkCopy.ColumnMappings.Clear()
        $bulkCopy.Close()
        $bulkCopy.Dispose()
    }
#End function Import-DataTableToSQLBulkCopy
function New-PermissionExportObject
    {
        [cmdletbinding()]
        param(
        [parameter(Mandatory)]
        $TargetMailbox
        ,
        [parameter(Mandatory)]
        [string]$TrusteeIdentity
        ,
        [parameter(Mandatory)]
        [ValidateSet('FullAccess','SendOnBehalf','SendAs','None')]
        $PermissionType
        ,
        [parameter()]
        [ValidateSet('Direct','GroupMembership','None')]
        [string]$AssignmentType = 'Direct'
        ,
        $TrusteeGroupObjectGUID
        ,
        $ParentPermissionIdentity
        ,
        [string]$SourceExchangeOrganization = $ExchangeOrganization
        ,
        [boolean]$IsInherited = $False #Export-Permissions currently does not export inherited permissions for FullAccess, and they are not possible for SendOnBehalf, so this will get set to $true only for certain Send As permissions
        )#End Param
        $Script:PermissionIdentity++
        [pscustomobject]@{
            PermissionIdentity = $Script:PermissionIdentity
            ParentPermissionIdentity = $ParentPermissionIdentity
            SourceExchangeOrganization = $SourceExchangeOrganization
            TargetObjectGUID = $TargetMailbox.Guid.Guid
            TargetDistinguishedName = $TargetMailbox.DistinguishedName
            TargetPrimarySMTPAddress = $TargetMailbox.PrimarySmtpAddress.ToString()
            TargetRecipientType = $TargetMailbox.RecipientType
            TargetRecipientTypeDetails = $TargetMailbox.RecipientTypeDetails
            PermissionType = $PermissionType
            AssignmentType = $AssignmentType
            TrusteeGroupObjectGUID = $TrusteeGroupObjectGUID
            TrusteeIdentity = $TrusteeIdentity
            IsInherited = $IsInherited
        }
    }
#end function New-PermissionExportObject
function Add-TrusteeAttributesToPermissionExportObject
    {
        [cmdletbinding()]
        param
        (
        [parameter(Mandatory)]
        [Alias('rpeo')]
        $rawPermissionExportObject
        ,
        [parameter(Mandatory)]
        [Alias('Recipient','Mailbox')]
        [AllowNull()]
        $TrusteeRecipientObject
        ,
        [switch]$None
        )#End Param
        if ($TrusteeRecipientObject -ne $null)
        {
            $MorePermissionExportProperties = @{
                TrusteeObjectGUID = $TrusteeRecipientObject.guid.Guid
                TrusteeDistinguishedName = $TrusteeRecipientObject.DistinguishedName
                TrusteePrimarySMTPAddress = $TrusteeRecipientObject.PrimarySmtpAddress.ToString()
                TrusteeRecipientType = $TrusteeRecipientObject.RecipientType
                TrusteeRecipientTypeDetails = $TrusteeRecipientObject.RecipientTypeDetails
                
            }
        }
        else
        {
            $MorePermissionExportProperties = @{
                TrusteeObjectGUID = $null
                TrusteeDistinguishedName = if ($None) {'none'} else {$null}
                TrusteePrimarySMTPAddress = if ($None) {'none'} else {$null}
                TrusteeRecipientType = $null
                TrusteeRecipientTypeDetails = $null
            }
        }
        Add-Member -InputObject $rawPermissionExportObject -NotePropertyMembers $MorePermissionExportProperties
    }
#end function Add-TrusteeAttributesToPermissionExportObject
function New-UserDSN
    {
        [cmdletbinding()]
        param
        (
        [Parameter()]
        [string]$DSNName = 'MPTDatabase'
        ,
        [Parameter()]
        [string]$DBName = 'MigrationPAndT'
        ,
        [Parameter()]
        [string]$Description = 'Migration Planning and Tracking Database'
        ,
        [Parameter(Mandatory)]
        [string]$DBServer
        ,
        [Parameter()]
        [string]$DriverName = 'SQL Server Native Client 11.0'
        ,
        [Parameter()]
        [string]$DriverPath = 'C:\Windows\system32\sqlncli11.dll'
        )
        $RegObjectPath = Join-Path 'HKCU:\SOFTWARE\ODBC\ODBC.INI' $DSNName
        New-Item -Path $RegObjectPath -ItemType Directory
        Set-ItemProperty -Path $RegObjectPath -Name Driver -Value $DriverPath
        Set-ItemProperty -Path $RegObjectPath -Name Description -Value $DSNName
        Set-ItemProperty -Path $RegObjectPath -Name Server -Value $DBServer
        Set-ItemProperty -Path $RegObjectPath -Name Trusted_Connection -Value 'Yes'
        Set-ItemProperty -Path $RegObjectPath -Name Database -Value $DBName
        ## This is required to allow the ODBC connection to show up in the ODBC Administrator application.
        $RegObject2Path = 'HKCU:\SOFTWARE\ODBC\ODBC.INI\ODBC Data Sources'
        if (-not (Test-Path -LiteralPath $RegObject2Path)) {
            New-Item -Path $RegObject2Path -ItemType Directory
        }
        Set-ItemProperty -Path $RegObject2Path -Name $DSNName -Value $DriverName
    }
#end function New-UserDSN
function Get-MaxLengthOfAllAttributes
    {
        [cmdletbinding()]
        param(
        [switch]$ShowProgress
        ,
        [parameter(ValueFromPipeline)]
        [psobject[]]$InputObject
        )
        begin
        {
            $AllPropertyMaxLengths = @{}
            if ($ShowProgress -and $PSBoundParameters.Keys.Contains('InputObject'))
            {
                $TotalCount = $InputObject.Count
                $i = 0
                $CountKnown = $true
            }
            else 
            {
                $TotalCount = 0
                $CountKnown = $false
            }
            $WriteProgressParams = @{
            Activity = 'Analyzing Objects'
            Status =  "$i of $totalCount"
            PercentComplete = 0
            }
        }#begin
        process
        {
        foreach ($o in $InputObject)
        {
            if ($ShowProgress)
            {
                $i++
                if ($CountKnown -eq $false)
                {
                    $TotalCount++
                }
                $WriteProgressParams.Status = "$i of $totalcount"
                $WriteProgressParams.PercentComplete = $i/$TotalCount*100
                Write-Progress  @WriteProgressParams
            }
            $OPropertyList = $o | Get-Member -MemberType Properties | Select-object -ExpandProperty Name
            foreach ($p in $OPropertyList)
            {
                if ($o.$p.capacity -ne $null)
                {
                    $length = @($o.$p.Length) | Measure-Object -Sum | Select-Object -ExpandProperty Sum
                }
                else
                {
                    $length = $o.$p.Length
                }
                if ($AllPropertyMaxLengths.ContainsKey($p))
                {
                    if ($length -gt $AllPropertyMaxLengths.$p)
                    {
                        $AllPropertyMaxLengths.$p = $($length)
                    }
                }
                else 
                {
                    $AllPropertyMaxLengths.$p = $length
                }
            }
        }
        }#process
        end
        {
            $AllPropertyMaxLengths.GetEnumerator() | Sort-object -property Name
        }#end
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
        [string]$ComputerName = $($env:COMPUTERNAME)
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
    }
#End Function Initialize-MigrationDatabase
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
#end function Export-AzureADUser
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
        [parameter()]
        [ValidateSet('SourceAD','OneShellDefault')]
        [string]$ADPropertySet = 'OneShellDefault'
        #,
        #$PropertySet
        )
        Connect-ADInstance -ActiveDirectoryInstance $SourceAD > $null
        #Get Data from Active Directory
        Push-Location
        Set-Location "$($SourceAD):\"
        #$RawADUsers = Get-ADUser -LDAPFilter '(&((sAMAccountType=805306368))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' -Properties  $Properties | Select-Object -Property $Properties -ErrorAction SilentlyContinue
        switch ($ADPropertySet)
        {
            'SourceAD'
            {
                $Properties = Get-OrgProfileSystem | Where-Object -FilterScript {$_.SystemType -EQ 'ActiveDirectoryInstances'} | Where-Object -filterscript {$_.Name -eq $SourceAD} | Select-Object -ExpandProperty UserAttributes
            }
            'OneShellDefault'
            {
                $Properties = @(Get-OneShellVariable -Name ADUserAttributes | Select-Object -ExpandProperty Value)
            }
        }
        $RawADUsers = Get-ADUser -LDAPFilter '(sAMAccountType=805306368)' -Properties  $Properties | Select-Object -Property $Properties -ErrorAction SilentlyContinue
        Pop-Location
        $MVAttributes = @('msExchPoliciesExcluded','msexchextensioncustomattribute1','msexchextensioncustomattribute2','msexchextensioncustomattribute3','msexchextensioncustomattribute4','msexchextensioncustomattribute5','memberof','proxyAddresses')
        $SVAttributes = @('createTimeStamp','modifyTimeStamp','msExchWhenMailboxCreated','whenCreated','whenChanged','AccountExpirationDate','LastLogonDate','altRecipient','forwardingAddress','msExchGenericForwardingAddress','cn','userPrincipalName','sAMAccountName','CanonicalName','GivenName','SurName','DistinguishedName','displayName','employeeNumber','employeeID','enabled','Mail','mailNickname','homeMDB','homeMTA','msExchHomeServerName','legacyExchangeDN','msExchArchiveName','msExchMasterAccountSID','msExchUserCulture','targetAddress','msExchRecipientDisplayType','msExchRecipientTypeDetails','msExchRemoteRecipientType','msExchVersion','extensionattribute1','extensionattribute2','extensionattribute3','extensionattribute4','extensionattribute5','extensionattribute6','extensionattribute7','extensionattribute8','extensionattribute9','extensionattribute10','extensionattribute11','extensionattribute12','extensionattribute13','extensionattribute14','extensionattribute15','canonicalname','department','deliverandRedirect','distinguishedName','msExchHideFromAddressLists','msExchUsageLocation','c','co','country','physicalDeliveryOfficeName','company','city','notes')
        $propertyset = Get-CSVExportPropertySet -Delimiter '|' -MultiValuedAttributes $MVAttributes -ScalarAttributes $SVAttributes 
        $propertyset += @{n='mS-DS-ConsistencyGuid';e={(Get-GuidFromByteArray -GuidByteArray $_.'mS-DS-ConsistencyGuid').guid}}
        $propertyset += @{n='msExchMailboxGUID';e={(Get-GuidFromByteArray -GuidByteArray $_.msExchMailboxGUID).guid}}
        $propertyset += @{n='msExchArchiveGUID';e={(Get-GuidFromByteArray -GuidByteArray $_.msExchArchiveGUID).guid}}
        $propertyset += @{n='ObjectGUID';e={$_.ObjectGUID.guid}}
        $propertyset += @{n='SourceOrganization';e={$SourceAD}}
        $propertyset += @{n='ExpectedAzureADImmutableID';e={Get-ImmutableIDFromGUID -Guid $_.ObjectGUID}}
        $ADUsersexport = @($RawADUsers | Select-Object -Property $propertyset -ErrorAction SilentlyContinue) # -ExcludeProperty ObjectGUID,msExchMailboxGUID,msExchArchiveGUID,CanonicalName,DistinguishedName)
        Write-Output $ADUsersexport
    }
#end function Export-ADUser
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
        ##########################################################################
        #Add exchange online/2016 detection via organizationconfig?
        if ($ExchangeOrganization -eq 'OL')
        {$propertyset += @{n='ExchangeGuid';e={$_.ExchangeGUID.guid}}}
        else
        {$propertyset += @{n='ExchangeGuid';e={''}}}
        ##########################################################################
        $propertyset += @{n='ArchiveGuid';e={$_.ArchiveGuid.guid}}
        $propertyset += @{n='SourceOrganization';e={$ExchangeOrganization}}
        $ExchangeRecipientsExport = @($RawRecipients | Select-Object -Property $propertyset) #-ErrorAction SilentlyContinue
        Write-Output $ExchangeRecipientsExport
    }
#end function Export-ExchangeRecipient
function Export-ExchangeMailbox
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
        $RawRecipients = Invoke-ExchangeCommand -ExchangeOrganization $ExchangeOrganization -cmdlet 'Get-Mailbox' -splat $Splat
        $MVAttributes = @('AcceptMessagesOnlyFrom','AcceptMessagesOnlyFromDLMembers','AcceptMessagesOnlyFromSendersOrMembers','AddressListMembership','ArchiveName','AuditAdmin','AuditDelegate','AuditOwner','BypassModerationFromSendersOrMembers','EmailAddresses','ExtensionCustomAttribute1','ExtensionCustomAttribute2','ExtensionCustomAttribute3','ExtensionCustomAttribute4','ExtensionCustomAttribute5','GrantSendOnBehalfTo','Languages','MailTipTranslations','ModeratedBy','ObjectClass','PersistedCapabilities','PoliciesExcluded','PoliciesIncluded','ProtocolSettings','RejectMessagesFrom','RejectMessagesFromDLMembers','RejectMessagesFromSendersOrMembers','ResourceCustom')
        $SVAttributes = @('ActiveSyncMailboxPolicy','ActiveSyncMailboxPolicyIsDefaulted','AddressBookPolicy','Alias','AntispamBypassEnabled','ArchiveDatabase','ArchiveDomain','ArchiveQuota','ArchiveStatus','ArchiveWarningQuota','AuthenticationType','AuditEnabled','AuditLogAgeLimit','CalendarRepairDisabled','CalendarVersionStoreDisabled','CustomAttribute1','CustomAttribute10','CustomAttribute11','CustomAttribute12','CustomAttribute13','CustomAttribute14','CustomAttribute15','CustomAttribute2','CustomAttribute3','CustomAttribute4','CustomAttribute5','CustomAttribute6','CustomAttribute7','CustomAttribute8','CustomAttribute9','Database','DeliverToMailboxAndForward','DisabledArchiveDatabase','Department','DisplayName','DistinguishedName','DowngradeHighPriorityMessagesEnabled','EmailAddressPolicyEnabled','ExchangeSecurityDescriptor','ExchangeUserAccountControl','ExchangeVersion','ExternalDirectoryObjectId','ExternalOofOptions','ForwardingAddress','ForwardingSmtpAddress','HasPicture','HasSpokenName','HiddenFromAddressListsEnabled','Identity','ImmutableId','IsLinked','IsMailboxEnabled','IsResource','IsShared','IsValid','LastExchangeChangedTime','LegacyExchangeDN','LinkedMasterAccount','LitigationHoldDate','LitigationHoldEnabled','LitigationHoldOwner','MailboxMoveBatchName','MailboxMoveFlags','MailboxMoveRemoteHostName','MailboxMoveSourceMDB','MailboxMoveStatus','MailboxMoveTargetMDB','MailboxPlan','MailTip','ManagedFolderMailboxPolicy','MaxBlockedSenders','MaxReceiveSize','MaxSafeSenders','MaxSendSize','MessageTrackingReadStatusEnabled','ModerationEnabled','Name','ObjectCategory','Office','OfflineAddressBook','OrganizationalUnit','OrganizationId','OriginatingServer','PrimarySmtpAddress','PSComputerName','PSShowComputerName','RecipientLimits','RecipientType','RecipientTypeDetails','RecoverableItemsQuota','RecoverableItemsWarningQuota','RemoteAccountPolicy','RemoteRecipientType','RequireSenderAuthenticationEnabled','ResourceCapacity','ResourceType','RetainDeletedItemsFor','RetainDeletedItemsUntilBackup','RetentionComment','RetentionHoldEnabled','RetentionPolicy','RetentionUrl','RoleAssignmentPolicy','RulesQuota','SamAccountName','SCLDeleteEnabled','SCLDeleteThreshold','SCLJunkEnabled','SCLJunkThreshold','SCLQuarantineEnabled','SCLQuarantineThreshold','SCLRejectEnabled','SCLRejectThreshold','SendModerationNotifications','ServerLegacyDN','ServerName','SharingPolicy','SimpleDisplayName','SingleItemRecoveryEnabled','SKUAssigned','StartDateForRetentionHold','ThrottlingPolicy','UMEnabled','UsageLocation','UseDatabaseQuotaDefaults','UseDatabaseRetentionDefaults','UserPrincipalName','WhenChanged','WhenChangedUTC','WhenCreated','WhenCreatedUTC','WhenMailboxCreated','WindowsEmailAddress','WindowsLiveID')
        $propertyset = Get-CSVExportPropertySet -Delimiter '|' -MultiValuedAttributes $MVAttributes -ScalarAttributes $SVAttributes 
        $propertyset += @{n='Guid';e={$_.GUID.guid}}
        $propertyset += @{n='ArchiveGuid';e={$_.ArchiveGuid.guid}}
        $propertyset += @{n='ExchangeGuid';e={$_.ExchangeGuid.guid}}
        $propertyset += @{n='DisabledArchiveGuid';e={$_.DisabledArchiveGuid.guid}}
        $propertyset += @{n='SourceOrganization';e={$ExchangeOrganization}}
        $ExchangeMailboxesExport = @($RawRecipients | Select-Object -Property $propertyset) #-ErrorAction SilentlyContinue
        Write-Output $ExchangeMailboxesExport
    }
#end function Export-ExchangeMailbox
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
        #Remove Soft Deleted Disconnected Mailbox Results
        $RawMailboxStatistics = @($RawMailboxStatistics | Where-Object -FilterScript {$_.DisconnectReason -ne 'SoftDeleted'})
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
#end function Export-MailboxStatistics
Function Export-Permissions
    {
        #ToDo
        #Add an attribute to the permission object which indicates if the target/permholder were in the mailboxes scope
        #switch ExchangeOrganization to a dynamic parameter
        #use get-group and/or get-user when get-recipient fails to get an object
        #move code to add additional attributes to export object to a new function or update the existin function
        #Fix Fullaccess to leverage SID History and Inheritance options
        #Make inheritance work for expanded group perms, too. right now will say false for all which isn't correct.
        #add excluded prefixes with split on \
        #add scoping by OU? integrate EXO recipients as a filter of some sort?
        #fix ugly out-file hack
        #implement explicit garbage collection. 
        #fix denies --done
        #globalsendas -- done
        ##parameterset -- done
        ##recip instead of mailbox -- done just for globalsendas
        #sid stuff -- done
        #AD connection -- done
        #inheritance switch and output -- done
        #hard-code sendas guid -- done
        #add genericall -- done

        [cmdletbinding(DefaultParameterSetName = 'AllMailboxes')]
        param(
            [string]$ExchangeOrganization
            ,
            [parameter(ParameterSetName = 'GlobalSendAs',Mandatory)]
            [switch]$GlobalSendAs
            ,
            [parameter(ParameterSetName = 'Scoped',Mandatory)]
            [string[]]$Identity
            ,
            [Parameter(ParameterSetName = 'AllMailboxes',Mandatory)]
            [switch]$AllMailboxes
            ,
            [parameter()]#These will be resolved to recipient objects
            [string[]]$ExcludedIdentities
            ,
            #Trustees in these NETBIOS domains will be ignored. Only SendAs for now.
            [string[]]$ExcludedTrusteeDomains
            ,
            #These trustees (Domain\username) will be ignored. Only SendAs for now.
            [string[]]$ExcludedTrustees
            ,
            [parameter(ParameterSetName = 'Scoped',Mandatory)]
            [Parameter(ParameterSetName = 'AllMailboxes',Mandatory)]
            [boolean]$IncludeSendOnBehalf = $true
            ,
            [parameter(ParameterSetName = 'Scoped',Mandatory)]
            [Parameter(ParameterSetName = 'AllMailboxes',Mandatory)]
            [boolean]$IncludeFullAccess = $true
            ,
            [parameter(ParameterSetName = 'Scoped',Mandatory)]
            [Parameter(ParameterSetName = 'AllMailboxes',Mandatory)]
            [boolean]$IncludeSendAs = $true
            ,
            [boolean]$expandGroups = $true
            ,
            [boolean]$dropExpandedGroups = $false
            ,
            [boolean]$dropInheritedPermissions = $false #Currently Functional Only For Send-As, though this function is hard-coded to ignore inherited FMB and inherited SendOnBehalf is not possible.
            ,
            [parameter(Mandatory)]
            [string]$ActiveDirectoryInstance
        )#End Param
        Function Get-SIDHistoryRecipientHash {
            param (
                [parameter(Mandatory)]
                $ActiveDirectoryInstance,
                $ExchangeOrganization
            )#End param
            Write-Log -Message "Operation: Retrieve Mapping for all User Recipients with SIDHistory." -Verbose
            $SIDHistoryRecipientHash = @{}
            Push-Location
            Set-Location $("$ActiveDirectoryInstance`:") -ErrorAction Stop
            $sidhistoryusers = get-aduser -ldapfilter "(&(legacyExchangeDN=*)(sidhistory=*))" -Properties sidhistory,legacyExchangeDN
            Pop-Location
            $CurrentEA = $Global:ErrorActionPreference
            $sidhistoryusercounter = 0
            $Global:ErrorActionPreference = 'Stop'
            Foreach ($sidhistoryuser in $sidhistoryusers) {
                $sidhistoryusercounter++
                $message = 'Generating hash of SIDHistory SIDs and Recipient objects...'
                $ProgressInterval = [int]($($sidhistoryusers.Count) * .01)
                if ($($sidhistoryusercounter) % $ProgressInterval -eq 0)
                    {Write-Progress -Activity $message -status "Items processed: $($sidhistoryusercounter) of $($sidhistoryusers.Count)" -percentComplete (($sidhistoryusercounter / $($sidhistoryusers.Count))*100)}
                $splat = @{Identity = $sidhistoryuser.ObjectGuid.guid}
                $sidhistoryuserrecipient = $Null
                Try {$sidhistoryuserrecipient = Invoke-ExchangeCommand -ExchangeOrganization $ExchangeOrganization -cmdlet 'Get-Recipient' -splat $splat}
                Catch {}
                If (!($sidhistoryuserrecipient)) {Continue}
                Foreach ($sidhistorysid in $sidhistoryuser.sidhistory) {
                    $SIDHistoryRecipientHash.$($sidhistorysid.value) = $sidhistoryuserrecipient
                }#End Foreach
            }#End Foreach
            $Global:ErrorActionPreference = $CurrentEA
            Write-Output $SIDHistoryRecipientHash
        }#End Get-SIDHistoryRecipientHash
        if (!(Connect-Exchange -ExchangeOrganization $ExchangeOrganization)) {
            write-log -Message "Could not connect to Exchange Organization $($ExchangeOrganization)" -ErrorLog
            throw {"Could not connect to Exchange Organization $($ExchangeOrganization)"}
            
        }#End If
        if (!(Connect-ADInstance $ActiveDirectoryInstance)) {
            write-log -Message "Could not connect to Active Directory Intance $($ActiveDirectoryInstance)" -ErrorLog
            throw {"Could not connect to Active Directory Instance $($ActiveDirectoryInstance)"}
        }#End If
        #Region GetInScopeMailboxes
        switch ($PSCmdlet.ParameterSetName)
        {
            'Scoped'
            { 
                Write-Log -Message "Operation: Scoped Permission retrieval with $($Identity.Count) Identities provided." -Verbose
                $message = "Retrieve mailbox object for each provided Identity in Exchange Organization $ExchangeOrganization."
                Write-Log -Message $message -EntryType Attempting -Verbose
                $InScopeMailboxes = @($Identity | ForEach-Object {
                        $splat = @{Identity = $_}
                        Invoke-ExchangeCommand -ExchangeOrganization $ExchangeOrganization -cmdlet 'Get-Recipient' -splat $splat
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
                $InScopeMailboxes = @(Invoke-ExchangeCommand -ExchangeOrganization $ExchangeOrganization -cmdlet 'Get-Mailbox' -splat $splat)
                Write-Log -Message $message -EntryType Succeeded -Verbose
            }
            'GlobalSendAs'
            {
                Write-Log -Message "Operation: Send As Permission retrieval for all recipients." -Verbose
                $message = "Retrieve all available recipient objects in Exchange Organization $ExchangeOrganization."
                Write-Log -Message $message -EntryType Attempting -Verbose
                $splat = @{ResultSize = 'unlimited'}
                $InScopeMailboxes = @(Invoke-ExchangeCommand -ExchangeOrganization $ExchangeOrganization -cmdlet 'Get-Recipient' -splat $splat)
                Write-Log -Message $message -EntryType Succeeded -Verbose
            }
        }
        #EndRegion GetInScopeMailboxes
        if ($PSBoundParameters.ContainsKey('ExcludedIdentities'))
        {
            $excludedRecipients = @(
                $ExcludedIdentities | ForEach-Object {
                    $splat = @{
                        Identity = $_
                        ErrorAction = 'SilentlyContinue'
                    }
                    Invoke-ExchangeCommand -ExchangeOrganization $ExchangeOrganization -cmdlet 'Get-Recipient' -splat $splat
                }
            )
            $excludedRecipientsGUIDHash = $excludedRecipients | Group-Object -Property GUID -AsString -AsHashTable
        }

        #ADSI Adapter: http://social.technet.microsoft.com/wiki/contents/articles/4231.working-with-active-directory-using-powershell-adsi-adapter.aspx
        <#$dse = [ADSI]"LDAP://Rootdse"
        $ext = [ADSI]("LDAP://CN=Extended-Rights," + $dse.ConfigurationNamingContext)
        $dn = [ADSI]"LDAP://$($dse.DefaultNamingContext)"
        $dsLookFor = New-Object System.DirectoryServices.DirectorySearcher($dn)
        $permission = "Send As"
        $right = $ext.psbase.Children | Where-Object { $_.DisplayName -eq $permission }

        commented out the above since the GUID for this right seems to be well-known. the below is the GUID is extracted from the above object if you want to revert.

        [GUID]$right.RightsGuid.Value#>

        $right = [GUID]'ab721a54-1e2f-11d0-9819-00aa0040529b' #Well-known GUID for Send As Permissions
        $CanonicalNameHash = @{}
        $DomainPrincipalHash = @{}
        $DistinguishedNameHash = $InScopeMailboxes | Group-Object -AsHashTable -Property DistinguishedName -AsString
        $SIDHistoryRecipientHash = Get-SIDHistoryRecipientHash -ActiveDirectoryInstance $ActiveDirectoryInstance -ExchangeOrganization $ExchangeOrganization
        $MissingOrAmbiguousRecipients = @()
        $mailboxCounter = 0
        $InScopeMailboxCount = $InScopeMailboxes.count
        [uint32]$Script:PermissionIdentity = 0
        Foreach ($mailbox in $InScopeMailboxes)
        {
            $mailboxCounter++
            if ($PSBoundParameters.ContainsKey('ExcludedIdentities'))
            {
                if ($excludedRecipientsGUIDHash.ContainsKey($mailbox.guid.Guid))
                {
                    continue
                }
            }
            $ID = $mailbox.PrimarySMTPAddress.ToString();
            $message = "Collect permissions for $($ID)"
            Write-Progress -Activity $message -status "Items processed: $($mailboxCounter) of $($InScopeMailboxCount)" -percentComplete (($mailboxCounter / $InScopeMailboxCount)*100)
            Write-Log -Message $message -EntryType Attempting -Verbose
            $rawPermissions = @(
                #Get Delegate Users (actual permissions are stored in the mailbox . . . so these are not true delegates just a likely correlation to delegates) This section should also check if the grantsendonbehalfto permission holder is a group, because it can be . . .
                If (($IncludeSendOnBehalf) -and (!($GlobalSendAs)))
                {
                    $sbTrustees = $mailbox.grantsendonbehalfto.ToArray()
                    foreach ($sb in $sbTrustees)
                    {
                        New-PermissionExportObject -TargetMailbox $mailbox -TrusteeIdentity $sb -PermissionType SendOnBehalf -AssignmentType Direct -SourceExchangeOrganization $ExchangeOrganization
                    }
                }
                #Get Full Access Users
                If (($IncludeFullAccess) -and (!($GlobalSendAs)))
                {
                    $faTrustees = @(
                        $splat = @{Identity = $ID; ErrorAction = 'SilentlyContinue'}
                        Invoke-ExchangeCommand -ExchangeOrganization $ExchangeOrganization -cmdlet 'Get-MailboxPermission' -splat $splat |
                        Where-Object -FilterScript {
                            ($_.AccessRights -like “*FullAccess*”) -and 
                            ($_.IsInherited -eq $false) -and -not 
                            ($_.User -like “NT AUTHORITY\SELF”) -and -not 
                            ($_.Deny -eq $True) -and -not
                            ($_.User -like "S-1-5*")
                        } | Select-Object -ExpandProperty User
                    )
                    foreach ($fa in $faTrustees)
                    {
                        New-PermissionExportObject -TargetMailbox $mailbox -TrusteeIdentity $fa -PermissionType FullAccess -AssignmentType Direct -SourceExchangeOrganization $ExchangeOrganization
                    }
                }
                #Get Send As Users
                If (($IncludeSendAs) -or ($GlobalSendAs))
                {
                    if (!(Connect-Exchange -ExchangeOrganization $ExchangeOrganization)) {
                        write-log -Message "Could not connect to Exchange Organization $($ExchangeOrganization)" -ErrorLog
                        throw {"Could not connect to Exchange Organization $($ExchangeOrganization)"}
                        
                    }#End If
                    $userDN = [ADSI]("LDAP://$($mailbox.DistinguishedName)")
                    $saTrustees = @(
                        $userDN.psbase.ObjectSecurity.Access | Where-Object -FilterScript { (($_.ObjectType -eq $right) -or ($_.ActiveDirectoryRights -eq 'GenericAll')) -and ($_.AccessControlType -eq 'Allow')} | 
                        Where-Object -FilterScript {$_.identityreference -notin $ExcludedTrustees}|Where-Object -FilterScript {($_.identityreference.ToString().split('\')[0]) -notin $ExcludedTrusteeDomains}|Select-Object identityreference,IsInherited 
                        #| Where-Object -FilterScript {$_ -notlike "NT AUTHORITY\SELF"}
                    )
                    foreach ($sa in $saTrustees)
                    {	
                        If ($sa.IsInherited -eq $true) {
                            If ($dropInheritedPermissions) {Continue}
                        }#End If
                        
                        New-PermissionExportObject -TargetMailbox $mailbox -TrusteeIdentity $sa.identityreference -PermissionType SendAs -AssignmentType Direct -SourceExchangeOrganization $ExchangeOrganization -IsInherited $sa.IsInherited
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
                        if ($CanonicalNameHash.ContainsKey($rp.TrusteeIdentity))
                        {
                            $Recipient = @($CanonicalNameHash.$($rp.TrusteeIdentity))
                        }
                    }
                    Default #both SendAs and FullAccess use Domain\SecurityPrincipal format
                    {
                        if ($DomainPrincipalHash.ContainsKey($rp.TrusteeIdentity))
                        {
                            $Recipient = @($DomainPrincipalHash.$($rp.TrusteeIdentity))
                        }
                        elseif ($SIDHistoryRecipientHash.ContainsKey($rp.TrusteeIdentity)) {
                            $Recipient = @($SIDHistoryRecipientHash.$($rp.TrusteeIdentity))
                        }#End elseif
                    }
                }
                if ($Recipient.Count -eq 0)
                {
                    $splat = @{Identity = $rp.TrusteeIdentity; ErrorAction = 'SilentlyContinue'}
                    $Recipient = @(Invoke-ExchangeCommand -ExchangeOrganization $ExchangeOrganization -cmdlet 'Get-Recipient' -splat $splat)
                }
                switch ($Recipient.Count)
                {
                    1
                    {
                        $Recipient = $Recipient[0]
                        Add-TrusteeAttributesToPermissionExportObject -rawPermissionExportObject $rp -TrusteeRecipientObject $Recipient
                        switch ($rp.permissionType) {
                            'SendOnBehalf' {$CanonicalNameHash.$($rp.TrusteeIdentity) = $Recipient}
                            Default {$DomainPrincipalHash.$($rp.TrusteeIdentity) = $Recipient}
                        }
                    }#1
                    Default
                    {
                        $MissingOrAmbiguousRecipients += $rp.TrusteeIdentity
                        Add-TrusteeAttributesToPermissionExportObject -rawPermissionExportObject $rp -TrusteeRecipientObject $null
                    }#Default
                }#switch Recipient.Count
            }#foreach Rp in RawPermissions
            if ($expandGroups)
            {
                #enumerate groups: http://stackoverflow.com/questions/8055338/listing-users-in-ad-group-recursively-with-powershell-script-without-cmdlets/8055996#8055996
                $expandedPermissions = @(
                    $groupPerms = @($rawPermissions | Where-Object -FilterScript {$_.TrusteeRecipientTypeDetails -like '*Group*'})
                    foreach ($gp in $groupPerms)
                    {
                        $dsLookFor.Filter = "(&(memberof:1.2.840.113556.1.4.1941:=$($gp.TrusteeDistinguishedName))(objectCategory=user))" 
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
                                        TrusteeIdentity = $Recipient.DistinguishedName
                                        PermissionType = $gp.PermissionType
                                        AssignmentType = 'GroupMembership'
                                        TrusteeGroupObjectGUID = $gp.TrusteeObjectGUID
                                        SourceExchangeOrganization = $ExchangeOrganization
                                        ParentPermissionIdentity = $gp.PermissionIdentity
                                    }
                                    $rawEP = New-PermissionExportObject @GPEOParams
                                    Add-TrusteeAttributesToPermissionExportObject -rawPermissionExportObject $rawEP -TrusteeRecipientObject $Recipient
                                    Write-Output $rawEP
                                    $DistinguishedNameHash.$uDN = $Recipient
                                }#1
                                Default
                                {
                                    $GPEOParams = @{
                                        TargetMailbox = $Mailbox
                                        TrusteeIdentity = "$uDN"
                                        PermissionType = $gp.PermissionType
                                        AssignmentType = 'GroupMembership'
                                        TrusteeGroupObjectGUID = $gp.TrusteeObjectGUID
                                        SourceExchangeOrganization = $ExchangeOrganization
                                        ParentPermissionIdentity = $gp.PermissionIdentity
                                    }
                                    $rawEP = New-PermissionExportObject @GPEOParams
                                    Add-TrusteeAttributesToPermissionExportObject -rawPermissionExportObject $rawEP -TrusteeRecipientObject $null
                                    $MissingOrAmbiguousRecipients += $rp.TrusteeIdentity
                                }#Default
                            }#switch Recipient.Count
                        }#foreach u in lstusr
                    }#foreach gp in groupPerms
                )#expandedPermissions
                if ($dropExpandedGroups)
                {
                    $rawPermissions = $rawPermissions | Where-Object -FilterScript {$_.TrusteeRecipientTypeDetails -notlike '*group*'}
                }
            }
            #combine and remove and self permissions that came in through expansion or otherwise
            if ($expandedPermissions.Count -ge 1)
            {$AllPermissionsOutput = $expandedPermissions + $rawPermissions | Where-Object -FilterScript {$_.TargetObjectGUID -ne $_.TrusteeObjectGUID}}
            else
            {$AllPermissionsOutput = $rawPermissions | Where-Object -FilterScript {$_.TargetObjectGUID -ne $_.TrusteeObjectGUID}}
            #remove permissions from excludedPermissionHolders if needed
            if ($PSBoundParameters.ContainsKey('ExcludedIdentities'))
            {
                $AllPermissionsOutput = @(
                    $AllPermissionsOutput | Where-Object -FilterScript {
                        ($_.TrusteeObjectGUID -eq $null) -or
                        (-not $excludedRecipientsGUIDHash.ContainsKey($_.TrusteeObjectGUID))
                    }
                )
            }
            if ($AllPermissionsOutput.Count -eq 0)
            {
                $GPEOParams = @{
                    TargetMailbox = $mailbox
                    TrusteeIdentity = 'Not Applicable'
                    PermissionType = 'None'
                    AssignmentType = 'None'
                    SourceExchangeOrganization = $ExchangeOrganization
                }
                $NonPerm = New-PermissionExportObject @GPEOParams
                Add-TrusteeAttributesToPermissionExportObject -rawPermissionExportObject $NonPerm -TrusteeRecipientObject $null -None
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
                $ExportFilePath = $script:ExportDataPath +  (get-timestamp)  + 'MissingOrAmbiguousRecipients' + '.txt'
                $MissingOrAmbiguousRecipients | out-file $exportFilePath
            }
    }
#End Function Export-Permissions

#Mostly OBC still 
Function Create-Batches
    {
        [cmdletbinding()]
        param
        (
            [Parameter(Mandatory=$true)]
            $PermissionsData
        )
        $PermissionsData = $PermissionsData | Where-Object TrusteeRecipientType -NotLike '*group' #| ? {$_.TrusteeRecipientType -ne $null -and $_.TrusteePrimarySMTPAddress -eq 'none'}
        Write-StartFunctionStatus -CallingFunction $MyInvocation.MyCommand
        $hashData = $PermissionsData | Group-Object TargetPrimarySMTPAddress -AsHashTable -AsString
        $hashDataByDelegate = $PermissionsData | Group-Object TrusteePrimarySMTPAddress -AsHashTable -AsString
        $usersWithNoDependents = New-Object System.Collections.ArrayList
        $hashDataSize = $hashData.Count
        $yyyyMMdd = Get-Date -Format 'yyyyMMdd'
        try
        {
            Write-Log -Message "Build ArrayList for Mailboxes with no dependents" -Verbose
            If ($hashDataByDelegate["None"].count -gt 0) 
            {
                $hashDataByDelegate["None"] | ForEach-Object {$_.TargetPrimarySMTPAddress} | ForEach-Object {[void]$usersWithNoDependents.Add($_)}
            }	    
            Write-Log -Message "Identify users with no permissions on them, nor them have perms on another" -Verbose
            If ($usersWithNoDependents.count -gt 0)
            {
                $($usersWithNoDependents) | ForEach-Object {if ($hashDataByDelegate.ContainsKey($_)) {$usersWithNoDependents.Remove($_)}	
                }
            Write-Log -Message "Remove users with no Target/Trustee relationships from hash Data" -Verbose
                $usersWithNoDependents | ForEach-Object {$hashData.Remove($_)}
                #Clean out hashData of users in hash data with no delegates, otherwise they'll get batched
            Write-Log -Message "Clean out hashData of users in hash data with no Trustees" -Verbose
                foreach ($key in $($hashData.keys)) 
            {
            if (($hashData[$key] | Select-Object -expandproperty TrusteePrimarySMTPAddress) -eq "None") {$hashData.Remove($key)}
                }
            }
            #Execute batch functions
            $script:batch = @{}
            If (($hashData.count -ne 0) -or ($usersWithNoDependents.count -ne 0))
            {
                Write-Log -Message "Run Find-Links function" -Verbose
                while ($hashData.count -ne 0) {$hashData = Find-Links -hashData $hashData} 
                Write-Log -message "Run Create-BatchOutput function" -Verbose
                Create-BatchOutput -batchResults $batch -usersWithNoDepsResults $usersWithNoDependents
            }
        }
        catch
        {
            Write-Log -message "Error: $_" -ErrorLog -Verbose
        }
    }
#End Function Create-Batches
Function Find-Links
    {
        [cmdletbinding()]
        param
        (
            $hashData
        )
        try
        {
            Write-Log -message "Hash Data Size: $($hashData.count)" -Verbose
            $nextInHash = $hashData.Keys | Select-Object -first 1
            $script:batch.Add($nextInHash,$hashData[$nextInHash])
            Do
            {
                $checkForMatches = $false
                foreach ($key in $($hashData.keys)) 
                {
                    $Script:comparisonCounter++
                    Write-Progress -Activity "Analyzing Data to Populate Batches" -status "Items remaining: $($hashData.Count)" -percentComplete (($hashDataSize-$hashData.Count) / $hashDataSize*100) -CurrentOperation $key
                    #Checks
                    $usersHashData = $($hashData[$key]) | ForEach-Object {$_.TargetPrimarySMTPAddress}
                    $usersBatch = $($script:batch[$nextInHash]) | ForEach-Object {$_.TargetPrimarySMTPAddress}
                    $delegatesHashData = $($hashData[$key]) | ForEach-Object {$_.TrusteePrimarySMTPAddress}
                    $delegatesBatch = $($script:batch[$nextInHash]) | ForEach-Object {$_.TrusteePrimarySMTPAddress}
                    $ifMatchesHashUserToBatchUser = [bool]($usersHashData | Where-Object{$usersBatch -contains $_})
                    $ifMatchesHashDelegToBatchDeleg = [bool]($delegatesHashData | Where-Object{$delegatesBatch -contains $_})
                    $ifMatchesHashUserToBatchDelegate = [bool]($usersHashData | Where-Object{$delegatesBatch -contains $_})
                    $ifMatchesHashDelegToBatchUser = [bool]($delegatesHashData | Where-Object{$usersBatch -contains $_})
                    If ($ifMatchesHashDelegToBatchDeleg -OR $ifMatchesHashDelegToBatchUser -OR $ifMatchesHashUserToBatchUser -OR $ifMatchesHashUserToBatchDelegate)
                    {
                        if (($key -ne $nextInHash))
                        { 
                            $script:batch[$nextInHash] += $hashData[$key]
                            $checkForMatches = $true
                        }
                        $hashData.Remove($key)
                    }#if
                }#foreach
            }#Do
            Until ($checkForMatches -eq $false)

            Write-Output $hashData 
            
        }
        catch
        {
            Write-Log -message "Error: $_" -Verbose -ErrorLog
        }
    }
#end Function Find-Links
Function Create-BatchOutput
    {
        [cmdletbinding()]
        param
        (
        $batchResults
        ,
        $usersWithNoDepsResults
        )
        $batchNum = 0
        try
        {
            $batchesOutput = @(
                foreach ($key in $batchResults.keys)
                {
                $batchNum++
                $batchName = "$batchNum"
                    $BatchTargetsAndTrustees = @(
                    $($batch[$key]) | Select-Object -ExpandProperty TargetPrimarySMTPAddress
                    $($batch[$key]) | Select-Object -ExpandProperty TrusteePrimarySMTPAddress
                )
                    $BatchTargetsAndTrustees | Select-Object -Unique | ForEach-Object {[pscustomobject]@{BatchName = $batchName; BatchMember = $_}}
                }#foreach
                If($usersWithNoDepsResults.count -gt 0)
                {
                    $batchNum++
                $batchName = "0"
                    foreach ($user in $usersWithNoDepsResults)
                {
                    [pscustomobject]@{BatchName = $batchName; BatchMember = $user}
                    }
                }
            )#BatchesOutput
            Write-Output $batchesOutput
            Write-Log -Message "Batches created: $($batchNum)" -Verbose
            Write-Log -Message "Number of comparisons: $($Script:comparisonCounter)" -Verbose
        }#Try
        catch
        {
            Write-Log -message "Error: $_" -Verbose -ErrorLog
        }
    }
#end function Create-BatchOutput
##########################################################################################################
#MCTL Data Management Functions
##########################################################################################################
function Get-SourceData
    {
        #Get latest data from SQL 
    $SourceData = Invoke-Sqlcmd -Query 'Select * from dbo.MigrationCandidateList' @Global:InvokeSQLParams | Select-Object -Property * -ExcludeProperty Item
    }
#end function Get-SourceData
function Set-MCTLWaveEntry
    {
        [cmdletbinding()]
        param(
        [parameter(Mandatory)]
        $Wave
        ,
        [parameter(Mandatory)]
        [string[]]$ObjectGUID
        )
        $UpdateMCTLWaveEntry = "UPDATE [dbo].[WaveMembers] SET [Wave] = $Wave FROM [dbo].[WaveMembers] WHERE [ObjectGUID] IN ($($ObjectGUID -join ','))"
        Invoke-SQLServerQuery -connection $SQLConnections[0] -sql $UpdateMCTLWaveEntry -ErrorAction Stop
    }
#end function Set-MCTLWaveEntry
function New-MCTLWaveEntry
    {
        [cmdletbinding()]
        param(
        [parameter(Mandatory)]
        $Wave
        ,
        [parameter(Mandatory)]
        [string]$ObjectGUID
        )
        $NewMCTLWaveEntry = "INSERT INTO [dbo].[WaveMembers]([Wave],[ObjectGUID]) VALUES($Wave,$ObjectGUID)"
        Invoke-SQLServerQuery -connection $SQLConnections[0] -sql $NewMCTLWaveEntry -ErrorAction Stop 
    }
#end function New-MCTLWaveEntry