$AzureADUsersExport = Export-AzureADUser
$AzureADUsersDataTable = Convert-PSObjectToDataTable -InputObject $AzureADUsersExport
Import-DataTableToSQLBulkCopy -SQLTable 'AzureUsersStaging' -DataTable $AzureADUsersDataTable -sqlConnectionName 'MPT' -ValidateColumnMappings -TruncateSQLTable
$ADUsers = Export-ADUser -SourceAD esgc
$ADUsersDataTable = Convert-PSObjectToDataTable -InputObject $ADUsers
Import-DataTableToSQLBulkCopy -SQLTable 'ADUsersStaging' -DataTable $ADUsersDataTable -sqlConnectionName 'MPT' -ValidateColumnMappings -TruncateSQLTable
$ExchangeRecipients = Export-ExchangeRecipient -ExchangeOrganization OP 
$ExchangeRecipientsDataTable = Convert-PSObjectToDataTable -InputObject $ExchangeRecipients
Import-DataTableToSQLBulkCopy -SQLTable 'ExchangeRecipientsStaging' -DataTable $ExchangeRecipientsDataTable -sqlConnectionName 'MPT' -ValidateColumnMappings -TruncateSQLTable