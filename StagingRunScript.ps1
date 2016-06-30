$AzureADUsersExport = Export-AzureADUser
$AzureADUsersDataTable = Convert-PSObjectToDataTable -InputObject $AzureADUsersExport
Import-DataTableToSQLBulkCopy -SQLTable 'AzureUsersStaging' -DataTable $AzureADUsersDataTable -sqlConnectionName 'MPT' -ValidateColumnMappings -TruncateSQLTable
$ADUsers = Export-ADUser -SourceAD esgc
$ADUsersDataTable = Convert-PSObjectToDataTable -InputObject $ADUsers
Import-DataTableToSQLBulkCopy -SQLTable 'ADUsersStaging' -DataTable $ADUsersDataTable -sqlConnectionName 'MPT' -ValidateColumnMappings -TruncateSQLTable
