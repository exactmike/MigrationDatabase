$AzureADUsersExport = Export-AzureUsers
$AzureADUsersDataTable = Convert-PSObjectToDataTable -InputObject $AzureADUsersExport
Import-DataTableToSQLBulkCopy -SQLTable 'AzureUsersStaging' -sqlConnectionName 'MPT' -ValidateColumnMappings -TruncateSQLTable