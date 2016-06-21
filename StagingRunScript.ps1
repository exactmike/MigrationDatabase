$AzureADUsersExport = Export-AzureUsers
$AzureADUsersDataTable = Convert-PSObjectToDataTable -InputObject $AzureADUsersExport
Import-DataTableToSQLBulkCopy -SQLTable 'AzureUsersStaging' -Database $MigrationDatabaseSQLDB -ConnectionString $SQLConnectionString -DataTable $AzureADUsersDataTable -ValidateColumnMappings -TruncateSQLTable 