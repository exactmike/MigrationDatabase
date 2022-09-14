CREATE TABLE [dbo].[ADUsers](
	[ID] [int] IDENTITY(1,1) NOT NULL,
	[ObjectGUID] [nchar](36) NOT NULL,
    ExpectedAzureADImmutableID [nvarchar](24) NULL,
	[AccountExpirationDate] [datetime] NULL,
	[altRecipient] [nvarchar](256) NULL,
	[c] [nchar](2) NULL,
	[CanonicalName] [nvarchar](256) NULL,
	[city] [nvarchar](64) NULL,
	[cn] [nvarchar](256) NULL,
	[co] [nvarchar](256) NULL,
    [company] [nvarchar](64) NULL,
	[country] [nvarchar](256) NULL,
    [createTimeStamp] [datetime] NULL,
	[deliverandRedirect] [nvarchar](5) NULL,
	[department] [nvarchar](64) NULL,
	[displayName] [nvarchar](256) NULL,
	[DistinguishedName] [nvarchar](256) NULL,
	[employeeID] [nvarchar](16) NULL,
	[employeeNumber] [nvarchar](512) NULL,
	[enabled][bit] NULL,
	[extensionattribute1] [nvarchar](1024) NULL,
	[extensionattribute10] [nvarchar](1024) NULL,
	[extensionattribute11] [nvarchar](1024) NULL,
	[extensionattribute12] [nvarchar](1024) NULL,
	[extensionattribute13] [nvarchar](1024) NULL,
	[extensionattribute14] [nvarchar](1024) NULL,
	[extensionattribute15] [nvarchar](1024) NULL,
	[extensionattribute2] [nvarchar](1024) NULL,
	[extensionattribute3] [nvarchar](1024) NULL,
	[extensionattribute4] [nvarchar](1024) NULL,
	[extensionattribute5] [nvarchar](1024) NULL,
	[extensionattribute6] [nvarchar](1024) NULL,
	[extensionattribute7] [nvarchar](1024) NULL,
	[extensionattribute8] [nvarchar](1024) NULL,
	[extensionattribute9] [nvarchar](1024) NULL,
	[forwardingAddress] [nvarchar](256) NULL,
	[GivenName] [nvarchar](64) NULL,
	[homeMDB] [nvarchar](256) NULL,
	[homeMTA] [nvarchar](256) NULL,
	[LastLogonDate] [datetime] NULL,
	[legacyExchangeDN] [nvarchar](256) NULL,
	[Mail] [nvarchar](256) NULL,
	[mailNickname] [nvarchar](64) NULL,
	[memberof] [nvarchar](max) NULL,
    [modifyTimeStamp] [datetime] NULL,
	[mS-DS-ConsistencyGuid] [nchar](36) NULL,
	[msExchArchiveGUID] [nchar](36) NULL,
	[msExchArchiveName] [nvarchar](256) NULL,
	[msexchextensioncustomattribute1] [nvarchar](max) NULL,
	[msexchextensioncustomattribute2] [nvarchar](max) NULL,
	[msexchextensioncustomattribute3] [nvarchar](max) NULL,
	[msexchextensioncustomattribute4] [nvarchar](max) NULL,
	[msexchextensioncustomattribute5] [nvarchar](max) NULL,
	[msExchGenericForwardingAddress] [nvarchar](max) NULL,
	[msExchHideFromAddressLists] [nvarchar](256) NULL,
	[msExchHomeServerName] [nvarchar](256) NULL,
	[msExchMailboxGUID] [nchar](36) NULL,
	[msExchMasterAccountSID] [nvarchar](256) NULL,
	[msExchPoliciesExcluded] [nvarchar](256) NULL,
	[msExchRecipientDisplayType] [nvarchar](256) NULL,
	[msExchRecipientTypeDetails] [nvarchar](256) NULL,
	[msExchRemoteRecipientType] [nvarchar](256) NULL,
	[msExchUsageLocation] [nvarchar](256) NULL,
	[msExchUserCulture] [nvarchar](256) NULL,
	[msExchVersion] [nvarchar](256) NULL,
	[msExchWhenMailboxCreated] [datetime] NULL,
	[notes][nvarchar](max),
	[physicalDeliveryOfficeName] [nvarchar](256) NULL,
	[proxyAddresses] [nvarchar](max) NULL,
	[sAMAccountName] [nvarchar](256) NULL,
	[SourceOrganization] [nvarchar](10) NOT NULL,
	[SurName] [nvarchar](64) NULL,
	[targetAddress] [nvarchar](2048) NULL,
	[userPrincipalName] [nvarchar](1024) NULL,
    [whenChanged] [datetime] NULL,
    [whenCreated] [datetime] NULL
 CONSTRAINT [PK_ADUsers] PRIMARY KEY NONCLUSTERED
(
	[ObjectGUID] ASC
));

CREATE UNIQUE CLUSTERED INDEX [CIX_ADUsers] ON [dbo].[ADUsers]
(
	[ID] ASC
);

CREATE NONCLUSTERED INDEX [NCI_Mail] ON [dbo].[ADUsers]
(
	[Mail] ASC
)
INCLUDE (
	[SamAccountName],
	[targetAddress],
	[SourceOrganization],
	[userPrincipalName]
) ;
CREATE NONCLUSTERED INDEX [NCI_SourceOrganization] ON [dbo].[ADUsers]
(
	[SourceOrganization] ASC
)
INCLUDE (
	[Mail],
	[SamAccountName],
	[targetAddress],
	[userPrincipalName]
) ;
