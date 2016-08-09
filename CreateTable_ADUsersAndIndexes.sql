USE [MigrationPAndT];
SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
CREATE TABLE [dbo].[ADUsers](
	[ID] [int] IDENTITY(1,1) NOT NULL,
	[ObjectGUID] [nchar](36) NOT NULL,
	[altRecipient] [nvarchar](256) NULL,
	[c] [nchar](2) NULL,
	[CanonicalName] [nvarchar](256) NULL,
	[cn] [nvarchar](256) NULL,
	[co] [nvarchar](256) NULL,
	[country] [nvarchar](256) NULL,
	[deliverandRedirect] [nvarchar](5) NULL,
	[department] [nvarchar](64) NULL,
	[displayName] [nvarchar](256) NULL,
	[DistinguishedName] [nvarchar](256) NULL,
	[employeeID] [nvarchar](16) NULL,
	[employeeNumber] [nvarchar](512) NULL,
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
	[homeMDB] [nvarchar](max) NULL,
	[homeMTA] [nvarchar](max) NULL,
	[legacyExchangeDN] [nvarchar](max) NULL,
	[Mail] [nvarchar](256) NULL,
	[mailNickname] [nvarchar](64) NULL,
	[memberof] [nvarchar](max) NULL,
	[mS-DS-ConsistencyGuid] [nchar](36) NULL,
	[msExchArchiveGUID] [nchar](36) NULL,,
	[msExchArchiveName] [nvarchar](max) NULL,
	[msexchextensioncustomattribute1] [nvarchar](max) NULL,
	[msexchextensioncustomattribute2] [nvarchar](max) NULL,
	[msexchextensioncustomattribute3] [nvarchar](max) NULL,
	[msexchextensioncustomattribute4] [nvarchar](max) NULL,
	[msexchextensioncustomattribute5] [nvarchar](max) NULL,
	[msExchGenericForwardingAddress] [nvarchar](max) NULL,
	[msExchHideFromAddressLists] [nvarchar](max) NULL,
	[msExchHomeServerName] [nvarchar](max) NULL,
	[msExchMailboxGUID] [nchar](36) NULL,
	[msExchMasterAccountSID] [nvarchar](max) NULL,
	[msExchPoliciesExcluded] [nvarchar](max) NULL,
	[msExchRecipientDisplayType] [nvarchar](max) NULL,
	[msExchRecipientTypeDetails] [nvarchar](max) NULL,
	[msExchRemoteRecipientType] [nvarchar](max) NULL,
	[msExchUsageLocation] [nvarchar](max) NULL,
	[msExchUserCulture] [nvarchar](max) NULL,
	[msExchVersion] [nvarchar](max) NULL,
	[physicalDeliveryOfficeName] [nvarchar](max) NULL,
	[proxyAddresses] [nvarchar](max) NULL,
	[sAMAccountName] [nvarchar](256) NULL,
	[SourceOrganization] [nvarchar](10) NOT NULL,
	[SurName] [nvarchar](64) NULL,
	[targetAddress] [nvarchar](2048) NULL,
	[userPrincipalName] [nvarchar](1024) NULL,
 CONSTRAINT [PK_ADUsers] PRIMARY KEY NONCLUSTERED 
(
	[ObjectGUID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY];
CREATE UNIQUE CLUSTERED INDEX [CIX_ADUsers] ON [dbo].[ADUsers]
(
	[ID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, SORT_IN_TEMPDB = OFF, IGNORE_DUP_KEY = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON);
CREATE NONCLUSTERED INDEX [NCI_SourceMailUPN] ON [dbo].[ADUsers]
(
	[Mail] ASC,
	[SourceOrganization] ASC,
	[userPrincipalName] ASC
)
INCLUDE ( 	[proxyAddresses],
	[sAMAccountName],
	[targetAddress]) WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, SORT_IN_TEMPDB = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON);
