USE [MigrationPandT];
SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
CREATE TABLE [dbo].[ADUsersStaging](
    altRecipient [nvarchar](MAX) NULL,
    c [nvarchar](MAX) NULL,
    CanonicalName [nvarchar](MAX) NULL,
	city [nvarchar](128) NULL,
    cn [nvarchar](MAX) NULL,
    co [nvarchar](MAX) NULL,
    country [nvarchar](MAX) NULL,
    company [nvarchar] (64) NULL,
    deliverandRedirect [nvarchar](MAX) NULL,
    department [nvarchar](MAX) NULL,
    displayName [nvarchar](MAX) NULL,
    DistinguishedName [nvarchar](MAX) NULL,
    employeeID [nvarchar](MAX) NULL,
    employeeNumber [nvarchar](MAX) NULL,
    [enabled] [nvarchar](MAX) NULL,
    extensionattribute1 [nvarchar](MAX) NULL,
    extensionattribute10 [nvarchar](MAX) NULL,
    extensionattribute11 [nvarchar](MAX) NULL,
    extensionattribute12 [nvarchar](MAX) NULL,
    extensionattribute13 [nvarchar](MAX) NULL,
    extensionattribute14 [nvarchar](MAX) NULL,
    extensionattribute15 [nvarchar](MAX) NULL,
    extensionattribute2 [nvarchar](MAX) NULL,
    extensionattribute3 [nvarchar](MAX) NULL,
    extensionattribute4 [nvarchar](MAX) NULL,
    extensionattribute5 [nvarchar](MAX) NULL,
    extensionattribute6 [nvarchar](MAX) NULL,
    extensionattribute7 [nvarchar](MAX) NULL,
    extensionattribute8 [nvarchar](MAX) NULL,
    extensionattribute9 [nvarchar](MAX) NULL,
    forwardingAddress [nvarchar](MAX) NULL,
    GivenName [nvarchar](MAX) NULL,
    homeMDB [nvarchar](MAX) NULL,
    homeMTA [nvarchar](MAX) NULL,
    legacyExchangeDN [nvarchar](MAX) NULL,
    Mail [nvarchar](MAX) NULL,
    mailNickname [nvarchar](MAX) NULL,
    memberof [nvarchar](MAX) NULL,
    [mS-DS-ConsistencyGuid] [nvarchar](MAX) NULL,
    msExchArchiveGUID [nvarchar](MAX) NULL,
    msExchArchiveName [nvarchar](MAX) NULL,
    msexchextensioncustomattribute1 [nvarchar](MAX) NULL,
    msexchextensioncustomattribute2 [nvarchar](MAX) NULL,
    msexchextensioncustomattribute3 [nvarchar](MAX) NULL,
    msexchextensioncustomattribute4 [nvarchar](MAX) NULL,
    msexchextensioncustomattribute5 [nvarchar](MAX) NULL,
    msExchGenericForwardingAddress [nvarchar](MAX) NULL,
    msExchHideFromAddressLists [nvarchar](MAX) NULL,
    msExchHomeServerName [nvarchar](MAX) NULL,
    msExchMailboxGUID [nvarchar](MAX) NULL,
    msExchMasterAccountSID [nvarchar](MAX) NULL,
    msExchWhenMailboxCreated [nvarchar](MAX) NULL,
    msExchPoliciesExcluded [nvarchar](MAX) NULL,
    msExchRecipientDisplayType [nvarchar](MAX) NULL,
    msExchRecipientTypeDetails [nvarchar](MAX) NULL,
    msExchRemoteRecipientType [nvarchar](MAX) NULL,
    msExchUsageLocation [nvarchar](MAX) NULL,
    msExchUserCulture [nvarchar](MAX) NULL,
    msExchVersion [nvarchar](MAX) NULL,
	physicalDeliveryOfficeName [nvarchar] (MAX) NULL,
    ObjectGUID [nvarchar](MAX) NULL,
    proxyAddresses [nvarchar](MAX) NULL,
    SamAccountName [nvarchar](MAX) NULL,
    SourceOrganization [nvarchar](MAX) NULL,
    SurName [nvarchar](MAX) NULL,
    targetAddress [nvarchar](MAX) NULL,
    userPrincipalName [nvarchar](MAX) NULL,
    whenChanged [nvarchar](MAX) NULL,
    whenCreated [nvarchar](MAX) NULL,
    AccountExpirationDate [nvarchar](MAX) NULL,
    LastLogonDate [nvarchar](MAX) NULL,
    createTimeStamp [nvarchar](MAX) NULL,
    modifyTimeStamp [nvarchar](MAX) NULL
);