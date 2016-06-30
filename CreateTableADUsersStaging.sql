USE [MigrationPandT];
SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
CREATE TABLE [dbo].[ADUsersStaging](
    altRecipient [nvarchar](510) NULL,
    c [nvarchar](510) NULL,
    CanonicalName [nvarchar](510) NULL,
    cn [nvarchar](510) NULL,
    co [nvarchar](510) NULL,
    country [nvarchar](510) NULL,
    deliverandRedirect [nvarchar](510) NULL,
    department [nvarchar](510) NULL,
    displayName [nvarchar](510) NULL,
    DistinguishedName [nvarchar](510) NULL,
    employeeID [nvarchar](510) NULL,
    employeeNumber [nvarchar](510) NULL,
    extensionattribute1 [nvarchar](510) NULL,
    extensionattribute10 [nvarchar](510) NULL,
    extensionattribute11 [nvarchar](510) NULL,
    extensionattribute12 [nvarchar](510) NULL,
    extensionattribute13 [nvarchar](510) NULL,
    extensionattribute14 [nvarchar](510) NULL,
    extensionattribute15 [nvarchar](510) NULL,
    extensionattribute2 [nvarchar](510) NULL,
    extensionattribute3 [nvarchar](510) NULL,
    extensionattribute4 [nvarchar](510) NULL,
    extensionattribute5 [nvarchar](510) NULL,
    extensionattribute6 [nvarchar](510) NULL,
    extensionattribute7 [nvarchar](510) NULL,
    extensionattribute8 [nvarchar](510) NULL,
    extensionattribute9 [nvarchar](510) NULL,
    forwardingAddress [nvarchar](510) NULL,
    GivenName [nvarchar](510) NULL,
    homeMDB [nvarchar](510) NULL,
    homeMTA [nvarchar](510) NULL,
    legacyExchangeDN [nvarchar](510) NULL,
    Mail [nvarchar](510) NULL,
    mailNickname [nvarchar](510) NULL,
    memberof [nvarchar](510) NULL,
    mS-DS-ConsistencyGuid [nvarchar](510) NULL,
    msExchArchiveGUID [nvarchar](510) NULL,
    msExchArchiveName [nvarchar](510) NULL,
    msexchextensioncustomattribute1 [nvarchar](1024) NULL,
    msexchextensioncustomattribute2 [nvarchar](1024) NULL,
    msexchextensioncustomattribute3 [nvarchar](1024) NULL,
    msexchextensioncustomattribute4 [nvarchar](1024) NULL,
    msexchextensioncustomattribute5 [nvarchar](1024) NULL,
    msExchGenericForwardingAddress [nvarchar](510) NULL,
    msExchHideFromAddressLists [nvarchar](510) NULL,
    msExchHomeServerName [nvarchar](510) NULL,
    msExchMailboxGUID [nvarchar](510) NULL,
    msExchMasterAccountSID [nvarchar](510) NULL,
    msExchPoliciesExcluded [nvarchar](510) NULL,
    msExchRecipientDisplayType [nvarchar](510) NULL,
    msExchRecipientTypeDetails [nvarchar](510) NULL,
    msExchRemoteRecipientType [nvarchar](510) NULL,
    msExchUsageLocation [nvarchar](510) NULL,
    msExchUserCulture [nvarchar](510) NULL,
    msExchVersion [nvarchar](510) NULL,
    ObjectGUID [nvarchar](510) NULL,
    physicalDeliveryOfficeName [nvarchar](510) NULL,
    proxyAddresses [nvarchar](1024) NULL,
    sAMAccountName [nvarchar](510) NULL,
    SourceOrganization [nvarchar](510) NULL,
    SurName [nvarchar](510) NULL,
    targetAddress [nvarchar](510) NULL,
    userPrincipalName [nvarchar](510) NULL
);