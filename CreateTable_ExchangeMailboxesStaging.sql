USE [MigrationPandT];
SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
CREATE TABLE [dbo].[ExchangeMailboxesStaging](
    SourceOrganization  [nvarchar](36) NULL,
    AcceptMessagesOnlyFrom [nvarchar](max) NULL,
    AcceptMessagesOnlyFromDLMembers [nvarchar](max) NULL,
    AcceptMessagesOnlyFromSendersOrMembers [nvarchar](max) NULL,
    AddressListMembership [nvarchar](max) NULL,
    ArchiveName [nvarchar](max) NULL,
    AuditAdmin [nvarchar](max) NULL,
    AuditDelegate [nvarchar](max) NULL,
    AuditOwner [nvarchar](max) NULL,
    BypassModerationFromSendersOrMembers [nvarchar](max) NULL,
    EmailAddresses [nvarchar](max) NULL,
    ExtensionCustomAttribute1 [nvarchar](max) NULL,
    ExtensionCustomAttribute2 [nvarchar](max) NULL,
    ExtensionCustomAttribute3 [nvarchar](max) NULL,
    ExtensionCustomAttribute4 [nvarchar](max) NULL,
    ExtensionCustomAttribute5 [nvarchar](max) NULL,
    GrantSendOnBehalfTo [nvarchar](max) NULL,
    Languages [nvarchar](max) NULL,
    MailTipTranslations [nvarchar](max) NULL,
    ModeratedBy [nvarchar](max) NULL,
    ObjectClass [nvarchar](max) NULL,
    PersistedCapabilities [nvarchar](max) NULL,
    PoliciesExcluded [nvarchar](max) NULL,
    PoliciesIncluded [nvarchar](max) NULL,
    ProtocolSettings [nvarchar](max) NULL,
    RejectMessagesFrom [nvarchar](max) NULL,
    RejectMessagesFromDLMembers [nvarchar](max) NULL,
    RejectMessagesFromSendersOrMembers [nvarchar](max) NULL,
    ResourceCustom [nvarchar](max) NULL,
    AddressBookPolicy [nvarchar](1024) NULL,
    ActiveSyncMailboxPolicy [nvarchar](1024) NULL,
    ActiveSyncMailboxPolicyIsDefaulted [nvarchar](1024) NULL,
    AddressBookPolicy [nvarchar](1024) NULL,
    Alias [nvarchar](64) NULL,
    AntispamBypassEnabled [nvarchar](1024) NULL,
    ArchiveDatabase [nvarchar](1024) NULL,
    ArchiveDomain [nvarchar](1024) NULL,
    ArchiveQuota [nvarchar](1024) NULL,
    ArchiveStatus [nvarchar](1024) NULL,
    ArchiveWarningQuota [nvarchar](1024) NULL,
    AuthenticationType [nvarchar](1024) NULL,
    AuditEnabled [nvarchar](1024) NULL,
    AuditLogAgeLimit [nvarchar](1024) NULL,
    CalendarRepairDisabled [nvarchar](1024) NULL,
    CalendarVersionStoreDisabled [nvarchar](1024) NULL,
    CustomAttribute1 [nvarchar](1024) NULL,
    CustomAttribute10 [nvarchar](1024) NULL,
    CustomAttribute11 [nvarchar](1024) NULL,
    CustomAttribute12 [nvarchar](1024) NULL,
    CustomAttribute13 [nvarchar](1024) NULL,
    CustomAttribute14 [nvarchar](1024) NULL,
    CustomAttribute15 [nvarchar](1024) NULL,
    CustomAttribute2 [nvarchar](1024) NULL,
    CustomAttribute3 [nvarchar](1024) NULL,
    CustomAttribute4 [nvarchar](1024) NULL,
    CustomAttribute5 [nvarchar](1024) NULL,
    CustomAttribute6 [nvarchar](1024) NULL,
    CustomAttribute7 [nvarchar](1024) NULL,
    CustomAttribute8 [nvarchar](1024) NULL,
    CustomAttribute9 [nvarchar](1024) NULL,
    Database [nvarchar](1024) NULL,
    DeliverToMailboxAndForward [nvarchar](1024) NULL,
    DisabledArchiveDatabase [nvarchar](1024) NULL,
    Department [nvarchar](64) NULL,
    DisplayName [nvarchar](1024) NULL,
    DistinguishedName [nvarchar](1024) NULL,
    DowngradeHighPriorityMessagesEnabled [nvarchar](1024) NULL,
    EmailAddressPolicyEnabled [nvarchar](1024) NULL,
    ExchangeSecurityDescriptor [nvarchar](1024) NULL,
    ExchangeUserAccountControl [nvarchar](1024) NULL,
    ExchangeVersion [nvarchar](1024) NULL,
    ExternalDirectoryObjectId [nvarchar](1024) NULL,
    ExternalOofOptions [nvarchar](1024) NULL,
    ForwardingAddress [nvarchar](1024) NULL,
    ForwardingSmtpAddress [nvarchar](1024) NULL,
    HasPicture [nvarchar](1024) NULL,
    HasSpokenName [nvarchar](1024) NULL,
    HiddenFromAddressListsEnabled [nvarchar](1024) NULL,
    Identity [nvarchar](1024) NULL,
    ImmutableId [nvarchar](1024) NULL,
    IsLinked [nvarchar](1024) NULL,
    IsMailboxEnabled [nvarchar](1024) NULL,
    IsResource [nvarchar](1024) NULL,
    IsShared [nvarchar](1024) NULL,
    IsValid [nvarchar](1024) NULL,
    LastExchangeChangedTime [nvarchar](1024) NULL,
    LegacyExchangeDN [nvarchar](max) NULL,
    LinkedMasterAccount [nvarchar](1024) NULL,
    LitigationHoldDate [nvarchar](1024) NULL,
    LitigationHoldEnabled [nvarchar](1024) NULL,
    LitigationHoldOwner [nvarchar](1024) NULL,
    MailboxMoveBatchName [nvarchar](1024) NULL,
    MailboxMoveFlags [nvarchar](1024) NULL,
    MailboxMoveRemoteHostName [nvarchar](1024) NULL,
    MailboxMoveSourceMDB [nvarchar](1024) NULL,
    MailboxMoveStatus [nvarchar](1024) NULL,
    MailboxMoveTargetMDB [nvarchar](1024) NULL,
    MailboxPlan [nvarchar](1024) NULL,
    MailTip [nvarchar](1024) NULL,
    ManagedFolderMailboxPolicy [nvarchar](1024) NULL,
    MaxBlockedSenders [nvarchar](1024) NULL,
    MaxReceiveSize [nvarchar](1024) NULL,
    MaxSafeSenders [nvarchar](1024) NULL,
    MaxSendSize [nvarchar](1024) NULL,
    MessageTrackingReadStatusEnabled [nvarchar](1024) NULL,
    ModerationEnabled [nvarchar](1024) NULL,
    Name [nvarchar](255) NULL,
    ObjectCategory [nvarchar](1024) NULL,
    Office [nvarchar](1024) NULL,
    OfflineAddressBook [nvarchar](1024) NULL,
    OrganizationalUnit [nvarchar](1024) NULL,
    OrganizationId [nvarchar](1024) NULL,
    OriginatingServer [nvarchar](1024) NULL,
    PrimarySmtpAddress [nvarchar](1024) NULL,
    PSComputerName [nvarchar](1024) NULL,
    PSShowComputerName [nvarchar](1024) NULL,
    RecipientLimits [nvarchar](1024) NULL,
    RecipientType [nvarchar](1024) NULL,
    RecipientTypeDetails [nvarchar](1024) NULL,
    RecoverableItemsQuota [nvarchar](1024) NULL,
    RecoverableItemsWarningQuota [nvarchar](1024) NULL,
    RemoteAccountPolicy [nvarchar](1024) NULL,
    RemoteRecipientType [nvarchar](1024) NULL,
    RequireSenderAuthenticationEnabled [nvarchar](1024) NULL,
    ResourceCapacity [nvarchar](1024) NULL,
    ResourceType [nvarchar](1024) NULL,
    RetainDeletedItemsFor [nvarchar](1024) NULL,
    RetainDeletedItemsUntilBackup [nvarchar](1024) NULL,
    RetentionComment [nvarchar](1024) NULL,
    RetentionHoldEnabled [nvarchar](1024) NULL,
    RetentionPolicy [nvarchar](1024) NULL,
    RetentionUrl [nvarchar](1024) NULL,
    RoleAssignmentPolicy [nvarchar](1024) NULL,
    RulesQuota [nvarchar](1024) NULL,
    SamAccountName [nvarchar](256) NULL,
    SCLDeleteEnabled [nvarchar](1024) NULL,
    SCLDeleteThreshold [nvarchar](1024) NULL,
    SCLJunkEnabled [nvarchar](1024) NULL,
    SCLJunkThreshold [nvarchar](1024) NULL,
    SCLQuarantineEnabled [nvarchar](1024) NULL,
    SCLQuarantineThreshold [nvarchar](1024) NULL,
    SCLRejectEnabled [nvarchar](1024) NULL,
    SCLRejectThreshold [nvarchar](1024) NULL,
    SendModerationNotifications [nvarchar](1024) NULL,
    ServerLegacyDN [nvarchar](1024) NULL,
    ServerName [nvarchar](1024) NULL,
    SharingPolicy [nvarchar](1024) NULL,
    SimpleDisplayName [nvarchar](1024) NULL,
    SingleItemRecoveryEnabled [nvarchar](1024) NULL,
    SKUAssigned [nvarchar](1024) NULL,
    StartDateForRetentionHold [nvarchar](1024) NULL,
    ThrottlingPolicy [nvarchar](1024) NULL,
    UMEnabled [nvarchar](1024) NULL,
    UsageLocation [nvarchar](1024) NULL,
    UseDatabaseQuotaDefaults [nvarchar](1024) NULL,
    UseDatabaseRetentionDefaults [nvarchar](1024) NULL,
    UserPrincipalName [nvarchar](1024) NULL,
    WhenChanged [nvarchar](1024) NULL,
    WhenChangedUTC [nvarchar](1024) NULL,
    WhenCreated [nvarchar](1024) NULL,
    WhenCreatedUTC [nvarchar](1024) NULL,
    WhenMailboxCreated [nvarchar](1024) NULL,
    WindowsEmailAddress [nvarchar](1024) NULL,
    WindowsLiveID [nvarchar](1024) NULL
);