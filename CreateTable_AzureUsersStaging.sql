CREATE TABLE [dbo].[AzureUsersStaging](
	--[ID] [int] IDENTITY(1,1) NOT NULL,
    SourceOrganization [nvarchar](510) NULL,
	AlternateEmailAddresses [nvarchar](1024) NULL,
	AlternateMobilePhones [nvarchar](1024) NULL,
	--AlternativeSecurityIds [nvarchar](1024) NULL,
	BlockCredential [nvarchar](510) NULL,
	City [nvarchar](510) NULL,
	CloudExchangeRecipientDisplayType [nvarchar](510) NULL,
	Country [nvarchar](510) NULL,
	Department [nvarchar](510) NULL,
	--DirSyncProvisioningErrors [nvarchar](1024) NULL,
	DisplayName [nvarchar](510) NULL,
	--Errors
	--ExtensionData
	Fax [nvarchar](510) NULL,
	FirstName [nvarchar](510) NULL,
	ImmutableId [nvarchar](510) NULL,
	--IndirectLicenseErrors
	IsBlackberryUser [nvarchar](510) NULL,
	IsLicensed [nvarchar](510) NULL,
	LastDirSyncTime [nvarchar](510) NULL,
	LastName [nvarchar](510) NULL,
	LastPasswordChangeTimestamp [nvarchar](510) NULL,
	LicenseReconciliationNeeded [nvarchar](510) NULL,
	Licenses [nvarchar](1024) NULL,
    ServiceStatus [nvarchar](1024) NULL,
	LiveId [nvarchar](510) NULL,
	MobilePhone [nvarchar](510) NULL,
	MSExchRecipientTypeDetails [nvarchar](510) NULL,
	MSRtcSipDeploymentLocator [nvarchar](510) NULL,
	MSRtcSipPrimaryUserAddress [nvarchar](510) NULL,
	ObjectId [nvarchar](510) NULL,
	Office [nvarchar](510) NULL,
	OverallProvisioningStatus [nvarchar](510) NULL,
	PasswordNeverExpires [nvarchar](510) NULL,
	PasswordResetNotRequiredDuringActivate [nvarchar](510) NULL,
	PhoneNumber [nvarchar](510) NULL,
	--PortalSettings
	PostalCode [nvarchar](510) NULL,
	PreferredLanguage [nvarchar](510) NULL,
	ProxyAddresses [nvarchar](max) NULL,
	ReleaseTrack [nvarchar](510) NULL,
	--ServiceInformation
	SignInName [nvarchar](510) NULL,
	SoftDeletionTimestamp [nvarchar](510) NULL,
	State [nvarchar](510) NULL,
	StreetAddress [nvarchar](510) NULL,
	--StrongAuthenticationMethods
	--StrongAuthenticationPhoneAppDetails
	--StrongAuthenticationProofupTime
	--StrongAuthenticationRequirements
	--StrongAuthenticationUserDetails
	StrongPasswordRequired [nvarchar](510) NULL,
	StsRefreshTokensValidFrom [nvarchar](510) NULL,
	Title [nvarchar](510) NULL,
	UsageLocation [nvarchar](510) NULL,
	UserLandingPageIdentifierForO365Shell [nvarchar](510) NULL,
	UserPrincipalName [nvarchar](510) NULL,
	UserThemeIdentifierForO365Shell [nvarchar](510) NULL,
	UserType [nvarchar](510) NULL,
	ValidationStatus [nvarchar](510) NULL,
	WhenCreated [nvarchar](510) NULL
);