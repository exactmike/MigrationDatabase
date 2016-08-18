USE [MigrationPAndT];
SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
CREATE TABLE [dbo].[ExchangePermissionsStaging](
	[PermissionIdentity][bigint] NOT NULL,
	[ParentPermissionIdentity] [bigint] NULL,
	[AssignmentType] [nvarchar](50) NOT NULL,
	[PermissionType] [nvarchar](20) NOT NULL,
	[SourceExchangeOrganization] [nvarchar](50) NOT NULL,
	[TargetDistinguishedName] [nvarchar](256) NOT NULL,
	[TargetObjectGUID] [nvarchar](36) NOT NULL,
	[TargetPrimarySMTPAddress] [nvarchar](256) NULL,
	[TargetRecipientType] [nvarchar](100) NOT NULL,
	[TargetRecipientTypeDetails] [nvarchar](100) NOT NULL,
	[TrusteeDistinguishedName] [nvarchar](256) NULL,
	[TrusteeGroupObjectGUID] [nvarchar](36) NULL,
	[TrusteeIdentity] [nvarchar](256) NOT NULL,
	[TrusteeObjectGUID] [nvarchar](36) NULL,
	[TrusteePrimarySMTPAddress] [nvarchar](256) NULL,
	[TrusteeRecipientType] [nvarchar](100) NULL,
	[TrusteeRecipientTypeDetails] [nvarchar](100) NULL,
) ON [PRIMARY]
;
