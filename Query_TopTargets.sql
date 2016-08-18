SELECT 
	  -- P.[AssignmentType]
      --P.[PermissionType]) 
      --,P.[SourceExchangeOrganization]
      Count(P.[TrusteeObjectGUID]) AS TrusteeCount
	  ,P.[TargetDistinguishedName]
      ,P.[TargetObjectGUID]
      ,P.[TargetPrimarySMTPAddress]
      ,P.[TargetRecipientType]
      ,P.[TargetRecipientTypeDetails]
      --,P.[TrusteeDistinguishedName]
      --,P.[TrusteeGroupObjectGUID]
      --,P.[TrusteeIdentity]
      --,P.[TrusteePrimarySMTPAddress]
	  ,A.[enabled] AS TargetEnabled
      --,P.[TrusteeRecipientType]
      --,P.[TrusteeRecipientTypeDetails]
  FROM [MigrationPAndT].[dbo].[ExchangePermissionsStaging] As P
  LEFT JOIN dbo.ADUsers As A ON P.TargetObjectGUID = A.ObjectGUID
  WHERE 
	--remove quest objects
	[TargetDistinguishedName] NOT LIKE '%quest%' AND [TrusteeDistinguishedName] NOT LIKE '%quest%'
	--remove SendAS permissions
	AND [PermissionType] IN ('SendOnBehalf','FullAccess','None')
	--remove group based permissions
	AND [AssignmentType] IN ('Direct','None') AND [TrusteeRecipientType] NOT LIKE '%Group'
	--remove disabled Trustees
	AND A.[enabled] IS NOT NULL
	--remove Trustees that are already migrated and Targets that are already migrated
	AND [TrusteeRecipientTypeDetails] NOT IN ('RemoteUserMailbox') AND [TargetRecipientTypeDetails] NOT IN ('RemoteUserMailbox')
GROUP BY 
      P.[TargetDistinguishedName]
      ,P.[TargetObjectGUID]
      ,P.[TargetPrimarySMTPAddress]
      ,P.[TargetRecipientType]
      ,P.[TargetRecipientTypeDetails]
	  ,A.[enabled]
HAVING Count(TrusteeObjectGuid) > 9
ORDER BY TrusteeCount Desc;