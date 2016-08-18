SELECT 
	E.PrimarySMTPAddress
	, A.userPrincipalName
	, A.ObjectGUID
	, A.employeeNumber
	, A.[enabled]
	, A.DistinguishedName
	, A.department
	, A.company
	, A.city
	, A.Notes
	, E.RecipientTypeDetails AS OPRecipientType
	, O.RecipientTypeDetails AS EOLRecipientType
	, O.PrimarySmtpAddress AS EOLPrimarySMTP
	, S.ItemCount
	, S.TotalItemSizeInGB
	, S.DeletedItemCount
	, S.TotalDeletedItemSizeInGB
	, (SELECT STUFF ((Select DISTINCT ('| ' + CA.userPrincipalName + ' ' + coalesce(''+CAST(CW.Wave AS nvarchar),'')) FROM [dbo].[ExchangePermissionsStaging] AS EPS LEFT JOIN dbo.ADUsers AS CA ON EPS.TrusteeObjectGUID = CA.ObjectGUID LEFT JOIN dbo.WaveMembers AS CW ON CA.ObjectGUID = CW.ObjectGUID WHERE EPS.TargetObjectGUID = A.ObjectGUID AND EPS.PermissionType IN ('SendOnBehalf','FullAccess') AND (CW.WAVE IS NULL OR CW.Wave <> W.Wave) FOR XML PATH('')), 1,1,'')) AS TrusteeAndWave
	, (Select Count(TT.UserPrincipalName) AS TargetCount FROM (Select DISTINCT CA.userPrincipalName FROM [dbo].[ExchangePermissionsStaging] AS EPS LEFT JOIN dbo.ADUsers AS CA ON EPS.TrusteeObjectGUID = CA.ObjectGUID LEFT JOIN dbo.WaveMembers AS CW ON CA.ObjectGUID = CW.ObjectGUID WHERE EPS.TargetObjectGUID = A.ObjectGUID AND EPS.PermissionType IN ('SendOnBehalf','FullAccess') AND (CW.WAVE IS NULL OR CW.Wave <> W.Wave)) AS TT) AS TrusteeCount
	, (SELECT STUFF ((Select DISTINCT ('| ' + CA.userPrincipalName + ' ' + coalesce(''+CAST(CW.Wave AS nvarchar),'')) FROM [dbo].[ExchangePermissionsStaging] AS EPS LEFT JOIN dbo.ADUsers AS CA ON EPS.TargetObjectGUID = CA.ObjectGUID LEFT JOIN dbo.WaveMembers AS CW ON CA.ObjectGUID = CW.ObjectGUID WHERE EPS.TrusteeObjectGUID = A.ObjectGUID AND EPS.PermissionType IN ('SendOnBehalf','FullAccess') AND (CW.WAVE IS NULL OR CW.Wave <> W.Wave) FOR XML PATH('')), 1,1,'')) AS TargetAndWave
	, (Select Count(TG.UserPrincipalName) AS TargetCount FROM (Select DISTINCT CA.userPrincipalName FROM [dbo].[ExchangePermissionsStaging] AS EPS LEFT JOIN dbo.ADUsers AS CA ON EPS.TargetObjectGUID = CA.ObjectGUID LEFT JOIN dbo.WaveMembers AS CW ON CA.ObjectGUID = CW.ObjectGUID WHERE EPS.TrusteeObjectGUID = A.ObjectGUID AND EPS.PermissionType IN ('SendOnBehalf','FullAccess') AND (CW.WAVE IS NULL OR CW.Wave <> W.Wave)) AS TG) AS TargetCount
	, W.Wave
FROM (SELECT 
	PrimarySmtpAddress
	,RecipientTypeDetails
	,GUID
	FROM dbo.ExchangeRecipientsStaging 
	WHERE SourceOrganization = 'EMD' 
	AND RecipientType LIKE '%mailbox%'
	AND RecipientTypeDetails NOT LIKE 'Remote%') 
	AS E 
LEFT JOIN
	(SELECT PrimarySmtpAddress,RecipientTypeDetails 
	FROM dbo.ExchangeRecipientsStaging 
	WHERE SourceOrganization = 'OL') 
	AS O
ON  O.PrimarySmtpAddress = E.PrimarySmtpAddress
JOIN dbo.ADUsers AS A
ON E.Guid = A.ObjectGUID
LEFT JOIN dbo.MailboxStatisticsStaging AS S
ON A.msExchMailboxGUID = S.MailboxGuid
LEFT JOIN dbo.WaveMembers AS W
ON A.ObjectGUID = W.objectGUID
ORDER BY W.Wave;