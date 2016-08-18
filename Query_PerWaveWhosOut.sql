DECLARE @Wave NUMERIC;
DECLARE @WaveMembers TABLE (ObjectGUID [nvarchar](36));
SET @Wave = 4.00;
Insert INTO @WaveMembers (ObjectGUID)
Select ObjectGUID FROM WaveMembers WHERE Wave = @Wave;

Select 
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
	,'Target' AS ConnectionType
	,Count(EPS.TrusteeObjectGUID) AS ConnectionCount
	, W.Wave
FROM [dbo].[ExchangePermissionsStaging] AS EPS 
JOIN dbo.ADUsers AS A 
ON EPS.TargetObjectGUID = A.ObjectGUID 
LEFT JOIN dbo.WaveMembers AS W 
ON A.ObjectGUID = W.ObjectGUID 
JOIN
(SELECT 
	PrimarySmtpAddress
	,RecipientTypeDetails
	,GUID
	FROM dbo.ExchangeRecipientsStaging 
	WHERE SourceOrganization = 'EMD' 
	AND RecipientType LIKE '%mailbox%'
	AND RecipientTypeDetails NOT LIKE 'Remote%') 
	AS E 
ON E.Guid = A.ObjectGUID
WHERE EPS.TargetObjectGUID NOT IN (Select ObjectGUID FROM @WaveMembers)
	AND EPS.TrusteeObjectGUID IN (Select ObjectGUID FROM @WaveMembers)
	AND EPS.PermissionType IN ('SendOnBehalf','FullAccess') 
GROUP BY 	
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
	, E.RecipientTypeDetails
	, W.Wave
UNION
Select 	
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
	,'Trustee' AS ConnectionType,
	Count(EPS.TargetObjectGUID) AS ConnectionCount
	, W.Wave
FROM [dbo].[ExchangePermissionsStaging] AS EPS 
JOIN dbo.ADUsers AS A 
ON EPS.TrusteeObjectGUID = A.ObjectGUID 
LEFT JOIN dbo.WaveMembers AS W 
ON A.ObjectGUID = W.ObjectGUID
JOIN
(SELECT 
	PrimarySmtpAddress
	,RecipientTypeDetails
	,GUID
	FROM dbo.ExchangeRecipientsStaging 
	WHERE SourceOrganization = 'EMD' 
	AND RecipientType LIKE '%mailbox%'
	AND RecipientTypeDetails NOT LIKE 'Remote%') 
	AS E 
ON E.Guid = A.ObjectGUID
WHERE EPS.TrusteeObjectGUID NOT IN (Select ObjectGUID FROM @WaveMembers)
	AND EPS.TargetObjectGUID IN (Select ObjectGUID FROM @WaveMembers)
	AND EPS.PermissionType IN ('SendOnBehalf','FullAccess') 
GROUP BY 
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
	, E.RecipientTypeDetails
	, W.Wave
ORDER BY ConnectionCount DESC;

