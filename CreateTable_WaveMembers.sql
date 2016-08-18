USE [MigrationPAndT]
GO

/****** Object:  Table [dbo].[WaveMembers]    Script Date: 8/18/2016 2:03:04 PM ******/
SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO

CREATE TABLE [dbo].[WaveMembers](
	[Wave] [numeric](3, 2) NOT NULL,
	[ObjectGUID] [nvarchar](36) NOT NULL
) ON [PRIMARY]

GO

