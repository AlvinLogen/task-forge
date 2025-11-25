CREATE DATABASE TaskForge;
GO

USE TaskForge;
GO

CREATE TABLE Users (
    UserID INT IDENTITY(1,1) PRIMARY KEY,
    UserName NVARCHAR(50) UNIQUE NOT NULL,
    Email NVARCHAR(100) UNIQUE NOT NULL,
    PasswordHash NVARCHAR(255) NOT NULL,
    FirstName NVARCHAR(50) NOT NULL,
    LastName NVARCHAR(50) NOT NULL,
    Role NVARCHAR(20) DEFAULT 'User' CHECK (Role IN ('Admin', 'Manager', 'User')),
    IsActive BIT DEFAULT 1,
    CreatedAt DATETIME2 DEFAULT GETUTCDATE(),
    ModifiedAt DATETIME2 DEFAULT GETUTCDATE(),
    LastLoginAt DATETIME2,
    CONSTRAINT CK_Users_Email CHECK (Email LIKE '%_@_%.%')
);

CREATE TABLE Projects (
    ProjectID INT IDENTITY(1,1) PRIMARY KEY,
    ProjectName NVARCHAR(100) NOT NULL,
    Description NVARCHAR(500),
    OwnerID INT NOT NULL,
    Status NVARCHAR(20) DEFAULT 'Active' CHECK (Status IN ('Active', 'Completed', 'Archived', 'On Hold')),
    Priority NVARCHAR(10) DEFAULT 'Medium' CHECK (Priority IN ('Low', 'Medium', 'High', 'Critical')),
    StartDate DATE,
    EndDate DATE,
    CreatedAt DATETIME2 DEFAULT GETUTCDATE(),
    ModifiedAt DATETIME2 DEFAULT GETUTCDATE(),

    FOREIGN KEY (OwnerID) REFERENCES Users (UserID),
    CONSTRAINT CK_Projects_Dates CHECK (EndDate IS NULL OR EndDate >= StartDate)
);


CREATE TABLE Tasks (
    TaskID INT IDENTITY(1,1) PRIMARY KEY,
    ProjectID INT NOT NULL,
    TaskName NVARCHAR(200) NOT NULL,
    Description NVARCHAR(1000),
    AssignedToID INT,
    CreatedByID INT NOT NULL,
    Status NVARCHAR(20) DEFAULT 'New' CHECK (Status IN ('New', 'In Progress', 'Review', 'Completed', 'Blocked')),
    Priority NVARCHAR(10) DEFAULT 'Medium' CHECK (Priority IN ('Low', 'Medium', 'High', 'Critical')),
    EstimatedHours DECIMAL(5,2),
    ActualHours DECIMAL(5,2),
    DueDate DATETIME2, 
    CompletedAt DATETIME2,
    CreatedAt DATETIME2 DEFAULT GETUTCDATE(),
    ModifiedAt DATETIME2 DEFAULT GETUTCDATE(),

    FOREIGN KEY (ProjectID) REFERENCES Projects(ProjectID) ON DELETE CASCADE, -- If Project Deleted, Delete associated tasks
    FOREIGN KEY (AssignedToID) REFERENCES Users(UserID), 
    FOREIGN KEY (CreatedByID) REFERENCES Users(UserID)
);


CREATE NONCLUSTERED INDEX IX_Tasks_ProjectID ON Tasks(ProjectID); -- Find tasks by Project
CREATE NONCLUSTERED INDEX IX_Tasks_AssignedToID ON Tasks(AssignedToID); -- Find tasks by Assignee
CREATE NONCLUSTERED INDEX IX_Tasks_Status ON Tasks(Status); --Filter Tasks by Status
CREATE NONCLUSTERED INDEX IX_Tasks_DueDate ON Tasks(DueDate); --Sort Tasks by Due Date
CREATE NONCLUSTERED INDEX IX_Porjects_OwnerID ON Projects(OwnerID); --Find Projects by Owner
CREATE NONCLUSTERED INDEX IX_Users_Email ON Users(Email); -- Login by Email



