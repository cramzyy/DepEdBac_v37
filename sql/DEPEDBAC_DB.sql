-- DepEd BAC Document Tracking System Database Schema
-- Cleaned and optimized version

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+08:00";

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

-- Create database if it doesn't exist
CREATE DATABASE IF NOT EXISTS `DEPEDBAC_DB` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
USE `DEPEDBAC_DB`;

-- =========================================
-- MODE OF PROCUREMENT TABLE
-- =========================================

CREATE TABLE `mode_of_procurement` (
  `MoPID` int(11) NOT NULL AUTO_INCREMENT,
  `MoPDescription` varchar(255) NOT NULL,
  PRIMARY KEY (`MoPID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Insert procurement methods

INSERT INTO `mode_of_procurement` (`MoPID`, `MoPDescription`) VALUES
(1, 'Competitive Bidding'),
(2, 'Limited Source Bidding'),
(3, 'Direct Contracting'),
(4, 'Repeat Order'),
(5, 'Shopping'),
(6, 'NP-53.1 Two Failed Biddings'),
(7, 'NP-53.2 Emergency Cases'),
(8, 'Emergency Procurement under the Bayanihan Act'),
(9, 'NP-53.3 Take-over of Contracts'),
(10, 'NP-53.4 Adjacent or Contiguous'),
(11, 'NP-53.5 Agency-to-Agency'),
(12, 'NP-53.6 Scientific, Scholarly, Artistic Work, Exclusive Technology and Media Services'),
(13, 'NP-53.7 Highly Technical Consultants'),
(14, 'NP-53.8 Defense Cooperation Agreement'),
(15, 'NP-53.9 Small Value Procurement'),
(16, 'NP-53.10 Lease of Real Property and Venue'),
(17, 'NP-53.11 NGO Participation'),
(18, 'NP-53.12 Community Participation'),
(19, 'NP-53.13 UN Agencies, Intl Organizations or International Financing Institutions'),
(20, 'NP-53.14 Direct Retail Purchase of Petroleum Fuel, Oil and Lubricant (POL) Products and Airline Tickets'),
(21, 'Others - Foreign-funded procurement');

-- =========================================
-- OFFICE TABLE
-- =========================================

CREATE TABLE `officeid` (
  `officeID` int(11) NOT NULL AUTO_INCREMENT,
  `officename` varchar(255) NOT NULL,
  `officedetails` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`officeID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Insert office data

INSERT INTO `officeid` (`officeID`, `officename`, `officedetails`) VALUES
(1, 'OSDS', NULL),
(2, 'OASDS', NULL),
(3, 'ADMIN', NULL),
(4, 'SGOD CHIEF', NULL),
(5, 'CID CHIEF', NULL),
(6, 'CID', NULL),
(7, 'SGOD', NULL),
(8, 'RECORDS', NULL),
(9, 'BAC', NULL),
(10, 'CASH', NULL),
(11, 'BUDGET', NULL),
(12, 'PERSONNEL', NULL),
(13, 'PAYROLL', NULL),
(14, 'SUPPLY', NULL),
(15, 'IT', NULL),
(16, 'MEDICAL', NULL),
(17, 'DENTAL', NULL);

-- =========================================
-- STAGE REFERENCE TABLE
-- =========================================

CREATE TABLE `stage_reference` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `stageName` varchar(255) NOT NULL,
  `stageOrder` int(11) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Insert stage reference data

INSERT INTO `stage_reference` (`id`, `stageName`, `stageOrder`) VALUES
(1, 'Mode Of Procurement', 1),
(2, 'Purchase Request', 2),
(3, 'Philgeps Posting', 3),
(4, 'Certification of Posting', 4),
(5, 'Request For Quotation', 5),
(6, 'Abstract of Quotation', 6),
(7, 'Resolution to Award', 7),
(8, 'Notice of Award', 8),
(9, 'Purchase Order', 9),
(10, 'Notice to Proceed', 10);

-- =========================================
-- PROJECT TABLE
-- =========================================

CREATE TABLE `tblproject` (
  `projectID` int(11) NOT NULL AUTO_INCREMENT,
  `projectDetails` text DEFAULT NULL,
  `userID` int(11) DEFAULT NULL,
  `createdAt` datetime DEFAULT current_timestamp(),
  `editedAt` datetime DEFAULT NULL,
  `prNumber` varchar(20) NOT NULL,
  `projectStatus` varchar(20) DEFAULT 'in-progress',
  `editedBy` int(11) DEFAULT NULL,
  `lastAccessedAt` datetime DEFAULT NULL,
  `lastAccessedBy` int(11) DEFAULT NULL,
  `MoPID` int(11) DEFAULT NULL,
  `programOwner` varchar(255) DEFAULT NULL,
  `programOffice` varchar(255) DEFAULT NULL,
  `totalABC` int(11) DEFAULT NULL,
  PRIMARY KEY (`projectID`),
  UNIQUE KEY `prNumber` (`prNumber`),
  KEY `userID` (`userID`),
  KEY `fk_edited_by` (`editedBy`),
  KEY `fk_last_accessed_by` (`lastAccessedBy`),
  KEY `fk_project_mop` (`MoPID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- =========================================
-- PROJECT STAGES TABLE
-- =========================================

CREATE TABLE `tblproject_stages` (
  `stageID` int(11) NOT NULL AUTO_INCREMENT,
  `projectID` int(11) NOT NULL,
  `stageName` varchar(255) NOT NULL,
  `createdAt` datetime DEFAULT current_timestamp(),
  `approvedAt` datetime DEFAULT NULL,
  `officeID` int(11) DEFAULT NULL,
  `remarks` text DEFAULT NULL,
  `isSubmitted` tinyint(1) DEFAULT 0,
  PRIMARY KEY (`stageID`),
  KEY `projectID` (`projectID`),
  KEY `fk_stage_office` (`officeID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- =========================================
-- USER TABLE
-- =========================================

CREATE TABLE `tbluser` (
  `userID` int(11) NOT NULL AUTO_INCREMENT,
  `firstname` varchar(100) NOT NULL,
  `middlename` varchar(100) DEFAULT NULL,
  `lastname` varchar(100) NOT NULL,
  `position` varchar(100) DEFAULT NULL,
  `admin` tinyint(1) DEFAULT 0,
  `username` varchar(100) NOT NULL,
  `password` varchar(255) NOT NULL,
  `officeID` int(11) DEFAULT NULL,
  PRIMARY KEY (`userID`),
  UNIQUE KEY `username` (`username`),
  KEY `fk_user_office` (`officeID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Insert default admin user (password: admin)
INSERT INTO `tbluser` (`userID`, `firstname`, `middlename`, `lastname`, `position`, `admin`, `username`, `password`, `officeID`) VALUES
(1, 'Admin', 'Admin', 'Admin', 'Admin', 1, 'admin', 'admin', 1),
(2, 'User', 'User', 'User', 'User', 0, 'user', 'user', 2);

-- =========================================
-- FOREIGN KEY CONSTRAINTS
-- =========================================
-- Project table constraints
ALTER TABLE `tblproject`
  ADD CONSTRAINT `fk_edited_by` FOREIGN KEY (`editedBy`) REFERENCES `tbluser` (`userID`) ON DELETE SET NULL,
  ADD CONSTRAINT `fk_last_accessed_by` FOREIGN KEY (`lastAccessedBy`) REFERENCES `tbluser` (`userID`) ON DELETE SET NULL,
  ADD CONSTRAINT `fk_project_mop` FOREIGN KEY (`MoPID`) REFERENCES `mode_of_procurement` (`MoPID`) ON DELETE SET NULL,
  ADD CONSTRAINT `fk_project_user` FOREIGN KEY (`userID`) REFERENCES `tbluser` (`userID`);

-- Project stages table constraints
ALTER TABLE `tblproject_stages`
  ADD CONSTRAINT `fk_stage_office` FOREIGN KEY (`officeID`) REFERENCES `officeid` (`officeID`) ON DELETE SET NULL ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_stage_project` FOREIGN KEY (`projectID`) REFERENCES `tblproject` (`projectID`) ON DELETE CASCADE;

-- User table constraints
ALTER TABLE `tbluser`
  ADD CONSTRAINT `fk_user_office` FOREIGN KEY (`officeID`) REFERENCES `officeid` (`officeID`) ON DELETE SET NULL;

COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
