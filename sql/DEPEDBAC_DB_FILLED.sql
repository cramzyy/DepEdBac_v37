-- phpMyAdmin SQL Dump
-- version 5.2.0
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Jul 01, 2025 at 06:11 PM
-- Server version: 10.4.24-MariaDB
-- PHP Version: 8.1.6

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `depedbac_db`
--

-- --------------------------------------------------------

--
-- Table structure for table `mode_of_procurement`
--

CREATE TABLE `mode_of_procurement` (
  `MoPID` int(11) NOT NULL,
  `MoPDescription` varchar(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Dumping data for table `mode_of_procurement`
--

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

-- --------------------------------------------------------

--
-- Table structure for table `officeid`
--

CREATE TABLE `officeid` (
  `officeID` int(11) NOT NULL,
  `officename` varchar(255) NOT NULL,
  `officedetails` varchar(255) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Dumping data for table `officeid`
--

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

-- --------------------------------------------------------

--
-- Table structure for table `stage_reference`
--

CREATE TABLE `stage_reference` (
  `id` int(11) NOT NULL,
  `stageName` varchar(255) NOT NULL,
  `stageOrder` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Dumping data for table `stage_reference`
--

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

-- --------------------------------------------------------

--
-- Table structure for table `tblproject`
--

CREATE TABLE `tblproject` (
  `projectID` int(11) NOT NULL,
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
  `totalABC` int(11) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Dumping data for table `tblproject`
--

INSERT INTO `tblproject` (`projectID`, `projectDetails`, `userID`, `createdAt`, `editedAt`, `prNumber`, `projectStatus`, `editedBy`, `lastAccessedAt`, `lastAccessedBy`, `MoPID`, `programOwner`, `programOffice`, `totalABC`) VALUES
(2, 'A', 1, '2025-07-01 23:58:31', '2025-07-01 23:58:31', '1', 'in-progress', NULL, NULL, NULL, 1, 'A', 'OSDS', 1),
(3, 'B', 1, '2025-07-01 23:58:42', '2025-07-01 23:58:42', '2', 'in-progress', NULL, NULL, NULL, 2, 'B', 'OASDS', 2),
(4, 'C', 1, '2025-07-01 23:58:52', '2025-07-01 23:58:52', '3', 'in-progress', NULL, NULL, NULL, 3, 'C', 'ADMIN', 3),
(5, 'D', 1, '2025-07-01 23:59:02', '2025-07-01 23:59:02', '4', 'in-progress', NULL, NULL, NULL, 4, 'D', 'SGOD CHIEF', 4),
(6, 'E', 1, '2025-07-01 23:59:18', '2025-07-01 23:59:18', '5', 'in-progress', NULL, NULL, NULL, 5, 'E', 'CID CHIEF', 5),
(7, 'F', 1, '2025-07-01 23:59:41', '2025-07-01 23:59:41', '6', 'in-progress', NULL, NULL, NULL, 6, 'F', 'CID', 6),
(8, 'G', 1, '2025-07-02 00:00:14', '2025-07-02 00:00:14', '7', 'in-progress', NULL, NULL, NULL, 7, 'G', 'SGOD', 7),
(9, 'H', 1, '2025-07-02 00:00:29', '2025-07-02 00:00:29', '8', 'in-progress', NULL, NULL, NULL, 8, 'H', 'RECORDS', 8),
(10, 'I', 1, '2025-07-02 00:00:54', '2025-07-02 00:00:58', '9', 'in-progress', 1, '2025-07-02 00:00:58', 1, 9, 'I', 'BAC', 99),
(11, 'J', 1, '2025-07-02 00:01:27', '2025-07-02 00:01:27', '10', 'in-progress', NULL, NULL, NULL, 10, 'J', 'CASH', 10),
(12, 'K', 1, '2025-07-02 00:01:57', '2025-07-02 00:01:57', '11', 'in-progress', NULL, NULL, NULL, 11, 'K', 'BUDGET', 11),
(13, 'L', 1, '2025-07-02 00:04:18', '2025-07-02 00:04:18', '12', 'in-progress', NULL, NULL, NULL, 12, 'L', 'PERSONNEL', 12),
(14, 'M', 1, '2025-07-02 00:05:22', '2025-07-02 00:05:22', '13', 'finished', NULL, NULL, NULL, 13, 'M', 'PAYROLL', 13),
(15, 'N', 1, '2025-07-02 00:05:41', '2025-07-02 00:05:41', '14', 'finished', NULL, NULL, NULL, 14, 'N', 'SUPPLY', 14),
(16, 'O', 1, '2025-07-02 00:05:54', '2025-07-02 00:05:54', '15', 'in-progress', NULL, NULL, NULL, 15, 'O', 'IT', 15),
(17, 'P', 1, '2025-07-02 00:06:30', '2025-07-02 00:06:30', '17', 'finished', NULL, NULL, NULL, 16, 'P', 'MEDICAL', 17),
(18, 'Q', 1, '2025-07-02 00:07:12', '2025-07-02 00:07:12', '18', 'in-progress', NULL, NULL, NULL, 17, 'Q', 'DENTAL', 18),
(19, 'R', 1, '2025-07-02 00:07:32', '2025-07-02 00:07:32', '19', 'in-progress', NULL, NULL, NULL, 18, 'R', 'OSDS', 19),
(20, 'S', 1, '2025-07-02 00:07:48', '2025-07-02 00:07:48', '20', 'finished', NULL, NULL, NULL, 19, 'S', 'OSDS', 20),
(21, 'T', 1, '2025-07-02 00:08:06', '2025-07-02 00:08:06', '21', 'in-progress', NULL, NULL, NULL, 20, 'T', 'OSDS', 21),
(22, 'U', 1, '2025-07-02 00:09:06', '2025-07-02 00:09:06', '22', 'in-progress', NULL, NULL, NULL, 21, 'U', 'OSDS', 22),
(23, 'V', 1, '2025-07-02 00:09:28', '2025-07-02 00:09:28', '23', 'in-progress', NULL, NULL, NULL, 1, 'V', 'OSDS', 23),
(24, 'W', 1, '2025-07-02 00:09:47', '2025-07-02 00:09:47', '24', 'finished', NULL, NULL, NULL, 1, 'W', 'OSDS', 24),
(25, 'X', 1, '2025-07-02 00:10:02', '2025-07-02 00:10:02', '25', 'in-progress', NULL, NULL, NULL, 1, 'X', 'OSDS', 25),
(26, 'Y', 1, '2025-07-02 00:10:18', '2025-07-02 00:10:18', '26', 'in-progress', NULL, NULL, NULL, 1, 'Y', 'OSDS', 26),
(27, 'Z', 1, '2025-07-02 00:10:31', '2025-07-02 00:10:31', '27', 'finished', NULL, NULL, NULL, 1, 'Z', 'OSDS', 27);

-- --------------------------------------------------------

--
-- Table structure for table `tblproject_stages`
--

CREATE TABLE `tblproject_stages` (
  `stageID` int(11) NOT NULL,
  `projectID` int(11) NOT NULL,
  `stageName` varchar(255) NOT NULL,
  `createdAt` datetime DEFAULT current_timestamp(),
  `approvedAt` datetime DEFAULT NULL,
  `officeID` int(11) DEFAULT NULL,
  `remarks` text DEFAULT NULL,
  `isSubmitted` tinyint(1) DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Dumping data for table `tblproject_stages`
--

INSERT INTO `tblproject_stages` (`stageID`, `projectID`, `stageName`, `createdAt`, `approvedAt`, `officeID`, `remarks`, `isSubmitted`) VALUES
(3, 2, 'Mode Of Procurement', '2025-07-01 23:58:31', '2025-07-01 23:58:31', NULL, NULL, 1),
(4, 3, 'Mode Of Procurement', '2025-07-01 23:58:42', '2025-07-01 23:58:42', NULL, NULL, 1),
(5, 4, 'Mode Of Procurement', '2025-07-01 23:58:52', '2025-07-01 23:58:52', NULL, NULL, 1),
(6, 5, 'Mode Of Procurement', '2025-07-01 23:59:02', '2025-07-01 23:59:02', NULL, NULL, 1),
(7, 6, 'Mode Of Procurement', '2025-07-01 23:59:18', '2025-07-01 23:59:18', NULL, NULL, 1),
(8, 7, 'Mode Of Procurement', '2025-07-01 23:59:41', '2025-07-01 23:59:41', NULL, NULL, 1),
(9, 8, 'Mode Of Procurement', '2025-07-02 00:00:14', '2025-07-02 00:00:14', NULL, NULL, 1),
(10, 9, 'Mode Of Procurement', '2025-07-02 00:00:29', '2025-07-02 00:00:29', NULL, NULL, 1),
(11, 10, 'Mode Of Procurement', '2025-07-02 00:00:54', '2025-07-02 00:00:54', NULL, NULL, 1),
(12, 11, 'Mode Of Procurement', '2025-07-02 00:01:27', '2025-07-02 00:01:27', NULL, NULL, 1),
(13, 12, 'Mode Of Procurement', '2025-07-02 00:01:57', '2025-07-02 00:01:57', NULL, NULL, 1),
(14, 13, 'Mode Of Procurement', '2025-07-02 00:04:18', '2025-07-02 00:04:18', NULL, NULL, 1),
(15, 14, 'Mode Of Procurement', '2025-07-02 00:05:22', '2025-07-02 00:05:22', NULL, NULL, 1),
(16, 15, 'Mode Of Procurement', '2025-07-02 00:05:41', '2025-07-02 00:05:41', NULL, NULL, 1),
(17, 16, 'Mode Of Procurement', '2025-07-02 00:05:54', '2025-07-02 00:05:54', NULL, NULL, 1),
(18, 17, 'Mode Of Procurement', '2025-07-02 00:06:30', '2025-07-02 00:06:30', NULL, NULL, 1),
(19, 18, 'Mode Of Procurement', '2025-07-02 00:07:12', '2025-07-02 00:07:12', NULL, NULL, 1),
(20, 19, 'Mode Of Procurement', '2025-07-02 00:07:32', '2025-07-02 00:07:32', NULL, NULL, 1),
(21, 20, 'Mode Of Procurement', '2025-07-02 00:07:48', '2025-07-02 00:07:48', NULL, NULL, 1),
(22, 21, 'Mode Of Procurement', '2025-07-02 00:08:06', '2025-07-02 00:08:06', NULL, NULL, 1),
(23, 22, 'Mode Of Procurement', '2025-07-02 00:09:06', '2025-07-02 00:09:06', NULL, NULL, 1),
(24, 23, 'Mode Of Procurement', '2025-07-02 00:09:28', '2025-07-02 00:09:28', NULL, NULL, 1),
(25, 24, 'Mode Of Procurement', '2025-07-02 00:09:47', '2025-07-02 00:09:47', NULL, NULL, 1),
(26, 25, 'Mode Of Procurement', '2025-07-02 00:10:02', '2025-07-02 00:10:02', NULL, NULL, 1),
(27, 26, 'Mode Of Procurement', '2025-07-02 00:10:18', '2025-07-02 00:10:18', NULL, NULL, 1),
(28, 27, 'Mode Of Procurement', '2025-07-02 00:10:31', '2025-07-02 00:10:31', NULL, NULL, 1);

-- --------------------------------------------------------

--
-- Table structure for table `tbluser`
--

CREATE TABLE `tbluser` (
  `userID` int(11) NOT NULL,
  `firstname` varchar(100) NOT NULL,
  `middlename` varchar(100) DEFAULT NULL,
  `lastname` varchar(100) NOT NULL,
  `position` varchar(100) DEFAULT NULL,
  `admin` tinyint(1) DEFAULT 0,
  `username` varchar(100) NOT NULL,
  `password` varchar(255) NOT NULL,
  `officeID` int(11) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Dumping data for table `tbluser`
--

INSERT INTO `tbluser` (`userID`, `firstname`, `middlename`, `lastname`, `position`, `admin`, `username`, `password`, `officeID`) VALUES
(1, 'Admin', 'Admin', 'Admin', 'Admin', 1, 'admin', 'admin', 1),
(2, 'User', 'User', 'User', 'User', 0, 'user', 'user', 2);

--
-- Indexes for dumped tables
--

--
-- Indexes for table `mode_of_procurement`
--
ALTER TABLE `mode_of_procurement`
  ADD PRIMARY KEY (`MoPID`);

--
-- Indexes for table `officeid`
--
ALTER TABLE `officeid`
  ADD PRIMARY KEY (`officeID`);

--
-- Indexes for table `stage_reference`
--
ALTER TABLE `stage_reference`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `tblproject`
--
ALTER TABLE `tblproject`
  ADD PRIMARY KEY (`projectID`),
  ADD UNIQUE KEY `prNumber` (`prNumber`),
  ADD KEY `userID` (`userID`),
  ADD KEY `fk_edited_by` (`editedBy`),
  ADD KEY `fk_last_accessed_by` (`lastAccessedBy`),
  ADD KEY `fk_project_mop` (`MoPID`);

--
-- Indexes for table `tblproject_stages`
--
ALTER TABLE `tblproject_stages`
  ADD PRIMARY KEY (`stageID`),
  ADD KEY `projectID` (`projectID`),
  ADD KEY `fk_stage_office` (`officeID`);

--
-- Indexes for table `tbluser`
--
ALTER TABLE `tbluser`
  ADD PRIMARY KEY (`userID`),
  ADD UNIQUE KEY `username` (`username`),
  ADD KEY `fk_user_office` (`officeID`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `mode_of_procurement`
--
ALTER TABLE `mode_of_procurement`
  MODIFY `MoPID` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=22;

--
-- AUTO_INCREMENT for table `officeid`
--
ALTER TABLE `officeid`
  MODIFY `officeID` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=18;

--
-- AUTO_INCREMENT for table `stage_reference`
--
ALTER TABLE `stage_reference`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=11;

--
-- AUTO_INCREMENT for table `tblproject`
--
ALTER TABLE `tblproject`
  MODIFY `projectID` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=28;

--
-- AUTO_INCREMENT for table `tblproject_stages`
--
ALTER TABLE `tblproject_stages`
  MODIFY `stageID` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=29;

--
-- AUTO_INCREMENT for table `tbluser`
--
ALTER TABLE `tbluser`
  MODIFY `userID` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `tblproject`
--
ALTER TABLE `tblproject`
  ADD CONSTRAINT `fk_edited_by` FOREIGN KEY (`editedBy`) REFERENCES `tbluser` (`userID`) ON DELETE SET NULL,
  ADD CONSTRAINT `fk_last_accessed_by` FOREIGN KEY (`lastAccessedBy`) REFERENCES `tbluser` (`userID`) ON DELETE SET NULL,
  ADD CONSTRAINT `fk_project_mop` FOREIGN KEY (`MoPID`) REFERENCES `mode_of_procurement` (`MoPID`) ON DELETE SET NULL,
  ADD CONSTRAINT `fk_project_user` FOREIGN KEY (`userID`) REFERENCES `tbluser` (`userID`);

--
-- Constraints for table `tblproject_stages`
--
ALTER TABLE `tblproject_stages`
  ADD CONSTRAINT `fk_stage_office` FOREIGN KEY (`officeID`) REFERENCES `officeid` (`officeID`) ON DELETE SET NULL ON UPDATE CASCADE,
  ADD CONSTRAINT `fk_stage_project` FOREIGN KEY (`projectID`) REFERENCES `tblproject` (`projectID`) ON DELETE CASCADE;

--
-- Constraints for table `tbluser`
--
ALTER TABLE `tbluser`
  ADD CONSTRAINT `fk_user_office` FOREIGN KEY (`officeID`) REFERENCES `officeid` (`officeID`) ON DELETE SET NULL;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
