-- SQL Script for MySQL 5.0
--
-- root priviledges are required!!!
--
-- Clear and create DB to begin with
--
DROP DATABASE IF EXISTS WEBPKI_ORG_CA;
CREATE DATABASE WEBPKI_ORG_CA CHARACTER SET utf8;
--
-- Create a user but remove any existing user first
DROP USER WEBPKI_ORG_CA@localhost;
--
CREATE USER WEBPKI_ORG_CA@localhost IDENTIFIED BY 'CyberPhone1';
--
-- Let user access
--
GRANT ALL ON WEBPKI_ORG_CA.* TO WEBPKI_ORG_CA@localhost;
