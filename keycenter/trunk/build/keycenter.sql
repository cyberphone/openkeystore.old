-- SQL Script for MySQL 5.0
--
-- Clear and create definitions to begin with
--
USE WEBPKI_ORG_CA;
--
-- Drop all stored procedures
--
DROP PROCEDURE IF EXISTS ActivateAccountSP;
DROP PROCEDURE IF EXISTS LoginSP;
DROP PROCEDURE IF EXISTS DeleteUserSP;
DROP PROCEDURE IF EXISTS ResetServerSP;
DROP PROCEDURE IF EXISTS SetServerAvailabilitySP;
--
-- Drop all tables.  Note: order is not arbitrary due to FOREIGN KEY constraints
--
-- From the phone.sql file:
--
DROP TABLE IF EXISTS PROVISIONEDKEYS;
DROP TABLE IF EXISTS DELETEDKEYS;
DROP TABLE IF EXISTS PROVISIONINGS;
DROP TABLE IF EXISTS AUTOSELECTIONS;
DROP TABLE IF EXISTS LOGOTYPES;
DROP TABLE IF EXISTS EXTENSIONS;
DROP TABLE IF EXISTS PROPERTIES;
DROP TABLE IF EXISTS PROPERTYBAGS;
DROP TABLE IF EXISTS DEVICEDATA;
DROP TABLE IF EXISTS USERKEYS;
DROP TABLE IF EXISTS PINPOLICIES;
DROP TABLE IF EXISTS PUKPOLICIES;
DROP TABLE IF EXISTS PROPERTYBAGCONSUMERS;
DROP TABLE IF EXISTS EXTENSIONCONSUMERS;
DROP TABLE IF EXISTS TYPEREGISTRY;
--
-- From the issuer.sql file:
--
DROP TABLE IF EXISTS I_OTPSTATE;
--
-- The user-related tables
--
DROP TABLE IF EXISTS SIGNUPS;
DROP TABLE IF EXISTS REQUESTS;
DROP TABLE IF EXISTS USERS;
DROP TABLE IF EXISTS ADMIN;


/*=============================================*/
/*               USERS Table                   */
/*=============================================*/

CREATE TABLE USERS
  (
    UserID      INT           NOT NULL  AUTO_INCREMENT,                  -- Unique user ID
    Created     TIMESTAMP     NOT NULL  DEFAULT CURRENT_TIMESTAMP,       -- Mostly for admins
    LoginCount  INT           NOT NULL  DEFAULT 0,                       -- Mostly for admins
    LastLogin   TIMESTAMP     NULL,                                      -- Mostly for admins
    IsAdmin     BOOLEAN       NULL,                                      -- Some users may be admins
    Name        VARCHAR (50)  NOT NULL,                                  -- Just decoration in CN fields
    Email       VARCHAR (50)  NOT NULL  UNIQUE,                          -- Login ID
    Password    VARCHAR (20)  NOT NULL,                                  -- Matching password
    PRIMARY KEY (UserID),
    INDEX (Email)
  ) ENGINE=InnoDB;


ALTER TABLE USERS AUTO_INCREMENT = 75034;


/*=============================================*/
/*               REQUESTS Table                */
/*=============================================*/

CREATE TABLE REQUESTS
  (
    RequestID    INT           NOT NULL  AUTO_INCREMENT,                 -- Each request object has a unique ID
    UserID       INT           NOT NULL,                                 -- The creator/owner of a request
    RequestData  VARCHAR (20)  NOT NULL,                                 -- The request data object itself
    FOREIGN KEY (UserID) REFERENCES USERS (UserID) ON DELETE CASCADE,
    PRIMARY KEY (RequestID)
  ) ENGINE=InnoDB;


/*=============================================*/
/*                SIGNUPS Table                */
/*=============================================*/

CREATE TABLE SIGNUPS
  (
    SignupID    INT           NOT NULL  AUTO_INCREMENT,                  -- Each signup gets an ID
    Created     TIMESTAMP     NOT NULL  DEFAULT CURRENT_TIMESTAMP,       -- Nice to know when created
    Name        VARCHAR (50)  NOT NULL,                                  -- Just decoration in CN fields
    Email       VARCHAR (50)  NOT NULL,                                  -- Login ID
    Password    VARCHAR (20)  NOT NULL,                                  -- Matching password
    PRIMARY KEY (SignupID),
    INDEX (SignupID, Email)
  ) ENGINE=InnoDB;


/*=============================================*/
/*                ADMIN Table                  */
/*=============================================*/

CREATE TABLE ADMIN
  (
    NotAvailMessage   VARCHAR (256)  NULL,                               -- If defined login is not available
    OpenAfterRestart  BOOLEAN        NOT NULL  DEFAULT 1                 -- For Godaddy hosting...
  ) ENGINE=InnoDB;

INSERT INTO ADMIN (NotAvailMessage) VALUES (NULL);                       -- There MUST always be exactly one element


delimiter //

CREATE PROCEDURE ActivateAccountSP (OUT p_success BOOLEAN,
                                    IN p_email VARCHAR (50),
                                    IN p_inst INT)
  BEGIN
    DECLARE v_userid INT;
    DECLARE v_sid INT;
    DECLARE v_password VARCHAR (20);
    DECLARE v_name     VARCHAR (50);

    SET v_sid = NULL;
    SELECT SignupID, Password, Name INTO v_sid, v_password, v_name
                                    FROM SIGNUPS
                                    WHERE Email = p_email AND SignupID = p_inst;
    IF v_sid IS NOT NULL THEN
      SET p_success = 1;
      SET v_userid = NULL;
      SELECT UserID Name INTO v_userid FROM USERS WHERE Email = p_email;
      IF v_userid IS NOT NULL THEN
        UPDATE USERS SET Password = v_password, Name = v_name WHERE Email = p_email;
      ELSE
        INSERT INTO USERS (Name, Email, Password) VALUES (v_name, p_email, v_password);
      END IF;
      DELETE FROM SIGNUPS WHERE Email = p_email;
    ELSE
      SET p_success = 0;
    END IF;
  END
//


CREATE PROCEDURE LoginSP (OUT p_success BOOLEAN,
                          OUT p_isadmin BOOLEAN,
                          OUT p_name VARCHAR (50),
                          OUT p_userid INT,
                          IN p_email VARCHAR (50),
                          IN p_password VARCHAR (20))
  BEGIN
    SET p_userid = NULL;
    SELECT IsAdmin, Name, UserID INTO p_isadmin, p_name, p_userid
                                 FROM USERS
                                 WHERE Email = p_email AND Password = p_password;
    IF p_userid IS NOT NULL THEN
      SET p_success = 1;
      UPDATE USERS SET LoginCount = LoginCount + 1, LastLogin = NOW() WHERE Email = p_email;
    ELSE
      SET p_success = 0;
    END IF;
  END
//


CREATE PROCEDURE DeleteUserSP (OUT p_success BOOLEAN, IN p_email VARCHAR (50))
  BEGIN
    DECLARE v_userid INT DEFAULT NULL;
    DECLARE v_pukpolicy INT DEFAULT NULL;
    
    SET p_success = FALSE;
    SELECT UserID INTO v_userid FROM USERS WHERE Email = p_email;
    IF v_userid IS NOT NULL THEN
      IF EXISTS (SELECT * FROM information_schema.tables WHERE table_name='USERKEYS') THEN
        SELECT PUKPolicyID INTO v_pukpolicy FROM DEVICEDATA WHERE UserID = v_userid;
        DELETE FROM DEVICEDATA WHERE UserID = v_userid;
        CALL DeleteUserKeysSP (v_userid);
        IF v_pukpolicy IS NOT NULL THEN
          DELETE FROM PUKPOLICIES WHERE PUKPolicyID = v_pukpolicy;
        END IF;
      END IF;
      DELETE FROM USERS WHERE UserID = v_userid;
      SET p_success = TRUE;
    END IF;
  END
//


CREATE PROCEDURE ResetServerSP (OUT p_reset_moment DATE,
                                OUT p_availability VARCHAR (256),
                                OUT p_reset_flag BOOLEAN)
  BEGIN
    SELECT OpenAfterRestart INTO p_reset_flag FROM ADMIN;
    IF p_reset_flag THEN
      UPDATE ADMIN SET NotAvailMessage = NULL;
    END IF;
    SELECT CURRENT_DATE INTO p_reset_moment;
    SELECT NotAvailMessage INTO p_availability FROM ADMIN;
  END
//


CREATE PROCEDURE SetServerAvailabilitySP (IN p_availability VARCHAR (256) CHARACTER SET utf8,
                                          IN p_reset_flag BOOLEAN)
  BEGIN
    UPDATE ADMIN SET NotAvailMessage = p_availability, OpenAfterRestart = p_reset_flag;
  END
//


delimiter ;
--
-- Add some default users
--
INSERT INTO USERS (IsAdmin, Name, Email, Password) VALUES (1, 'The Wizard', 'anders@webpki.org', 'theboss.400');
INSERT INTO USERS (Name, Email, Password) VALUES ('Anders Rundgren', 'anders.rundgren@telia.com', 'test');
