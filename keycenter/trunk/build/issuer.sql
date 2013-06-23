-- SQL Script for MySQL 5.0
--
-- Must be run AFTER keycenter.sql and phone.sql (if the database is scratched)
--
-- Note: USERS table is defined in keycenter.sql.
--
--
USE WEBPKI_ORG_CA;
--
-- Drop all tables
--
DROP PROCEDURE IF EXISTS GetOTPCounterSP;
DROP PROCEDURE IF EXISTS SetOTPCounterSP;
DROP PROCEDURE IF EXISTS DumpKeystoreSP;
DROP PROCEDURE IF EXISTS DeleteIssuedCredentialsSP;
DROP PROCEDURE IF EXISTS DeletePhoneKeysSP;
DROP PROCEDURE IF EXISTS GetRequestSP;
DROP PROCEDURE IF EXISTS SetRequestSP;

DROP TABLE IF EXISTS I_OTPSTATE;
DROP TABLE IF EXISTS I_SAVED_REQUESTS;


/*=============================================*/
/*              I_OTPSTATE Table               */
/*=============================================*/

CREATE TABLE I_OTPSTATE
  (
    UserID        INT           NOT NULL,                                  -- Owning user
    Counter       INT           NOT NULL  DEFAULT 0,                       -- Event counter
--
    FOREIGN KEY (UserID) REFERENCES USERS (UserID) ON DELETE CASCADE
  ) ENGINE=InnoDB;


/*=============================================*/
/*            I_SAVED_REQUESTS Table           */
/*=============================================*/

CREATE TABLE I_SAVED_REQUESTS
  (
    UserID        INT           NOT NULL,                                  -- Owning user
    ServerSession VARCHAR(255)  NOT NULL,                                  -- Server's provisioning ID
    ClientSession VARCHAR(255)  NOT NULL,                                  -- Client's provisioning ID
    SavedRequest  BLOB          NOT NULL,                                  -- Serialized "ProvisioningState"
--
    FOREIGN KEY (UserID) REFERENCES USERS (UserID) ON DELETE CASCADE
  ) ENGINE=InnoDB;


delimiter //

CREATE PROCEDURE GetOTPCounterSP (IN p_user_id INT,
                                  OUT p_counter INT)
  BEGIN
    IF NOT EXISTS (SELECT * FROM USERS WHERE UserID = p_user_id) THEN
      SET p_counter = -1;
    ELSE
      SET p_counter = NULL;
      SELECT Counter INTO p_counter FROM I_OTPSTATE WHERE UserID = p_user_id;
      IF p_counter IS NULL THEN
        INSERT INTO I_OTPSTATE (UserID) VALUES (p_user_id);
        SET p_counter = 0;
      END IF;
    END IF;
  END
//


CREATE PROCEDURE SetOTPCounterSP (IN p_user_id int,
                                  IN p_counter INT)
  BEGIN
    IF EXISTS (SELECT * FROM USERS WHERE UserID = p_user_id) THEN
      UPDATE I_OTPSTATE SET Counter=p_counter WHERE UserID = p_user_id;
    END IF;
  END
//


CREATE PROCEDURE DeleteIssuedCredentialsSP (IN p_user_id int)
  BEGIN
    DELETE FROM I_OTPSTATE WHERE UserID = p_user_id;
  END
//


CREATE PROCEDURE DeletePhoneKeysSP (IN p_user_id int)
  BEGIN
    DELETE FROM DEVICEDATA WHERE UserID = p_user_id;
    CALL DeleteUserKeysSP (p_user_id);
  END
//


CREATE PROCEDURE DumpKeystoreSP ()
BEGIN
  DECLARE v_done BOOLEAN DEFAULT FALSE;
  DECLARE v_user_id INT;
  DECLARE v_key_cursor CURSOR FOR SELECT UserID FROM DEVICEDATA;
  DECLARE CONTINUE HANDLER FOR NOT FOUND SET v_done = TRUE;

  OPEN v_key_cursor;

  REPEAT
    FETCH v_key_cursor INTO v_user_id;
    CALL DeletePhoneKeysSP (v_user_id);
    CALL DeleteIssuedCredentialsSP (v_user_id);
  UNTIL v_done END REPEAT;

  CLOSE v_key_cursor;
  
END
//


CREATE PROCEDURE GetRequestSP (IN p_user_id INT,
                               IN p_server_session_id VARCHAR(255),
                               IN p_client_session_id VARCHAR(255),
                               OUT p_saved_request BLOB)
  BEGIN
	SET p_saved_request = NULL;
    SELECT SavedRequest INTO p_saved_request FROM I_SAVED_REQUESTS
        WHERE ServerSession = p_server_session_id AND
              ClientSession = p_client_session_id AND
              UserID = p_user_id;
    DELETE FROM I_SAVED_REQUESTS WHERE UserID = p_user_id;
  END
//


CREATE PROCEDURE SetRequestSP (IN p_user_id INT,
                               IN p_server_session_id VARCHAR(255),
                               IN p_client_session_id VARCHAR(255),
                               IN p_saved_request BLOB)
  BEGIN
    IF EXISTS (SELECT * FROM I_SAVED_REQUESTS WHERE UserID = p_user_id) THEN
      UPDATE I_SAVED_REQUESTS SET ServerSession = p_server_session_id, ClientSession = p_client_session_id, SavedRequest = p_saved_request WHERE UserID = p_user_id;
    ELSE
      INSERT INTO I_SAVED_REQUESTS (UserID, ServerSession, ClientSession, SavedRequest) VALUES (p_user_id, p_server_session_id, p_client_session_id, p_saved_request);
	END IF;
  END
//


delimiter ;

