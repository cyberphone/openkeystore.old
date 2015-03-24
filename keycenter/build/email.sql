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
DROP PROCEDURE IF EXISTS GetEmailMessageSP;
DROP PROCEDURE IF EXISTS SetEmailMessageSP;

DROP TABLE IF EXISTS I_EMAIL;


/*=============================================*/
/*               I_EMAIL Table                 */
/*=============================================*/

CREATE TABLE I_EMAIL
  (
    UserID        INT           NOT NULL,                                  -- Owning user
    Sender        VARCHAR(255)  NULL,                                      -- Who sent it
    Message       TEXT          NULL  DEFAULT NULL,                        -- Optional email
--
    FOREIGN KEY (UserID) REFERENCES USERS (UserID) ON DELETE CASCADE
  ) ENGINE=InnoDB;


delimiter //

CREATE PROCEDURE GetEmailMessageSP (IN p_user_id INT,
                                    OUT p_sender VARCHAR(255),
                                    OUT p_message TEXT)
  BEGIN
	SET p_message = NULL;
    SELECT Message, Sender INTO p_message, p_sender FROM I_EMAIL WHERE UserID = p_user_id;
	IF p_message IS NOT NULL THEN
	  UPDATE I_EMAIL SET Message = NULL WHERE UserID = p_user_id;
    END IF;
  END
//


CREATE PROCEDURE SetEmailMessageSP (IN p_recepient VARCHAR(255),
                                    IN p_sender VARCHAR(255),
                                    IN p_message TEXT,
                                    OUT p_user_id INT)
  BEGIN
    SET p_user_id = NULL;
    SELECT UserID INTO p_user_id FROM USERS WHERE Email = p_recepient;
    IF p_user_id IS NOT NULL THEN
      IF EXISTS (SELECT * FROM I_EMAIL WHERE UserID = p_user_id) THEN
        UPDATE I_EMAIL SET Message = p_message, Sender = p_sender WHERE UserID = p_user_id;
      ELSE
		INSERT INTO I_EMAIL (UserID, Message, Sender) VALUES (p_user_id, p_message, p_sender);
	  END IF;
	END IF;
  END
//


delimiter ;

