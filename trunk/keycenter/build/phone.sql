-- SQL Script for MySQL 5.0
--
-- Must be run AFTER keycenter.sql (if the database is scratched)
--
-- Tables and procedures for the web-based phone emulator.
-- These tables should be fairly applicable to a native implementation as well
-- with *.UserID as the notable exception assuming there is just a single user.
--
-- Note: USERS table is defined in keycenter.sql.
--
--
USE WEBPKI_ORG_CA;
--
-- Drop all stored procedures
--
DROP PROCEDURE IF EXISTS UnlockKeySP;
DROP PROCEDURE IF EXISTS DeleteKeySP;
DROP PROCEDURE IF EXISTS DeleteUserKeysSP;
DROP PROCEDURE IF EXISTS AddTypeURISP;
DROP PROCEDURE IF EXISTS AddPropertyBagConsumerSP;
DROP PROCEDURE IF EXISTS AddPropertyBagInstanceSP;
DROP PROCEDURE IF EXISTS AddExtensionConsumerSP;
DROP PROCEDURE IF EXISTS AddExtensionInstanceSP;
DROP PROCEDURE IF EXISTS AddLogotypeInstanceSP;
--
DROP PROCEDURE IF EXISTS FinalizeProvisioningSP;
DROP PROCEDURE IF EXISTS CleanupProvisioningSP;
--
-- Drop all tables
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


/*=============================================*/
/*              PUKPOLICIES Table              */
/*=============================================*/

CREATE TABLE PUKPOLICIES
  (
    PUKPolicyID   INT            NOT NULL  AUTO_INCREMENT,                 -- Unique ID of PUK policy
    Created       TIMESTAMP      NOT NULL  DEFAULT CURRENT_TIMESTAMP,      -- Nice to know when created
    RetryLimit    SMALLINT       NOT NULL,                                 -- PUK tries before locking the key(s)
    PUKTryCount   SMALLINT       NOT NULL,                                 -- Decremented for each error, locking at 0
    Format        SMALLINT       NOT NULL,                                 -- Ordinal (0..n) of "PassphraseFormats"
    PUKValue      BLOB           NULL      DEFAULT NULL,                   -- Encrypted PUK.  NULL => Not yet defined
    PRIMARY KEY (PUKPolicyID)
  ) ENGINE=InnoDB;


/*=============================================*/
/*              PINPOLICIES Table              */
/*=============================================*/

CREATE TABLE PINPOLICIES
  (
    PINPolicyID   INT            NOT NULL  AUTO_INCREMENT,                 -- Unique ID of PIN policy
    Created       TIMESTAMP      NOT NULL  DEFAULT CURRENT_TIMESTAMP,      -- Nice to know when created
    RetryLimit    SMALLINT       NOT NULL,                                 -- PIN tries before locking the key(s)
    PUKPolicyID   INT            NOT NULL,                                 -- For every PIN there is a governing PUK
--
--          User PIN set constraints
--
    Format        SMALLINT       NOT NULL,                                 -- Ordinal (0..n) of "PassphraseFormats"
    MinLength     SMALLINT       NOT NULL,                                 -- Shortest acceptable PIN
    MaxLength     SMALLINT       NOT NULL,                                 -- Longest acceptable PIN
    Grouping      SMALLINT       NOT NULL,                                 -- Ordinal (0..n) of "PINGrouping"
    PatternRestr  BLOB (32)      NULL,                                     -- "PatternRestrictions" [len + ordinals]
--
--              API control
--
    InputMeth     SMALLINT       NOT NULL,                                 -- Ordinal (0..n) of "InputMethods"
    CachingSupp   BOOLEAN        NOT NULL,                                 -- Caching PIN support option
--
    FOREIGN KEY (PUKPolicyID) REFERENCES PUKPOLICIES (PUKPolicyID),
    PRIMARY KEY (PINPolicyID)
  ) ENGINE=InnoDB;


/*=============================================*/
/*               USERKEYS Table                */
/*=============================================*/

CREATE TABLE USERKEYS
  (
    KeyID         INT            NOT NULL  AUTO_INCREMENT,                 -- Each key gets a unique ID in the database
    Created       TIMESTAMP      NOT NULL  DEFAULT CURRENT_TIMESTAMP,      -- Nice to know when created
    UserID        INT            NOT NULL,                                 -- Owner device of key
    Exportable    BOOLEAN        NOT NULL  DEFAULT 0,                      -- The key may exported
    Archived      BOOLEAN        NOT NULL  DEFAULT 0,                      -- The issuer has a copy of the private key
    FriendlyName  VARCHAR (50)   NULL,                                     -- Optional human-oriented ID
--
--        Only defined for PIN-protected keys
--
    PINPolicyID   INT            NULL,                                     -- Unique ID of associated PIN policy
    PINValue      BLOB           NULL,                                     -- Encrypted PIN.  NULL => Not yet defined
    PINSettable   BOOLEAN        NOT NULL  DEFAULT 1,                      -- The PIN can be set by the user?
    PINTryCount   SMALLINT       NULL,                                     -- Decremented for each error, locking at 0
--
--            User-key cryptographic data
--
    CertPath      BLOB           NULL,                                     -- Certificate path.  NULL => Not yet defined 
    PrivateKey    BLOB           NULL,                                     -- Encrypted private key (symmetric key = NULL)
    SecretKey     BLOB           NULL,                                     -- [Encrypted "piggybacked" symmetric key]
    SuppAlgs      TEXT           NULL,                                     -- [ -"- ] NULL => Unrestricted usage
--
    FOREIGN KEY (UserID) REFERENCES USERS (UserID),
    FOREIGN KEY (PINPolicyID) REFERENCES PINPOLICIES (PINPolicyID),
    PRIMARY KEY (KeyID)
  ) ENGINE=InnoDB;


/*=============================================*/
/*              DEVICEDATA Table               */
/*=============================================*/

CREATE TABLE DEVICEDATA
  (
    UserID        INT            NOT NULL,                                 -- Owner device of key
    Created       TIMESTAMP      NOT NULL  DEFAULT CURRENT_TIMESTAMP,      -- Nice to know when created
--
--            Device certificate
--
    CertPath      BLOB           NOT NULL,                                 -- Certificate path
    PrivateKey    BLOB           NOT NULL,                                 -- Matching encrypted private key
--
--                System PUK
--
    PUKPolicyID   INT            NOT NULL,                                 -- Unique ID of PUK policy
--
    FOREIGN KEY (PUKPolicyID) REFERENCES PUKPOLICIES (PUKPolicyID),
    FOREIGN KEY (UserID) REFERENCES USERS (UserID)
  ) ENGINE=InnoDB;


/*=============================================*/
/*             TYPEREGISTRY Table              */
/*=============================================*/

CREATE TABLE TYPEREGISTRY
  (
    TypeID        INT            NOT NULL  AUTO_INCREMENT,                 -- Each URI gets a unique ID for references
    TypeURI       VARCHAR (256)  NOT NULL,                                 -- Type = URI
--
    PRIMARY KEY (TypeID)
  ) ENGINE=InnoDB;


/*=============================================*/
/*         PROPERTYBAGCONSUMERS Table          */
/*=============================================*/

CREATE TABLE PROPERTYBAGCONSUMERS
  (
--
--   There may be more than one application that wants a specific
--   property bag type, each requring a "subscription" in this table
--
    TypeID        INT            NOT NULL,                                 -- Reference to type (URI) of property bag
    ImplClass     VARCHAR (256)  NOT NULL,                                 -- Java implementation class of consumer
--
    FOREIGN KEY (TypeID) REFERENCES TYPEREGISTRY (TypeID)
  ) ENGINE=InnoDB;


/*=============================================*/
/*             PROPERTYBAGS Table              */
/*=============================================*/

CREATE TABLE PROPERTYBAGS
  (
    PropBagID     INT            NOT NULL  AUTO_INCREMENT,                 -- Each bag instance gets a unique ID
    KeyID         INT            NOT NULL,                                 -- Owning key
    TypeID        INT            NOT NULL,                                 -- Reference to type (URI) of property bag
--
    FOREIGN KEY (KeyID) REFERENCES USERKEYS (KeyID) ON DELETE CASCADE,
    FOREIGN KEY (TypeID) REFERENCES TYPEREGISTRY (TypeID),
    PRIMARY KEY (PropBagID)
  ) ENGINE=InnoDB;


/*=============================================*/
/*              PROPERTIES Table               */
/*=============================================*/

CREATE TABLE PROPERTIES
  (
    PropBagID     INT            NOT NULL,                                 -- Owning bag instance
    PropName      VARCHAR (256)  NOT NULL,                                 -- Name of the property
    PropValue     TEXT           NOT NULL,                                 -- Matching value
    Writable      BOOLEAN        NOT NULL,                                 -- True if writable
--
    FOREIGN KEY (PropBagID) REFERENCES PROPERTYBAGS (PropBagID) ON DELETE CASCADE
  ) ENGINE=InnoDB;


/*=============================================*/
/*          EXTENSIONCONSUMERS Table           */
/*=============================================*/

CREATE TABLE EXTENSIONCONSUMERS
  (
--
--   There may be more than one application that wants a specific
--   extension type, each requring a "subscription" in this table.
--
    TypeID        INT            NOT NULL,                                 -- Reference to type (URI) of extension
    ImplClass     VARCHAR (256)  NOT NULL,                                 -- Java implementation class of consumer
--
    FOREIGN KEY (TypeID) REFERENCES TYPEREGISTRY (TypeID)
  ) ENGINE=InnoDB;


/*=============================================*/
/*              EXTENSIONS Table               */
/*=============================================*/

CREATE TABLE EXTENSIONS
  (
    KeyID         INT            NOT NULL,                                 -- Owning key
    TypeID        INT            NOT NULL,                                 -- Each extension has a specific type
    ExtnData      BLOB           NOT NULL,                                 -- The extracted binary data
--
    FOREIGN KEY (KeyID) REFERENCES USERKEYS (KeyID) ON DELETE CASCADE,
    FOREIGN KEY (TypeID) REFERENCES TYPEREGISTRY (TypeID)
  ) ENGINE=InnoDB;


/*=============================================*/
/*               LOGOTYPES Table               */
/*=============================================*/

CREATE TABLE LOGOTYPES
  (
    KeyID         INT            NOT NULL,                                 -- Owning key
    TypeID        INT            NOT NULL,                                 -- Each image has a specific type (=usage)
    ImageData     BLOB           NOT NULL,                                 -- The binary image data
    MimeType      VARCHAR (100)  NOT NULL,                                 -- The MIME type for the image
--
    FOREIGN KEY (KeyID) REFERENCES USERKEYS (KeyID) ON DELETE CASCADE,
    FOREIGN KEY (TypeID) REFERENCES TYPEREGISTRY (TypeID)
  ) ENGINE=InnoDB;


/*=============================================*/
/*            AUTOSELECTIONS Table             */
/*=============================================*/

CREATE TABLE AUTOSELECTIONS
  (
    KeyID         INT            NOT NULL,                                 -- Owning key
    TypeID        INT            NOT NULL,                                 -- Associated application
    HostName      VARCHAR (256)  NOT NULL,                                 -- The pre-selected host
--
    FOREIGN KEY (KeyID) REFERENCES USERKEYS (KeyID) ON DELETE CASCADE,
    FOREIGN KEY (TypeID) REFERENCES TYPEREGISTRY (TypeID)
  ) ENGINE=InnoDB;


/*=============================================*/
/*             PROVISIONINGS Table             */
/*=============================================*/

CREATE TABLE PROVISIONINGS
  (
    ProvisionID   INT            NOT NULL  AUTO_INCREMENT,                 -- Each provisioning gets a unique ID
    UserID        INT            NOT NULL,                                 -- Owner of this particular provisioning
    Created       TIMESTAMP      NOT NULL  DEFAULT CURRENT_TIMESTAMP,      -- Nice to know when created
    
    IssuerURI     VARCHAR (256)  NOT NULL,                                 -- Defined by the issuer 
    ClientSession VARCHAR (256)  NOT NULL,                                 -- The ID of the client session
    ServerSession VARCHAR (256)  NOT NULL,                                 -- The ID of the server session
    SavedRequest  BLOB           NULL,                                     -- Serialized KeyOperationRequestDecoder
    DelayedDeploy INT            NULL,                                     -- Defined => Max days to wait
--
    PRIMARY KEY (ProvisionID),
    FOREIGN KEY (UserID) REFERENCES USERS (UserID) ON DELETE CASCADE
  ) ENGINE=InnoDB;


/*=============================================*/
/*            PROVISIONEDKEYS Table            */
/*=============================================*/

CREATE TABLE PROVISIONEDKEYS
  (
    ProvisionID   INT            NOT NULL,                                 -- Owning provisioning session
    KeyID         INT            NOT NULL,                                 -- Local KeyID of provisioned key
    KeyUsage      INT            NOT NULL,                                 -- Ordinal (0..n) of "KeyGen2KeyUsage"
    PublicKey     BLOB           NOT NULL,                                 -- The generated public key serialized
    ServerKeyID   VARCHAR (256)  NOT NULL,                                 -- The server's symbolic name
    ReplaceKeyID  INT            NULL,                                     -- Defined => Original KeyID (for update)
--
    FOREIGN KEY (ProvisionID) REFERENCES PROVISIONINGS (ProvisionID) ON DELETE CASCADE
  ) ENGINE=InnoDB;


/*=============================================*/
/*              DELETEDKEYS Table              */
/*=============================================*/

CREATE TABLE DELETEDKEYS
  (
    ProvisionID   INT            NOT NULL,                                 -- Owning provisioning session
    KeyID         INT            NOT NULL,                                 -- KeyID of key to be deleted
--
    FOREIGN KEY (ProvisionID) REFERENCES PROVISIONINGS (ProvisionID) ON DELETE CASCADE
  ) ENGINE=InnoDB;


DELIMITER //


CREATE PROCEDURE FinalizeProvisioningSP (IN p_server_session VARCHAR (256),
                                         IN p_client_session VARCHAR (256),
                                         IN p_user_id INT,
                                         OUT p_provision_id INT,
                                         OUT p_deleted INT,
                                         OUT p_status VARCHAR (256))
  BEGIN
    SET p_provision_id = NULL;
    SELECT ProvisionID INTO p_provision_id FROM PROVISIONINGS
           WHERE ServerSession = p_server_session AND
                 ClientSession = p_client_session AND
                 UserID = p_user_id;
    IF p_provision_id IS NULL THEN
      SET p_status = 'Missing provisioning instance';
    ELSE
      SET p_deleted = 0;
      BEGIN
        DECLARE v_done BOOLEAN DEFAULT FALSE;
        DECLARE v_key_id INT;
        DECLARE v_replace_key_id INT;
        DECLARE v_key_cursor CURSOR FOR SELECT KeyID, ReplaceKeyID FROM PROVISIONEDKEYS
                WHERE ProvisionID = p_provision_id AND ReplaceKeyID IS NOT NULL;
        DECLARE CONTINUE HANDLER FOR NOT FOUND SET v_done = TRUE;

        OPEN v_key_cursor;

        REPEAT
          FETCH v_key_cursor INTO v_key_id, v_replace_key_id;
          IF NOT v_done THEN
-- Missing the giant copy operation....
            CALL DeleteKeySP (v_key_id);
            SET p_deleted = p_deleted + 1;
          END IF;
        UNTIL v_done END REPEAT;

        CLOSE v_key_cursor;
      END;
      BEGIN
        DECLARE v_done BOOLEAN DEFAULT FALSE;
        DECLARE v_key_id INT;
        DECLARE v_key_cursor CURSOR FOR SELECT KeyID FROM DELETEDKEYS WHERE ProvisionID = p_provision_id;
        DECLARE CONTINUE HANDLER FOR NOT FOUND SET v_done = TRUE;

        OPEN v_key_cursor;

        REPEAT
          FETCH v_key_cursor INTO v_key_id;
          IF NOT v_done THEN
            CALL DeleteKeySP (v_key_id);
            SET p_deleted = p_deleted + 1;
          END IF;
        UNTIL v_done END REPEAT;

        CLOSE v_key_cursor;
      END;
      DELETE FROM PROVISIONINGS WHERE ProvisionID = p_provision_id;
    END IF;
  END
//


CREATE PROCEDURE CleanupProvisioningSP (IN p_server_session VARCHAR (256),
                                        IN p_client_session VARCHAR (256),
                                        IN p_user_id INT)
  BEGIN
    DECLARE v_provision_id INT DEFAULT NULL;
    SELECT ProvisionID INTO v_provision_id FROM PROVISIONINGS
           WHERE ServerSession = p_server_session AND
                 ClientSession = p_client_session AND
                 UserID = p_user_id;
    IF v_provision_id IS NOT NULL THEN
      BEGIN
        DECLARE v_done BOOLEAN DEFAULT FALSE;
        DECLARE v_key_id INT;
        DECLARE v_key_cursor CURSOR FOR SELECT KeyID FROM PROVISIONEDKEYS
                WHERE ProvisionID = v_provision_id;
        DECLARE CONTINUE HANDLER FOR NOT FOUND SET v_done = TRUE;

        OPEN v_key_cursor;

        REPEAT
          FETCH v_key_cursor INTO v_key_id;
          IF NOT v_done THEN
            CALL DeleteKeySP (v_key_id);
          END IF;
        UNTIL v_done END REPEAT;

        CLOSE v_key_cursor;
      END;
      DELETE FROM PROVISIONINGS WHERE ProvisionID = v_provision_id;
    END IF;
  END
//


CREATE PROCEDURE AddTypeURISP (IN p_type_uri VARCHAR (256),
                               OUT p_type_id INT)
  BEGIN
    SET p_type_id = NULL;
    SELECT TypeID INTO p_type_id FROM TYPEREGISTRY WHERE TypeURI = p_type_uri;
    IF p_type_id IS NULL THEN
      INSERT INTO TYPEREGISTRY (TypeURI) VALUES (p_type_uri);
      SET p_type_id = LAST_INSERT_ID();
    END IF;
  END
//


CREATE PROCEDURE AddPropertyBagConsumerSP (IN p_type_uri VARCHAR (256),
                                           IN p_impl_class VARCHAR (256))
  BEGIN
    DECLARE v_type_id INT;

    CALL AddTypeURISP (p_type_uri, v_type_id);
    IF NOT EXISTS (SELECT * FROM PROPERTYBAGCONSUMERS WHERE TypeID = v_type_id AND ImplClass = p_impl_class) THEN
      INSERT INTO PROPERTYBAGCONSUMERS (TypeID, ImplClass) VALUES (v_type_id, p_impl_class);
    END IF;
  END
//


CREATE PROCEDURE AddPropertyBagInstanceSP (IN p_key_id INT,
                                           IN p_type_uri VARCHAR (256),
                                           OUT p_prop_bag_id INT)
  BEGIN
    DECLARE v_type_id INT DEFAULT NULL;
    
    SELECT TYPEREGISTRY.TypeID INTO v_type_id
           FROM PROPERTYBAGCONSUMERS, TYPEREGISTRY
           WHERE TYPEREGISTRY.TypeURI = p_type_uri AND PROPERTYBAGCONSUMERS.TypeID = TYPEREGISTRY.TypeID;
    IF v_type_id IS NOT NULL THEN
      INSERT INTO PROPERTYBAGS (KeyID, TypeID) VALUES (p_key_id, v_type_id);
      SET p_prop_bag_id = LAST_INSERT_ID();
    ELSE
      SET p_prop_bag_id = 0;
    END IF;
  END
//


CREATE PROCEDURE AddExtensionConsumerSP (IN p_type_uri VARCHAR (256),
                                         IN p_impl_class VARCHAR (256))
  BEGIN
    DECLARE v_type_id INT;

    CALL AddTypeURISP (p_type_uri, v_type_id);
    IF NOT EXISTS (SELECT * FROM EXTENSIONCONSUMERS WHERE TypeID = v_type_id AND ImplClass = p_impl_class) THEN
      INSERT INTO EXTENSIONCONSUMERS (TypeID, ImplClass) VALUES (v_type_id, p_impl_class);
    END IF;
  END
//


CREATE PROCEDURE AddExtensionInstanceSP (IN p_key_id INT,
                                         IN p_type_uri VARCHAR (256),
                                         IN p_extn_data BLOB,
                                         OUT p_type_id INT)
  BEGIN
    SET p_type_id = 0;
    SELECT TYPEREGISTRY.TypeID INTO p_type_id FROM EXTENSIONCONSUMERS, TYPEREGISTRY
           WHERE TYPEREGISTRY.TypeURI = p_type_uri AND EXTENSIONCONSUMERS.TypeID = TYPEREGISTRY.TypeID;
    IF p_type_id > 0 THEN
      INSERT INTO EXTENSIONS (TypeID, KeyID, ExtnData) VALUES (p_type_id, p_key_id, p_extn_data);
    END IF;
  END
//


CREATE PROCEDURE AddLogotypeInstanceSP (IN p_key_id INT,
                                        IN p_type_uri VARCHAR (256),
                                        IN p_image_data BLOB,
                                        IN p_mime_type VARCHAR (100))
  BEGIN
    DECLARE v_type_id INT;

    CALL AddTypeURISP (p_type_uri, v_type_id);
    IF NOT EXISTS (SELECT * FROM LOGOTYPES WHERE TypeID = v_type_id AND KeyID = p_key_id) THEN
      INSERT INTO LOGOTYPES (KeyID, TypeID, ImageData, MimeType) VALUES (p_key_id, v_type_id, p_image_data, p_mime_type);
    END IF;
  END
//


CREATE PROCEDURE UnlockKeySP (OUT p_status INT,
                              OUT p_value INT,
                              IN p_shared INT,
                              IN p_key_id INT,
                              IN p_puk_value BLOB)
  BEGIN
    DECLARE v_puk_value   BLOB;
    DECLARE v_puk_count   INT;
    DECLARE v_pin_retries INT;
    DECLARE v_puk_retries INT;
    DECLARE v_puk_policy  INT;
    DECLARE v_pin_policy  INT;
    DECLARE v_grouping    INT;

    SET v_puk_value = NULL;

    SELECT PUKPOLICIES.PukValue, PUKPOLICIES.PUKTryCount, PINPOLICIES.RetryLimit, PUKPOLICIES.RetryLimit,
           PUKPOLICIES.PUKPolicyID, PINPOLICIES.PINPolicyID, PINPOLICIES.Grouping 
           INTO v_puk_value, v_puk_count, v_pin_retries, v_puk_retries,
                v_puk_policy, v_pin_policy, v_grouping
           FROM PUKPOLICIES, PINPOLICIES, USERKEYS
           WHERE USERKEYS.KeyID = p_key_id AND
                 USERKEYS.PINPolicyID = PINPOLICIES.PINPolicyID AND
                 PINPOLICIES.PUKPolicyID = PUKPOLICIES.PUKPolicyID;

    SET p_status = 0;              -- Success
    SET p_value = v_pin_retries;
    IF v_puk_value IS NOT NULL THEN
      IF v_puk_value = p_puk_value AND v_puk_count > 0 THEN
        IF v_grouping = p_shared THEN
          UPDATE USERKEYS SET PINTryCount = v_pin_retries WHERE PINPolicyID = v_pin_policy;
        ELSE
          UPDATE USERKEYS SET PINTryCount = v_pin_retries WHERE KeyID = p_key_id;
        END IF;
        IF v_puk_count < v_puk_retries THEN
          UPDATE PUKPOLICIES SET PUKTryCount = v_puk_retries WHERE PUKPolicyID = v_puk_policy;
        END IF;
      ELSE
        IF v_puk_count > 0 THEN
          SET v_puk_count = v_puk_count - 1;
          UPDATE PUKPOLICIES SET PUKTryCount = v_puk_count WHERE PUKPolicyID = v_puk_policy;
        END IF;
        SET p_status = 1;          -- PUK failure
        SET p_value = v_puk_count;
      END IF;
    ELSE
      SET p_status = 2;            -- Internal error: NO PUK
    END IF;
  END
//


CREATE PROCEDURE DeleteKeySP (IN p_key_id INT)
  BEGIN
    DECLARE v_puk_policy  INT;
    DECLARE v_pin_policy  INT DEFAULT NULL;
    DECLARE n             INT;

    SELECT USERKEYS.PINPolicyID, PINPOLICIES.PUKPolicyID
           INTO v_pin_policy, v_puk_policy
           FROM USERKEYS LEFT JOIN (PINPOLICIES CROSS JOIN PUKPOLICIES)
           ON USERKEYS.PINPolicyID=PINPOLICIES.PINPolicyID AND
              PINPOLICIES.PUKPolicyID=PUKPOLICIES.PUKPolicyID
           WHERE USERKEYS.KeyID = p_key_id;

    DELETE FROM USERKEYS WHERE KeyID = p_key_id;
    
    IF v_pin_policy IS NOT NULL THEN
--
-- The deleted was PIN protected, was this the last key hanging on the PIN policy object?
--
      SELECT COUNT(*) INTO n FROM USERKEYS WHERE PINPolicyID = v_pin_policy;
      IF n = 0 THEN
        DELETE FROM PINPOLICIES WHERE PINPolicyID = v_pin_policy;
--
-- PIN policy object deleted, was this the last hanging on the PUK policy object?
--
        SELECT COUNT(*) INTO n FROM PINPOLICIES WHERE PUKPolicyID = v_puk_policy;
        IF n = 0 THEN
--
-- Yes, but DO NOT delete the device PUK!
--
          DELETE FROM PUKPOLICIES WHERE PUKPolicyID = v_puk_policy AND
                 NOT EXISTS (SELECT * FROM DEVICEDATA WHERE PUKPolicyID = v_puk_policy);
        END IF;
      END IF;
    END IF;
  END
//


CREATE PROCEDURE DeleteUserKeysSP (IN p_user_id INT)
BEGIN
  DECLARE v_done BOOLEAN DEFAULT FALSE;
  DECLARE v_key_id INT;
  DECLARE v_key_cursor CURSOR FOR SELECT KeyID FROM USERKEYS WHERE UserID = p_user_id;
  DECLARE CONTINUE HANDLER FOR NOT FOUND SET v_done = TRUE;

  OPEN v_key_cursor;

  REPEAT
    FETCH v_key_cursor INTO v_key_id;
    IF NOT v_done THEN
      CALL DeleteKeySP (v_key_id);
    END IF;
  UNTIL v_done END REPEAT;

  CLOSE v_key_cursor;

END
//

DELIMITER ;

