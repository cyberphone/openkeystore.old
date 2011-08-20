/*
 *  Copyright 2006-2011 WebPKI.org (http://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.webpki.sks;

import java.security.PublicKey;

import java.security.cert.X509Certificate;

import java.security.interfaces.ECPublicKey;

/**
 * SKS (Secure Key Store) API.
 */
public interface SecureKeyStore
  {
    ///////////////////////////////////////////////////////////////////////////////////
    // SKS "sanity" limits
    ///////////////////////////////////////////////////////////////////////////////////
    public int MAX_LENGTH_PIN_PUK                    = 128;
    public int MAX_LENGTH_QUALIFIER                  = 128;
    public int MAX_LENGTH_SYMMETRIC_KEY              = 128;
    public int MAX_LENGTH_ID_TYPE                    = 32;
    public int MAX_LENGTH_URI                        = 1000;
    public int MAX_LENGTH_CRYPTO_DATA                = 16384;
    public int MAX_LENGTH_EXTENSION_DATA             = 65536;

    ///////////////////////////////////////////////////////////////////////////////////
    // Method IDs are used "as is" in the MAC KDF
    ///////////////////////////////////////////////////////////////////////////////////
    public byte[] METHOD_SET_CERTIFICATE_PATH        = {'s','e','t','C','e','r','t','i','f','i','c','a','t','e','P','a','t','h'};
    public byte[] METHOD_SET_SYMMETRIC_KEY           = {'s','e','t','S','y','m','m','e','t','r','i','c','K','e','y'};
    public byte[] METHOD_RESTORE_PRIVATE_KEY         = {'r','e','s','t','o','r','e','P','r','i','v','a','t','e','K','e','y'};
    public byte[] METHOD_CLOSE_PROVISIONING_SESSION  = {'c','l','o','s','e','P','r','o','v','i','s','i','o','n','i','n','g','S','e','s','s','i','o','n'};
    public byte[] METHOD_CREATE_KEY_ENTRY            = {'c','r','e','a','t','e','K','e','y','E','n','t','r','y'};
    public byte[] METHOD_CREATE_PIN_POLICY           = {'c','r','e','a','t','e','P','I','N','P','o','l','i','c','y'};
    public byte[] METHOD_CREATE_PUK_POLICY           = {'c','r','e','a','t','e','P','U','K','P','o','l','i','c','y'};
    public byte[] METHOD_ADD_EXTENSION               = {'a','d','d','E','x','t','e','n','s','i','o','n'};
    public byte[] METHOD_PP_DELETE_KEY               = {'p','p','_','d','e','l','e','t','e','K','e','y'};
    public byte[] METHOD_PP_UNLOCK_KEY               = {'p','p','_','u','n','l','o','c','k','K','e','y'};
    public byte[] METHOD_PP_UPDATE_KEY               = {'p','p','_','u','p','d','a','t','e','K','e','y'};
    public byte[] METHOD_PP_CLONE_KEY_PROTECTION     = {'p','p','_','c','l','o','n','e','K','e','y','P','r','o','t','e','c','t','i','o','n'};

    ///////////////////////////////////////////////////////////////////////////////////
    // Other KDF constants that are used "as is"
    ///////////////////////////////////////////////////////////////////////////////////
    public byte[] KDF_DEVICE_ATTESTATION             = {'D','e','v','i','c','e',' ','A','t','t','e','s','t','a','t','i','o','n'};
    public byte[] KDF_ENCRYPTION_KEY                 = {'E','n','c','r','y','p','t','i','o','n',' ','K','e','y'};
    public byte[] KDF_EXTERNAL_SIGNATURE             = {'E','x','t','e','r','n','a','l',' ','S','i','g','n','a','t','u','r','e'};
    public byte[] KDF_ANONYMOUS                      = {'A','n','o','n','y','m','o','u','s'};

    ///////////////////////////////////////////////////////////////////////////////////
    // Predefined PIN and PUK policy IDs for MAC operations
    ///////////////////////////////////////////////////////////////////////////////////
    public String CRYPTO_STRING_NOT_AVAILABLE        = "#N/A";
    public String CRYPTO_STRING_DEVICE_PIN           = "#Device PIN";

    ///////////////////////////////////////////////////////////////////////////////////
    // See "AppUsage" in the SKS specification
    ///////////////////////////////////////////////////////////////////////////////////
    public byte APP_USAGE_SIGNATURE                  = 0x00;
    public byte APP_USAGE_AUTHENTICATION             = 0x01;
    public byte APP_USAGE_ENCRYPTION                 = 0x02;
    public byte APP_USAGE_UNIVERSAL                  = 0x03;

    ///////////////////////////////////////////////////////////////////////////////////
    // See "PIN Grouping" in the SKS specification
    ///////////////////////////////////////////////////////////////////////////////////
    public byte PIN_GROUPING_NONE                    = 0x00;
    public byte PIN_GROUPING_SHARED                  = 0x01;
    public byte PIN_GROUPING_SIGN_PLUS_STD           = 0x02;
    public byte PIN_GROUPING_UNIQUE                  = 0x03;

    ///////////////////////////////////////////////////////////////////////////////////
    // See "PIN Pattern Control" in the SKS specification
    ///////////////////////////////////////////////////////////////////////////////////
    public byte PIN_PATTERN_TWO_IN_A_ROW             = 0x01;
    public byte PIN_PATTERN_THREE_IN_A_ROW           = 0x02;
    public byte PIN_PATTERN_SEQUENCE                 = 0x04;
    public byte PIN_PATTERN_REPEATED                 = 0x08;
    public byte PIN_PATTERN_MISSING_GROUP            = 0x10;

    ///////////////////////////////////////////////////////////////////////////////////
    // See "PIN and PUK Formats" in the SKS specification
    ///////////////////////////////////////////////////////////////////////////////////
    public byte PIN_FORMAT_NUMERIC                   = 0x00;
    public byte PIN_FORMAT_ALPHANUMERIC              = 0x01;
    public byte PIN_FORMAT_STRING                    = 0x02;
    public byte PIN_FORMAT_BINARY                    = 0x03;

    ///////////////////////////////////////////////////////////////////////////////////
    // See "SubType" for "addExtension" in the SKS specification
    ///////////////////////////////////////////////////////////////////////////////////
    public byte SUB_TYPE_EXTENSION                   = 0x00;
    public byte SUB_TYPE_ENCRYPTED_EXTENSION         = 0x01;
    public byte SUB_TYPE_PROPERTY_BAG                = 0x02;
    public byte SUB_TYPE_LOGOTYPE                    = 0x03;

    ///////////////////////////////////////////////////////////////////////////////////
    // "ExportProtection" and "DeleteProtection" share constants (and code...)
    ///////////////////////////////////////////////////////////////////////////////////
    public byte EXPORT_DELETE_PROTECTION_NONE        = 0x00;
    public byte EXPORT_DELETE_PROTECTION_PIN         = 0x01;
    public byte EXPORT_DELETE_PROTECTION_PUK         = 0x02;
    public byte EXPORT_DELETE_PROTECTION_NOT_ALLOWED = 0x03;

    ///////////////////////////////////////////////////////////////////////////////////
    // "InputMethod" constants
    ///////////////////////////////////////////////////////////////////////////////////
    public byte INPUT_METHOD_PROGRAMMATIC            = 0x01;
    public byte INPUT_METHOD_TRUSTED_GUI             = 0x02;
    public byte INPUT_METHOD_ANY                     = 0x03;

    ///////////////////////////////////////////////////////////////////////////////////
    // "BiometricProtection" constants
    ///////////////////////////////////////////////////////////////////////////////////
    public byte BIOMETRIC_PROTECTION_NONE            = 0x00;
    public byte BIOMETRIC_PROTECTION_ALTERNATIVE     = 0x01;
    public byte BIOMETRIC_PROTECTION_COMBINED        = 0x02;
    public byte BIOMETRIC_PROTECTION_EXCLUSIVE       = 0x03;

    ///////////////////////////////////////////////////////////////////////////////////
    // SKS key algorithm IDs used in "createKeyPair"
    ///////////////////////////////////////////////////////////////////////////////////
    public byte KEY_ALGORITHM_TYPE_RSA               = 0x00;
    public byte KEY_ALGORITHM_TYPE_EC                = 0x01;

    ///////////////////////////////////////////////////////////////////////////////////
    // "ProtectionStatus" constants
    ///////////////////////////////////////////////////////////////////////////////////
    public byte PROTECTION_STATUS_NO_PIN             = 0x00;
    public byte PROTECTION_STATUS_PIN_PROTECTED      = 0x01;
    public byte PROTECTION_STATUS_PIN_BLOCKED        = 0x04;
    public byte PROTECTION_STATUS_PUK_PROTECTED      = 0x02;
    public byte PROTECTION_STATUS_PUK_BLOCKED        = 0x08;
    public byte PROTECTION_STATUS_DEVICE_PIN         = 0x10;
 
    ///////////////////////////////////////////////////////////////////////////////////
    // Default algorithms
    ///////////////////////////////////////////////////////////////////////////////////
    public short[] SKS_DEFAULT_RSA_SUPPORT       = {1024, 2048};

    public String ALGORITHM_KEY_ATTEST_1         = "http://xmlns.webpki.org/keygen2/1.0#algorithm.sks.k1";

    public String ALGORITHM_SESSION_KEY_ATTEST_1 = "http://xmlns.webpki.org/keygen2/1.0#algorithm.sks.s1";

    ///////////////////////////////////////////////////////////////////////////////////
    // Miscellaneous
    ///////////////////////////////////////////////////////////////////////////////////
    public byte[] ZERO_LENGTH_ARRAY              = new byte[0];
    
    public short SKS_API_LEVEL                   = 0x0001;


    ///////////////////////////////////////////////////////////////////////////////////
    // Core Provisioning API
    ///////////////////////////////////////////////////////////////////////////////////

    public ProvisioningSession createProvisioningSession (String algorithm,
                                                          boolean privacy_enabled,
                                                          String server_session_id,
                                                          ECPublicKey server_ephemeral_key,
                                                          String issuer_uri,
                                                          PublicKey key_management_key, // Must be null if not applicable
                                                          int client_time,
                                                          int session_life_time,
                                                          short session_key_limit) throws SKSException;

    public byte[] closeProvisioningSession (int provisioning_handle,
                                            byte[] nonce,
                                            byte[] mac) throws SKSException;

    public EnumeratedProvisioningSession enumerateProvisioningSessions (int provisioning_handle,
                                                                        boolean provisioning_state) throws SKSException;

    public byte[] signProvisioningSessionData (int provisioning_handle,
                                               byte[] data) throws SKSException;

    public KeyData createKeyEntry (int provisioning_handle,
                                   String id,
                                   String algorithm,
                                   byte[] server_seed,  // May be null
                                   boolean device_pin_protection,
                                   int pin_policy_handle,
                                   byte[] pin_value,  // Must be null if not applicable
                                   boolean enable_pin_caching,
                                   byte biometric_protection,
                                   byte export_protection,
                                   byte delete_protection,
                                   byte app_usage,
                                   String friendly_name,  // May be null
                                   byte[] key_specifier,
                                   String[] endorsed_algorithms,
                                   byte[] mac) throws SKSException;
    
    public int getKeyHandle (int provisioning_handle,
                             String id) throws SKSException;

    public void abortProvisioningSession (int provisioning_handle) throws SKSException;
    
    public void setCertificatePath (int key_handle,
                                    X509Certificate[] certificate_path,
                                    byte[] mac) throws SKSException;
    
    public void addExtension (int key_handle,
                              String type,
                              byte sub_type,
                              byte[] qualifier,
                              byte[] extension_data,
                              byte[] mac) throws SKSException;
    
    public void setSymmetricKey (int key_handle,
                                 byte[] symmetric_key,
                                 byte[] mac) throws SKSException;
    
    public void restorePrivateKey (int key_handle,
                                   byte[] private_key,
                                   byte[] mac) throws SKSException;

    public int createPINPolicy (int provisioning_handle,
                                String id,
                                int puk_policy_handle,
                                boolean user_defined,
                                boolean user_modifiable,
                                byte format,
                                short retry_limit,
                                byte grouping,
                                byte pattern_restrictions,
                                short min_length,
                                short max_length,
                                byte input_method,
                                byte[] mac) throws SKSException;

    public int createPUKPolicy (int provisioning_handle,
                                String id,
                                byte[] puk_value,
                                byte format,
                                short retry_limit,
                                byte[] mac) throws SKSException;

    ///////////////////////////////////////////////////////////////////////////////////
    // Post Provisioning (Management)
    ///////////////////////////////////////////////////////////////////////////////////

    public void pp_deleteKey (int provisioning_handle,
                              int target_key_handle,
                              byte[] authorization,
                              byte[] mac) throws SKSException;

    public void pp_unlockKey (int provisioning_handle,
                              int target_key_handle,
                              byte[] authorization,
                              byte[] mac) throws SKSException;

    public void pp_updateKey (int key_handle,
                              int target_key_handle,
                              byte[] authorization,
                              byte[] mac) throws SKSException;

    public void pp_cloneKeyProtection (int key_handle,
                                       int target_key_handle,
                                       byte[] authorization,
                                       byte[] mac) throws SKSException;

    ///////////////////////////////////////////////////////////////////////////////////
    // "User" API
    ///////////////////////////////////////////////////////////////////////////////////

    public KeyAttributes getKeyAttributes (int key_handle) throws SKSException;
    
    public EnumeratedKey enumerateKeys (int key_handle) throws SKSException;

    public byte[] signHashedData (int key_handle,
                                  String algorithm,
                                  byte[] parameters,    // Must be null if not applicable
                                  byte[] authorization, // Must be null if not applicable
                                  byte[] data) throws SKSException;
    
    public byte[] performHMAC (int key_handle,
                               String algorithm,
                               byte[] authorization, // Must be null if not applicable
                               byte[] data) throws SKSException;
    
    public byte[] symmetricKeyEncrypt (int key_handle,
                                       String algorithm,
                                       boolean mode,
                                       byte[] iv,            // Must be null if not applicable
                                       byte[] authorization, // Must be null if not applicable
                                       byte[] data) throws SKSException;

    public byte[] asymmetricKeyDecrypt (int key_handle,
                                        String algorithm,
                                        byte[] parameters,    // Must be null if not applicable
                                        byte[] authorization, // Must be null if not applicable
                                        byte[] data) throws SKSException;

    public byte[] keyAgreement (int key_handle,
                                String algorithm,
                                byte[] parameters,    // Must be null if not applicable
                                byte[] authorization, // Must be null if not applicable
                                PublicKey public_key) throws SKSException;

    void deleteKey (int key_handle,
                    byte[] authorization /* Must be null if not applicable */) throws SKSException;
    
   
    ///////////////////////////////////////////////////////////////////////////////////
    // Miscellaneous
    ///////////////////////////////////////////////////////////////////////////////////

    public DeviceInfo getDeviceInfo () throws SKSException;

    public Extension getExtension (int key_handle,
                                   String type) throws SKSException;
    
    public KeyProtectionInfo getKeyProtectionInfo (int key_handle) throws SKSException;

    public void setProperty (int key_handle,
                             String type,
                             byte[] name,
                             byte[] value) throws SKSException;

    public void unlockKey (int key_handle,
                           byte[] authorization) throws SKSException;
    
    public void changePIN (int key_handle,
                           byte[] authorization,
                           byte[] new_pin) throws SKSException;
    
    public void setPIN (int key_handle,
                        byte[] authorization,
                        byte[] new_pin) throws SKSException;

    public byte[] exportKey (int key_handle,
                             byte[] authorization /* Must be null if not applicable */) throws SKSException;

  }
