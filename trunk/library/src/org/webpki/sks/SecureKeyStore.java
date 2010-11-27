/*
 *  Copyright 2006-2010 WebPKI.org (http://webpki.org).
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
    // Core Provisioning API
    ///////////////////////////////////////////////////////////////////////////////////

    public ProvisioningSession createProvisioningSession (String session_key_algorithm,
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

    public EnumeratedProvisioningSession enumerateProvisioningSessions (EnumeratedProvisioningSession eps,
                                                                        boolean provisioning_state) throws SKSException;

    public byte[] signProvisioningSessionData (int provisioning_handle,
                                               byte[] data) throws SKSException;

    public KeyPair createKeyPair (int provisioning_handle,
                                  String id,
                                  String attestation_algorithm,
                                  byte[] server_seed,
                                  boolean device_pin_protection,
                                  int pin_policy_handle,
                                  byte[] pin_value,  // Must be null if not applicable
                                  byte biometric_protection,
                                  boolean private_key_backup,
                                  byte export_protection,
                                  byte delete_protection,
                                  boolean enable_pin_caching,
                                  byte app_usage,
                                  String friendly_name,
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
                                byte[] value,
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
    
    public EnumeratedKey enumerateKeys (EnumeratedKey ek) throws SKSException;

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
