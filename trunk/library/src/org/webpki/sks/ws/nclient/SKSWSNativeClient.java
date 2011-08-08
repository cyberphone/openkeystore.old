package org.webpki.sks.ws.nclient;

import java.security.PublicKey;

import java.security.cert.X509Certificate;

import java.security.interfaces.ECPublicKey;

import org.webpki.sks.DeviceInfo;
import org.webpki.sks.EnumeratedKey;
import org.webpki.sks.EnumeratedProvisioningSession;
import org.webpki.sks.Extension;
import org.webpki.sks.KeyAttributes;
import org.webpki.sks.KeyData;
import org.webpki.sks.KeyProtectionInfo;
import org.webpki.sks.ProvisioningSession;
import org.webpki.sks.SKSException;
import org.webpki.sks.SecureKeyStore;

import org.webpki.sks.ws.WSSpecific;

public class SKSWSNativeClient implements SecureKeyStore, WSSpecific
  {
    @Override
    native public ProvisioningSession createProvisioningSession (String algorithm, 
                                                                 boolean privacy_enabled, 
                                                                 String server_session_id,
                                                                 ECPublicKey server_ephemeral_key,
                                                                 String issuer_uri, 
                                                                 PublicKey key_management_key,
                                                                 int client_time,
                                                                 int session_life_time,
                                                                 short session_key_limit) throws SKSException;

    @Override
    native public byte[] closeProvisioningSession (int provisioning_handle, 
                                                   byte[] nonce,
                                                   byte[] mac) throws SKSException;

    @Override
    native public EnumeratedProvisioningSession enumerateProvisioningSessions (int provisioning_handle,
                                                                               boolean provisioning_state) throws SKSException;

    @Override
    native public byte[] signProvisioningSessionData (int provisioning_handle,
                                                      byte[] data) throws SKSException;

    @Override
    native public KeyData createKeyEntry (int provisioning_handle,
                                          String id,
                                          String algorithm,
                                          byte[] server_seed,
                                          boolean device_pin_protection,
                                          int pin_policy_handle, 
                                          byte[] pin_value, 
                                          boolean enable_pin_caching, 
                                          byte biometric_protection, 
                                          byte export_protection, 
                                          byte delete_protection, 
                                          byte app_usage, 
                                          String friendly_name, 
                                          boolean private_key_backup, 
                                          byte[] key_specifier, 
                                          String[] endorsed_algorithms, 
                                          byte[] mac) throws SKSException;

    @Override
    native public int getKeyHandle (int provisioning_handle,
                                    String id) throws SKSException;

    @Override
    native public void abortProvisioningSession (int provisioning_handle) throws SKSException;

    @Override
    native public void setCertificatePath (int key_handle,
                                           X509Certificate[] certificate_path,
                                           byte[] mac) throws SKSException;

    @Override
    native public void addExtension (int key_handle,
                                     String type,
                                     byte sub_type,
                                     byte[] qualifier,
                                     byte[] extension_data,
                                     byte[] mac) throws SKSException;

    @Override
    native public void setSymmetricKey (int key_handle, 
                                        byte[] symmetric_key,
                                        byte[] mac) throws SKSException;

    @Override
    native public void restorePrivateKey (int key_handle,
                                          byte[] private_key,
                                          byte[] mac) throws SKSException;

    @Override
    native public int createPINPolicy (int provisioning_handle,
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

    @Override
    native public int createPUKPolicy (int provisioning_handle,
                                       String id,
                                       byte[] puk_value,
                                       byte format,
                                       short retry_limit,
                                       byte[] mac) throws SKSException;

    @Override
    native public void pp_deleteKey (int provisioning_handle, 
                                     int target_key_handle,
                                     byte[] authorization,
                                     byte[] mac) throws SKSException;

    @Override
    native public void pp_unlockKey (int provisioning_handle, 
                                     int target_key_handle,
                                     byte[] authorization,
                                     byte[] mac) throws SKSException;

    @Override
    native public void pp_updateKey (int key_handle,
                                     int target_key_handle,
                                     byte[] authorization,
                                     byte[] mac) throws SKSException;

    @Override
    native public void pp_cloneKeyProtection (int key_handle,
                                              int target_key_handle,
                                              byte[] authorization,
                                              byte[] mac) throws SKSException;

    @Override
    native public KeyAttributes getKeyAttributes (int key_handle) throws SKSException;

    @Override
    native public EnumeratedKey enumerateKeys (int key_handle) throws SKSException;

    @Override
    native public byte[] signHashedData (int key_handle,
                                         String algorithm,
                                         byte[] parameters,
                                         byte[] authorization,
                                         byte[] data) throws SKSException;

    @Override
    native public byte[] performHMAC (int key_handle,
                                      String algorithm,
                                      byte[] authorization,
                                      byte[] data) throws SKSException;

    @Override
    native public byte[] symmetricKeyEncrypt (int key_handle, 
                                              String algorithm,
                                              boolean mode, 
                                              byte[] iv,
                                              byte[] authorization,
                                              byte[] data) throws SKSException;

    @Override
    native public byte[] asymmetricKeyDecrypt (int key_handle,
                                               String algorithm,
                                               byte[] parameters,
                                               byte[] authorization,
                                               byte[] data) throws SKSException;

    @Override
    native public byte[] keyAgreement (int key_handle,
                                       String algorithm,
                                       byte[] parameters,
                                       byte[] authorization, 
                                       PublicKey public_key) throws SKSException;

    @Override
    native public void deleteKey (int key_handle, 
                                  byte[] authorization) throws SKSException;

    @Override
    native public DeviceInfo getDeviceInfo () throws SKSException;

    @Override
    native public Extension getExtension (int key_handle,
                                          String type) throws SKSException;

    @Override
    native public KeyProtectionInfo getKeyProtectionInfo (int key_handle) throws SKSException;

    @Override
    native public void setProperty (int key_handle, 
                                    String type,
                                    byte[] name,
                                    byte[] value) throws SKSException;

    @Override
    native public void unlockKey (int key_handle,
                                  byte[] authorization) throws SKSException;

    @Override
    native public void changePIN (int key_handle, 
                                  byte[] authorization,
                                  byte[] new_pin) throws SKSException;

    @Override
    native public void setPIN (int key_handle, 
                               byte[] authorization,
                               byte[] new_pin) throws SKSException;

    @Override
    native public byte[] exportKey (int key_handle,
                                    byte[] authorization) throws SKSException;

    @Override
    native public String getVersion ();

    @Override
    native public void logEvent (String event);
  }
