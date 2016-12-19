/*
 *  Copyright 2006-2016 WebPKI.org (http://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
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

import org.webpki.sks.ws.TrustedGUIAuthorization;
import org.webpki.sks.ws.WSSpecific;

public class SKSWSNativeClient implements SecureKeyStore, WSSpecific {
    @Override
    native public ProvisioningSession createProvisioningSession(String algorithm,
                                                                boolean privacy_enabled,
                                                                String server_session_id,
                                                                ECPublicKey server_ephemeral_key,
                                                                String issuer_uri,
                                                                PublicKey key_management_key,
                                                                int client_time,
                                                                int session_life_time,
                                                                short session_key_limit) throws SKSException;

    @Override
    native public byte[] closeProvisioningSession(int provisioning_handle,
                                                  byte[] nonce,
                                                  byte[] mac) throws SKSException;

    @Override
    native public EnumeratedProvisioningSession enumerateProvisioningSessions(int provisioning_handle,
                                                                              boolean provisioning_state) throws SKSException;

    @Override
    native public byte[] signProvisioningSessionData(int provisioning_handle,
                                                     byte[] data) throws SKSException;

    @Override
    native public KeyData createKeyEntry(int provisioning_handle,
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
                                         String key_algorithm,
                                         byte[] key_parameters,
                                         String[] endorsed_algorithms,
                                         byte[] mac) throws SKSException;

    @Override
    native public int getKeyHandle(int provisioning_handle,
                                   String id) throws SKSException;

    @Override
    native public void abortProvisioningSession(int provisioning_handle) throws SKSException;

    @Override
    native public void setCertificatePath(int key_handle,
                                          X509Certificate[] certificate_path,
                                          byte[] mac) throws SKSException;

    @Override
    native public void addExtension(int key_handle,
                                    String type,
                                    byte sub_type,
                                    String qualifier,
                                    byte[] extension_data,
                                    byte[] mac) throws SKSException;

    @Override
    native public void importSymmetricKey(int key_handle,
                                          byte[] symmetric_key,
                                          byte[] mac) throws SKSException;

    @Override
    native public void importPrivateKey(int key_handle,
                                        byte[] private_key,
                                        byte[] mac) throws SKSException;

    @Override
    native public int createPinPolicy(int provisioning_handle,
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
    native public int createPukPolicy(int provisioning_handle,
                                      String id,
                                      byte[] puk_value,
                                      byte format,
                                      short retry_limit,
                                      byte[] mac) throws SKSException;

    @Override
    native public void postDeleteKey(int provisioning_handle,
                                     int target_key_handle,
                                     byte[] authorization,
                                     byte[] mac) throws SKSException;

    @Override
    native public void postUnlockKey(int provisioning_handle,
                                     int target_key_handle,
                                     byte[] authorization,
                                     byte[] mac) throws SKSException;

    @Override
    native public void postUpdateKey(int key_handle,
                                     int target_key_handle,
                                     byte[] authorization,
                                     byte[] mac) throws SKSException;

    @Override
    native public void postCloneKeyProtection(int key_handle,
                                              int target_key_handle,
                                              byte[] authorization,
                                              byte[] mac) throws SKSException;

    @Override
    native public KeyAttributes getKeyAttributes(int key_handle) throws SKSException;

    @Override
    native public EnumeratedKey enumerateKeys(int key_handle) throws SKSException;

    @Override
    native public byte[] signHashedData(int key_handle,
                                        String algorithm,
                                        byte[] parameters,
                                        byte[] authorization,
                                        byte[] data) throws SKSException;

    @Override
    native public byte[] performHmac(int key_handle,
                                     String algorithm,
                                     byte[] parameters,
                                     byte[] authorization,
                                     byte[] data) throws SKSException;

    @Override
    native public byte[] symmetricKeyEncrypt(int key_handle,
                                             String algorithm,
                                             boolean mode,
                                             byte[] parameters,
                                             byte[] authorization,
                                             byte[] data) throws SKSException;

    @Override
    native public byte[] asymmetricKeyDecrypt(int key_handle,
                                              String algorithm,
                                              byte[] parameters,
                                              byte[] authorization,
                                              byte[] data) throws SKSException;

    @Override
    native public byte[] keyAgreement(int key_handle,
                                      String algorithm,
                                      byte[] parameters,
                                      byte[] authorization,
                                      ECPublicKey public_key) throws SKSException;

    @Override
    native public void deleteKey(int key_handle,
                                 byte[] authorization) throws SKSException;

    @Override
    native public DeviceInfo getDeviceInfo() throws SKSException;

    @Override
    native public Extension getExtension(int key_handle,
                                         String type) throws SKSException;

    @Override
    native public KeyProtectionInfo getKeyProtectionInfo(int key_handle) throws SKSException;

    @Override
    native public void setProperty(int key_handle,
                                   String type,
                                   String name,
                                   String value) throws SKSException;

    @Override
    native public void unlockKey(int key_handle,
                                 byte[] authorization) throws SKSException;

    @Override
    native public void changePin(int key_handle,
                                 byte[] authorization,
                                 byte[] new_pin) throws SKSException;

    @Override
    native public void setPin(int key_handle,
                              byte[] authorization,
                              byte[] new_pin) throws SKSException;

    @Override
    native public byte[] exportKey(int key_handle,
                                   byte[] authorization) throws SKSException;

    @Override
    native public String getVersion();

    @Override
    native public void logEvent(String event);

    @Override
    public boolean setTrustedGUIAuthorizationProvider(TrustedGUIAuthorization tga) {
        return false;
    }

    @Override
    public String[] listDevices() throws SKSException {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public void setDeviceID(String device_id) {
        // TODO Auto-generated method stub

    }

    @Override
    public String updateFirmware(byte[] chunk) throws SKSException {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public void updateKeyManagementKey(int provisioning_handle, PublicKey key_managegent_key, byte[] authorization) throws SKSException {
        // TODO Auto-generated method stub

    }

}
