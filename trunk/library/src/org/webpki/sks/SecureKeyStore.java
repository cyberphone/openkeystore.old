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

import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;

import org.webpki.keygen2.KeyInitializationRequestDecoder;
import org.webpki.keygen2.KeyUsage;

public interface SecureKeyStore
  {
    public KeyPairResult createKeyPair (int provisioning_handle,
                                        String attestation_algorithm,
                                        byte[] server_seed,
                                        String id,
                                        int pin_policy_handle,
                                        byte[] pin_value,
                                        byte biometric_protection,
                                        boolean private_key_backup,
                                        byte export_policy,
                                        boolean updatable,
                                        byte delete_policy,
                                        boolean enable_pin_caching,
                                        boolean import_private_key,
                                        KeyUsage key_usage,
                                        String friendly_name,
                                        KeyInitializationRequestDecoder.KeyAlgorithmData key_algorithm) throws SKSException;
    
    public EnumeratedKey enumerateKeys (int key_handle,
                                        boolean provisioning_state) throws SKSException;
    
    public void abortProvisioningSession (int provisioning_handle) throws SKSException;
    
    public void setCertificatePath (int key_handle,
                                    X509Certificate[] certificate_path,
                                    byte[] mac) throws SKSException;
    
    public byte[] closeProvisioningSession (int provisioning_handle, byte[] mac) throws SKSException;

    public ProvisioningSessionResult createProvisioningSession (String session_key_algorithm,
                                                                String server_session_id,
                                                                ECPublicKey server_ephemeral_key,
                                                                String issuer_uri,
                                                                boolean updatable,
                                                                int client_time,
                                                                int session_life_time,
                                                                int session_key_limit) throws SKSException;

    public DeviceInfo getDeviceInfo () throws SKSException;
    
    public EnumeratedProvisioningSession enumerateProvisioningSessions (int provisioning_handle,
                                                                        boolean provisioning_state) throws SKSException;

    public KeyAttributes getKeyAttributes (int key_handle) throws SKSException;
    
    public byte[] signProvisioningSessionData (int provisioning_handle,
                                               byte[] data) throws SKSException;
   
  }
