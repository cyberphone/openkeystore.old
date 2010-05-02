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

public class KeyPair
  {
    private PublicKey public_key;
    
    private byte[] key_attestation;
    
    private byte[] encrypted_private_key;
    
    public KeyPair (PublicKey public_key, byte[] key_attestation, byte[] encrypted_private_key)
      {
        this.public_key = public_key;
        this.key_attestation = key_attestation;
        this.encrypted_private_key = encrypted_private_key;
      }
    
    public PublicKey getPublicKey ()
      {
        return public_key;
      }
    
    public byte[] getKeyAttestation ()
      {
        return key_attestation;
      }
    
    public byte[] getEncryptedPrivateKey ()
      {
        return encrypted_private_key;
      }

  }
