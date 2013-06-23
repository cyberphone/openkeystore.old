/*
 *  Copyright 2006-2013 WebPKI.org (http://webpki.org).
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
package org.webpki.android.sks;

import java.security.PublicKey;

public class KeyData
  {
    private int key_handle;
    
    private PublicKey public_key;
    
    private byte[] attestation;
    
    public KeyData (int key_handle,
                    PublicKey public_key, 
                    byte[] attestation)
      {
        this.key_handle = key_handle;
        this.public_key = public_key;
        this.attestation = attestation;
      }
    
    public PublicKey getPublicKey ()
      {
        return public_key;
      }

    public int getKeyHandle ()
      {
        return key_handle;
      }
    
    public byte[] getAttestation ()
      {
        return attestation;
      }
    
  }
