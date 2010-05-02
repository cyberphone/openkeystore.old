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

import java.security.interfaces.ECPublicKey;

public class ProvisioningSession
  {
    int provisioning_handle;

    public int getProvisioningHandle ()
      {
        return provisioning_handle;
      }

    String client_session_id;

    public String getClientSessionID ()
      {
        return client_session_id;
      }

    byte[] session_attestation;

    public byte[] getSessionAttestation ()
      {
        return session_attestation;
      }

    ECPublicKey client_ephemeral_key;

    public ECPublicKey getClientEphemeralKey ()
      {
        return client_ephemeral_key;
      }

    public ProvisioningSession (int provisioning_handle, 
                                      String client_session_id,
                                      byte[] session_attestation,
                                      ECPublicKey client_ephemeral_key)
      {
        this.provisioning_handle = provisioning_handle;
        this.client_session_id = client_session_id;
        this.session_attestation = session_attestation;
        this.client_ephemeral_key = client_ephemeral_key;
      }

  }
