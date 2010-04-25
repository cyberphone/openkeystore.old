package org.webpki.sks;

import java.security.interfaces.ECPublicKey;

public class ProvisioningSessionResult
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

    public ProvisioningSessionResult (int provisioning_handle, 
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
