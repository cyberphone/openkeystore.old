package org.webpki.sks.twolayer;

import java.security.interfaces.ECPublicKey;

public class SEProvisioningData
  {
    public SEProvisioningState se_provisioning_state;

    public String client_session_id;

    public byte[] attestation;

    public ECPublicKey client_ephemeral_key;
  }
