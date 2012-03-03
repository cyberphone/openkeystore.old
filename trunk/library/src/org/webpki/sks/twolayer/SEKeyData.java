package org.webpki.sks.twolayer;

import java.security.PublicKey;

public class SEKeyData
  {
    public SEKeyState se_key_state;
    
    public byte[] attestation;
    
    public byte[] decrypted_pin_value;

    public PublicKey public_key;
  }
