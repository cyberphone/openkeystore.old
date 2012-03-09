package org.webpki.sks.twolayer.se;

import java.security.PublicKey;

public class SEKeyData
  {
    public SealedKey sealed_key;
    
    public byte[] attestation;
    
    public byte[] decrypted_pin_value;

    public PublicKey public_key;
  }
