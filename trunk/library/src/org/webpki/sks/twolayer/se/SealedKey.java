package org.webpki.sks.twolayer.se;

public class SealedKey
  {
    boolean is_symmetric;
    
    boolean is_exportable;
    
    byte[] wrapped_key;
    
    byte[] sha256_of_public_key_or_ee_certificate;  // just a little consistency checker
    
    byte[] mac;
  }
