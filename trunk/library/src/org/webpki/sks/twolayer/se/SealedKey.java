package org.webpki.sks.twolayer.se;

public class SealedKey
  {
    boolean is_symmetric;
    
    boolean is_exportable;
    
    byte[] wrapped_key;
    
    byte[] mac;
  }
