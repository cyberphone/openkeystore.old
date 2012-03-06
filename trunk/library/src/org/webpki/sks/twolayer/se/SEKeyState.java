package org.webpki.sks.twolayer.se;

public class SEKeyState
  {
    boolean is_symmetric_key;
    
    boolean exportable;
    
    byte[] wrapped_key;
    
    byte[] mac;
  }
