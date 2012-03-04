package org.webpki.sks.twolayer.se;

import java.security.PrivateKey;
import java.security.interfaces.RSAKey;

public class SEKeyState
  {
    boolean is_symmetric_key;
    
    boolean exportable;
    
    byte[] symmetric_key;
    
    PrivateKey private_key;
    
    boolean isRSA ()
      {
        return private_key instanceof RSAKey;
      }
  }
