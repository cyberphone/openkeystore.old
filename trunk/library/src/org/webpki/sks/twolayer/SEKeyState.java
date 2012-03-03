package org.webpki.sks.twolayer;

import java.security.PrivateKey;

public class SEKeyState
  {
    public boolean is_symmetric_key;
    
    public boolean exportable;
    
    public byte[] symmetric_key;
    
    public PrivateKey private_key;
  }
