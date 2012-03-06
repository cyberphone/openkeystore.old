package org.webpki.sks.twolayer.se;

public class SEProvisioningState
  {
    short mac_sequence_counter;

    short session_key_limit;
    
    byte[] wrapped_session_key;
  }
