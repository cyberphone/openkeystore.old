package org.webpki.keygen2;

import java.io.IOException;
import java.security.interfaces.ECPublicKey;

public interface ServerSessionKeyInterface
  {
    ECPublicKey generateEphemeralKey () throws IOException;
    
    byte[] generateSessionKey (ECPublicKey client_ephemeral_key) throws IOException;
  }
