package org.webpki.keygen2;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.interfaces.ECPublicKey;

public interface ServerSessionKeyInterface
  {
    ECPublicKey generateEphemeralKey () throws IOException, GeneralSecurityException;
    
    void generateSessionKey (ECPublicKey client_ephemeral_key,
                             String client_session_id,
                             String server_session_id,
                             String issuer_uri) throws IOException, GeneralSecurityException;;
  }
