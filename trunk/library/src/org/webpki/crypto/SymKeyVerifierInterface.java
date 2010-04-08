package org.webpki.crypto;


import java.io.IOException;

import java.security.GeneralSecurityException;

public interface SymKeyVerifierInterface
  {

    public boolean verifyData (byte[] data, byte[] digest, MacAlgorithms algorithm) throws IOException, GeneralSecurityException;

  }
