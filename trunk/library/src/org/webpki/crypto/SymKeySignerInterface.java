package org.webpki.crypto;


import java.io.IOException;

import java.security.GeneralSecurityException;

public interface SymKeySignerInterface
  {

    public byte[] signData (byte[] data) throws IOException, GeneralSecurityException;

    public MacAlgorithms getMacAlgorithm () throws IOException, GeneralSecurityException;

  }
