package org.webpki.crypto;


import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.PublicKey;

import org.webpki.crypto.SignatureAlgorithms;

public interface AsymKeySignerInterface
  {

    public byte[] signData (byte[] data, SignatureAlgorithms algorithm) throws IOException, GeneralSecurityException;

    public PublicKey getPublicKey () throws IOException, GeneralSecurityException;

  }
