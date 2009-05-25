package org.webpki.keygen2;

import java.io.IOException;

import java.security.GeneralSecurityException;

import java.security.cert.X509Certificate;


public interface SymmetricKeyDecrypter
  {
    public byte[] decrypt (byte[] value, X509Certificate optional_key_id) throws IOException, GeneralSecurityException;
  }
