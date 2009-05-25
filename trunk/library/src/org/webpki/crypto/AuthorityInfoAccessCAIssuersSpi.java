package org.webpki.crypto;

import java.io.IOException;

import java.security.cert.X509Certificate;


public interface AuthorityInfoAccessCAIssuersSpi
  {

    X509Certificate[] getUpdatedPath (X509Certificate[] input_path) throws IOException;

  }
