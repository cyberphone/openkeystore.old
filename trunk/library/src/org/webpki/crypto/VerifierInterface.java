package org.webpki.crypto;

import java.io.IOException;

import java.security.cert.X509Certificate;


public interface VerifierInterface
  {

    void setTrustedRequired (boolean flag) throws IOException;

    boolean verifyCertificatePath (X509Certificate[] certpath) throws IOException;

    X509Certificate[] getSignerCertificatePath () throws IOException;;
 
    CertificateInfo getSignerCertificateInfo () throws IOException;

  }
