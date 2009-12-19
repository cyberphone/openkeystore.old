package org.webpki.sks;

import java.io.IOException;

import java.security.cert.X509Certificate;


/**
 * PKI certificate high-level selector
 */
public class SelectedCertificate
  {
    X509Certificate certificate;

    int key_id;

    SecureKeyStore sks;


    SelectedCertificate (X509Certificate certificate, int key_id, SecureKeyStore sks)
      {
        this.certificate = certificate;
        this.key_id = key_id;
        this.sks = sks;
      }


    public X509Certificate getCertificate ()
      {
        return certificate;
      }


    public KeyDescriptor getKeyDescriptor () throws IOException
      {
        return new KeyMetadataProvider (sks).getKeyDescriptor (key_id);
      }

  }
