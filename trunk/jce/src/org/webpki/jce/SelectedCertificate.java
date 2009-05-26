package org.webpki.jce;

import java.io.IOException;

import java.security.cert.X509Certificate;


/**
 * PKI certificate high-level selector
 */
public class SelectedCertificate
  {
    X509Certificate certificate;

    int key_id;

    int user_id;


    SelectedCertificate (X509Certificate certificate, int key_id, int user_id)
      {
        this.certificate = certificate;
        this.key_id = key_id;
        this.user_id = user_id;
      }


    public X509Certificate getCertificate ()
      {
        return certificate;
      }


    public KeyDescriptor getKeyDescriptor () throws IOException
      {
        return new KeyMetadataProvider (user_id).getKeyDescriptor (key_id);
      }

  }
