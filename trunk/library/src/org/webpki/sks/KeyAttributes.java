package org.webpki.sks;

import java.security.cert.X509Certificate;

public class KeyAttributes
  {
    X509Certificate[] certificate_path;
    
    public X509Certificate[] getCertificatePath ()
      {
        return certificate_path;
      }
    
    public KeyAttributes (X509Certificate[] certificate_path)
      {
        this.certificate_path = certificate_path;
      }

  }
