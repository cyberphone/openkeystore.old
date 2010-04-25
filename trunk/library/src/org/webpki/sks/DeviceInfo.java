package org.webpki.sks;

import java.security.cert.X509Certificate;

public class DeviceInfo
  {
    X509Certificate[] certificate_path;
    
    public X509Certificate[] getDeviceCertificatePath ()
      {
        return certificate_path;
      }
    
    public DeviceInfo (X509Certificate[] certificate_path)
      {
        this.certificate_path = certificate_path;
      }

  }
