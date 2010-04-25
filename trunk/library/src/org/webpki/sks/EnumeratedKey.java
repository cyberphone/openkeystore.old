package org.webpki.sks;

import java.security.cert.X509Certificate;

public class EnumeratedKey
  {
    int key_handle;
    
    public int getKeyHandle ()
      {
        return key_handle;
      }
    int provisioning_handle;
    
    public int getProvisioningHandle ()
      {
        return provisioning_handle;
      }
    
    String id;
    
    public String getID ()
      {
        return id;
      }
    
    X509Certificate[] certificate_path;
    
    public X509Certificate[] getCertificatePath ()
      {
        return certificate_path;
      }
    // TODO - a LOT!!!!
    
    public EnumeratedKey (int key_handle, 
                          String id,
                          int provisioning_handle,
                          X509Certificate[] certificate_path)
      {
        this.key_handle = key_handle;
        this.id = id;
        this.provisioning_handle = provisioning_handle;
        this.certificate_path = certificate_path;
      }

  }
