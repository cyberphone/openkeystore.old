package org.webpki.sks;

public class EnumeratedKey
  {
    public static final int INIT = 0xFFFFFFFF;
    public static final int EXIT = 0xFFFFFFFF;
    
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
    
    // TODO - a LOT!!!!
    
    public EnumeratedKey (int key_handle, 
                          String id,
                          int provisioning_handle)
      {
        this.key_handle = key_handle;
        this.id = id;
        this.provisioning_handle = provisioning_handle;
      }

  }
