package org.webpki.sks;

public class EnumeratedProvisioningSession
  {
    public static final int INIT = 0xFFFFFFFF;
    public static final int EXIT = 0xFFFFFFFF;

    int provisioning_handle;
    
    public int getProvisioningHandle ()
      {
        return provisioning_handle;
      }
    
    String client_session_id;
    
    public String getClientSessionID ()
      {
        return client_session_id;
      }
    
    String server_session_id;
    
    public String getServerSessionID ()
      {
        return server_session_id;
      }
    

    public EnumeratedProvisioningSession ()
      {
        provisioning_handle = EXIT;
      }


    public EnumeratedProvisioningSession (int provisioning_handle,
                                          String client_session_id,
                                          String server_session_id)
      {
        this.provisioning_handle = provisioning_handle;
        this.client_session_id = client_session_id;
        this.server_session_id = server_session_id;
      }

  }
