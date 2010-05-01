/*
 *  Copyright 2006-2010 WebPKI.org (http://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
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
