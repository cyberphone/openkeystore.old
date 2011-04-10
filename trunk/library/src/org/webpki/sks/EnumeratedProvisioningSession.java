/*
 *  Copyright 2006-2011 WebPKI.org (http://webpki.org).
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


import java.util.Date;

import java.security.PublicKey;

public class EnumeratedProvisioningSession
  {
    public static final int INIT_ENUMERATION = 0;

    int provisioning_handle = INIT_ENUMERATION;
    
    public int getProvisioningHandle ()
      {
        return provisioning_handle;
      }
    

    PublicKey key_management_key;
    
    public PublicKey getKeyManagementKey ()
      {
        return key_management_key;
      }


    int client_time;
    
    public Date getClientTime ()
      {
        return new Date (client_time * 1000);
      }
    

    int session_life_time;
    
    public int getSessionLifeTime ()
      {
        return session_life_time;
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
 
    
    String issuer_uri;
    
    public String getIssuerURI ()
      {
        return issuer_uri;
      }
    

    public EnumeratedProvisioningSession ()
      {
      }
    
    
    public EnumeratedProvisioningSession (PublicKey key_management_key,
                                          int client_time,
                                          int session_life_time,
                                          int provisioning_handle,
                                          String client_session_id,
                                          String server_session_id,
                                          String issuer_uri)
      {
        this.key_management_key = key_management_key;
        this.client_time = client_time;
        this.session_life_time = session_life_time;
        this.provisioning_handle = provisioning_handle;
        this.client_session_id = client_session_id;
        this.server_session_id = server_session_id;
        this.issuer_uri = issuer_uri;
      }

  }
