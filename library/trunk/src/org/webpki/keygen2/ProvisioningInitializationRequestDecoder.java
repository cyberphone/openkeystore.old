/*
 *  Copyright 2006-2014 WebPKI.org (http://webpki.org).
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
package org.webpki.keygen2;

import java.io.IOException;
import java.util.Date;
import java.util.Vector;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;

import org.webpki.json.JSONArrayReader;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONSignatureDecoder;
import org.webpki.util.ISODateTime;

import static org.webpki.keygen2.KeyGen2Constants.*;


public class ProvisioningInitializationRequestDecoder extends ClientDecoder
  {
    private static final long serialVersionUID = 1L;

    public class KeyManagementKeyUpdateHolder
      {
        Vector<KeyManagementKeyUpdateHolder> children = new Vector<KeyManagementKeyUpdateHolder> ();
        
        PublicKey kmk;

        byte[] authorization;
        
        public KeyManagementKeyUpdateHolder[] KeyManagementKeyUpdateHolders ()
          {
            return children.toArray (new KeyManagementKeyUpdateHolder[0]);
          }
        
        public PublicKey getKeyManagementKey ()
          {
            return kmk;
          }
        
        KeyManagementKeyUpdateHolder (PublicKey kmk)
          {
            this.kmk = kmk;
          }

        public byte[] getAuthorization ()
          {
            return authorization;
          }
      }
    
    private KeyManagementKeyUpdateHolder kmk_root = new KeyManagementKeyUpdateHolder (null);
    
    public KeyManagementKeyUpdateHolder getKeyManagementKeyUpdateHolderRoot ()
      {
        return kmk_root;
      }

    String session_key_algorithm;
    
    public String getServerSessionID ()
      {
        return server_session_id;
      }


    public Date getServerTime ()
      {
        return server_time;
      }


    public String getSubmitURL ()
      {
        return submit_url;
      }

    
    public ECPublicKey getServerEphemeralKey ()
      {
        return server_ephemeral_key;
      }

    
    public String getSessionKeyAlgorithm ()
      {
        return session_key_algorithm;
      }


    public int getSessionLifeTime ()
      {
        return session_life_time;
      }

    
    public short getSessionKeyLimit ()
      {
        return session_key_limit;
      }


    PublicKey key_management_key;

    public PublicKey getKeyManagementKey ()
      {
        return key_management_key;
      }

    
    public String getVirtualEnvironmentFriendlyName ()
      {
        return virtual_environment_friendly_name;
      }


    private void scanForUpdateKeys (JSONObjectReader rd, KeyManagementKeyUpdateHolder kmk) throws IOException
      {
        if (rd.hasProperty (UPDATABLE_KEY_MANAGEMENT_KEYS_JSON))
          {
            JSONArrayReader upd_arr = rd.getArray (UPDATABLE_KEY_MANAGEMENT_KEYS_JSON);
            do
              {
                JSONObjectReader kmk_upd = upd_arr.getObject ();
                byte[] authorization = kmk_upd.getBinary (AUTHORIZATION_JSON);
                KeyManagementKeyUpdateHolder child = new KeyManagementKeyUpdateHolder (kmk_upd.getPublicKey ());
                child.authorization = authorization;
                kmk.children.add (child);
                scanForUpdateKeys (kmk_upd, child);
              }
            while (upd_arr.hasMore ());
          }
      }

    String server_session_id;
    
    byte[] nonce;

    Date server_time;
    
    String server_time_verbatim;

    String submit_url;
    
    ECPublicKey server_ephemeral_key;
    
    byte[] virtual_environment_data;

    String virtual_environment_type;

    String virtual_environment_friendly_name;  // Optional, defined => Virtual environment defined
    
    int session_life_time;

    short session_key_limit;

    
    @Override
    void readServerRequest (JSONObjectReader rd) throws IOException
      {
        /////////////////////////////////////////////////////////////////////////////////////////
        // Read the top level properties
        /////////////////////////////////////////////////////////////////////////////////////////
        session_key_algorithm = rd.getString (SESSION_KEY_ALGORITHM_JSON);
        
        server_session_id = getID (rd, SERVER_SESSION_ID_JSON);
        
        server_time_verbatim = rd.getString (SERVER_TIME_JSON);

        server_time = ISODateTime.parseDateTime (server_time_verbatim).getTime ();

        submit_url = getURL (rd, SUBMIT_URL_JSON);
        
        session_key_limit = (short)rd.getInt (SESSION_KEY_LIMIT_JSON);
        
        session_life_time = rd.getInt (SESSION_LIFE_TIME_JSON);
        
        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the server key
        /////////////////////////////////////////////////////////////////////////////////////////
        server_ephemeral_key = (ECPublicKey) rd.getObject (SERVER_EPHEMERAL_KEY_JSON).getPublicKey ();

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the optional key management key
        /////////////////////////////////////////////////////////////////////////////////////////
        if (rd.hasProperty (KEY_MANAGEMENT_KEY_JSON))
          {
            JSONObjectReader kmkrd = rd.getObject (KEY_MANAGEMENT_KEY_JSON);
            key_management_key = kmkrd.getPublicKey ();
            scanForUpdateKeys (kmkrd, kmk_root = new KeyManagementKeyUpdateHolder (key_management_key));
          }

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the optional virtual environment
        /////////////////////////////////////////////////////////////////////////////////////////
        if (rd.hasProperty (VIRTUAL_ENVIRONMENT_JSON))
          {
            //TODO
            rd.getBinaryConditional (NONCE_JSON);
            if (!rd.hasProperty (JSONSignatureDecoder.SIGNATURE_JSON))
              {
                throw new IOException ("Virtual Environment requests must be signed");
              }
            JSONObjectReader vmrd = rd.getObject (VIRTUAL_ENVIRONMENT_JSON);
            virtual_environment_data = vmrd.getBinary (CONFIGURATION_JSON);
            virtual_environment_type = vmrd.getString (TYPE_JSON);
            virtual_environment_friendly_name = vmrd.getString (FRIENDLY_NAME_JSON);
          }
      }

    @Override
    public String getQualifier ()
      {
        return KeyGen2Messages.PROVISIONING_INITIALIZATION_REQUEST.getName ();
      }
  }

