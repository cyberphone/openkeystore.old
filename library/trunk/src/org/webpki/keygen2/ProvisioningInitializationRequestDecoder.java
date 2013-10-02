/*
 *  Copyright 2006-2013 WebPKI.org (http://webpki.org).
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

import static org.webpki.keygen2.KeyGen2Constants.*;


public class ProvisioningInitializationRequestDecoder extends ClientDecoder
  {
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

    String algorithm;
    
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
        return algorithm;
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

    
    public String getVirtualMachineFriendlyName ()
      {
        return virtual_machine_friendly_name;
      }


    public String[] getClientAttributes ()
      {
        return client_attributes.toArray (new String[0]);
      }
 
    
    private void scanForUpdateKeys (JSONObjectReader rd, KeyManagementKeyUpdateHolder kmk) throws IOException
      {
        if (rd.hasProperty (UPDATE_KEY_MANAGEMENT_KEYS_JSON))
          {
            JSONArrayReader upd_arr = rd.getArray (UPDATE_KEY_MANAGEMENT_KEYS_JSON);
            do
              {
                JSONObjectReader kmk_upd = upd_arr.getObject ();
                byte[] authorization = kmk_upd.getBinary (AUTHORIZATION_JSON);
                KeyManagementKeyUpdateHolder child = new KeyManagementKeyUpdateHolder (JSONSignatureDecoder.readPublicKey (kmk_upd));
                child.authorization = authorization;
                kmk.children.add (child);
                scanForUpdateKeys (rd, child);
              }
            while (upd_arr.hasMore ());
          }
      }

    String server_session_id;
    
    byte[] nonce;

    Date server_time;

    String submit_url;
    
    ECPublicKey server_ephemeral_key;
    
    byte[] virtual_machine_data;

    String virtual_machine_type;

    String virtual_machine_friendly_name;  // Optional, defined => Virtual machine defined
    
    Vector<String> client_attributes = new Vector<String> ();
    
    int session_life_time;

    short session_key_limit;

    
    @Override
    void readServerRequest (JSONObjectReader rd) throws IOException
      {
        /////////////////////////////////////////////////////////////////////////////////////////
        // Read the top level properties
        /////////////////////////////////////////////////////////////////////////////////////////
        server_session_id = getID (rd, SERVER_SESSION_ID_JSON);

        server_time = rd.getDateTime (SERVER_TIME_JSON).getTime ();

        submit_url = getURL (rd, SUBMIT_URL_JSON);
        
        algorithm = rd.getString (JSONSignatureDecoder.ALGORITHM_JSON);
        
        session_key_limit = (short)rd.getInt (SESSION_KEY_LIMIT_JSON);
        
        session_life_time = rd.getInt (SESSION_LIFE_TIME_JSON);
        
        String[] attrs = rd.getStringArrayConditional (REQUESTED_CLIENT_ATTRIBUTES_JSON);
        if (attrs != null)
          {
            for (String attr : attrs)
              {
                client_attributes.add (attr);
              }
          }

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the server key
        /////////////////////////////////////////////////////////////////////////////////////////
        server_ephemeral_key = (ECPublicKey) JSONSignatureDecoder.readPublicKey (rd.getObject (SERVER_EPHEMERAL_KEY_JSON));

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the optional key management key
        /////////////////////////////////////////////////////////////////////////////////////////
        if (rd.hasProperty (KEY_MANAGEMENT_KEY_JSON))
          {
            JSONObjectReader kmkrd = rd.getObject (KEY_MANAGEMENT_KEY_JSON);
            key_management_key = JSONSignatureDecoder.readPublicKey (kmkrd);
            scanForUpdateKeys (kmkrd, kmk_root = new KeyManagementKeyUpdateHolder (key_management_key));
          }

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the optional virtual machine
        /////////////////////////////////////////////////////////////////////////////////////////
        if (rd.hasProperty (VIRTUAL_MACHINE_JSON))
          {
            //TODO
            rd.getBinaryConditional (NONCE_JSON);
            if (!rd.hasProperty (JSONSignatureDecoder.SIGNATURE_JSON))
              {
                throw new IOException ("Virtual Machine requests must be signed");
              }
            JSONObjectReader vmrd = rd.getObject (VIRTUAL_MACHINE_JSON);
            virtual_machine_data = vmrd.getBinary (CONFIGURATION_JSON);
            virtual_machine_type = vmrd.getString (TYPE_JSON);
            virtual_machine_friendly_name = vmrd.getString (FRIENDLY_NAME_JSON);
          }
      }

    @Override
    public String getQualifier ()
      {
        return PROVISIONING_INITIALIZATION_REQUEST_JSON;
      }
  }

