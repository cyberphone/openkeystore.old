/*
 *  Copyright 2006-2015 WebPKI.org (http://webpki.org).
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

import java.security.GeneralSecurityException;
import java.security.PublicKey;

import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import java.util.Date;
import java.util.Vector;

import org.webpki.sks.SecureKeyStore;

import org.webpki.util.ArrayUtil;

import org.webpki.json.JSONArrayWriter;
import org.webpki.json.JSONObjectWriter;

import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.SignatureWrapper;

import org.webpki.keygen2.ServerState.ProtocolPhase;

import static org.webpki.keygen2.KeyGen2Constants.*;


public class ProvisioningInitializationRequestEncoder extends ServerEncoder
  {
    private static final long serialVersionUID = 1L;

    ServerState server_state;
    
    KeyManagementKeyUpdateHolder kmk_root;
    
    public class KeyManagementKeyUpdateHolder
      {
        PublicKey key_management_key;
        
        byte[] authorization;
        
        Vector<KeyManagementKeyUpdateHolder> children = new Vector<KeyManagementKeyUpdateHolder> ();
        
        KeyManagementKeyUpdateHolder (PublicKey key_management_key)
          {
            this.key_management_key = key_management_key;
          }

        public KeyManagementKeyUpdateHolder update (PublicKey key_management_key) throws IOException
          {
            KeyManagementKeyUpdateHolder kmk = new KeyManagementKeyUpdateHolder (key_management_key);
            kmk.authorization = server_state.server_crypto_interface.generateKeyManagementAuthorization (key_management_key,
                                                                                                         ArrayUtil.add (SecureKeyStore.KMK_ROLL_OVER_AUTHORIZATION,
                                                                                                         this.key_management_key.getEncoded ()));
            children.add (kmk);
            return kmk;
          }

        public KeyManagementKeyUpdateHolder update (PublicKey key_management_key, byte[] external_authorization) throws IOException
          {
            KeyManagementKeyUpdateHolder kmk = new KeyManagementKeyUpdateHolder (key_management_key);
            kmk.authorization = external_authorization;
            try
              {
                SignatureWrapper kmk_verify = 
                    new SignatureWrapper (key_management_key instanceof RSAPublicKey ? 
                                                  AsymSignatureAlgorithms.RSA_SHA256 : AsymSignatureAlgorithms.ECDSA_SHA256,
                                          key_management_key);
                kmk_verify.update (SecureKeyStore.KMK_ROLL_OVER_AUTHORIZATION);
                kmk_verify.update (this.key_management_key.getEncoded ());
                if (!kmk_verify.verify (external_authorization))
                  {
                    throw new IOException ("Authorization signature did not validate");
                  }
              }
            catch (GeneralSecurityException e)
              {
                throw new IOException (e);
              }
            children.add (kmk);
            return kmk;
          }
      }    

    // Constructors

    public ProvisioningInitializationRequestEncoder (ServerState server_state,
                                                     String submit_url,
                                                     int session_life_time,
                                                     short session_key_limit)  throws IOException
      {
        server_state.checkState (true, ProtocolPhase.PROVISIONING_INITIALIZATION);
        this.server_state = server_state;
        this.submit_url = server_state.issuer_uri = submit_url;
        this.session_life_time = server_state.session_life_time = session_life_time;
        this.session_key_limit = server_state.session_key_limit = session_key_limit;
        nonce = server_state.ve_nonce;
        server_session_id = server_state.server_session_id;
        server_ephemeral_key = server_state.server_ephemeral_key = server_state.generateEphemeralKey ();
      }


    public KeyManagementKeyUpdateHolder setKeyManagementKey (PublicKey key_management_key)
      {
        return kmk_root = new KeyManagementKeyUpdateHolder (server_state.key_management_key = key_management_key);
      }


    public void setVirtualEnvironment (byte[] ve_data, String type, String friendly_name)
      {
        virtual_environment_data = ve_data;
        virtual_environment_type = type;
        virtual_environment_friendly_name = friendly_name;
      }


    public void setSessionKeyAlgorithm (String session_key_algorithm)
      {
        server_state.provisioning_session_algorithm = session_key_algorithm;
      }

    
    public void setServerTime (Date server_time)
      {
        this.server_time = server_time;
      }
    
    private void scanForUpdatedKeys (JSONObjectWriter wr, KeyManagementKeyUpdateHolder kmk) throws IOException
      {
        if (!kmk.children.isEmpty ())
          {
            JSONArrayWriter kmku_arr = wr.setArray (UPDATABLE_KEY_MANAGEMENT_KEYS_JSON);
            for (KeyManagementKeyUpdateHolder child : kmk.children)
              {
                JSONObjectWriter kmku_object = kmku_arr.setObject ();
                kmku_object.setPublicKey (child.key_management_key);
                kmku_object.setBinary (AUTHORIZATION_JSON, child.authorization);
                scanForUpdatedKeys (kmku_object, child);
              }
          }
      }


    String server_session_id;
    
    byte[] nonce;

    Date server_time;

    String submit_url;
    
    ECPublicKey server_ephemeral_key;
    
    byte[] virtual_environment_data;

    String virtual_environment_type;

    String virtual_environment_friendly_name;  // Optional, defined => Virtual environment defined
    
    int session_life_time;

    short session_key_limit;

    @Override
    void checkIfSignatureIsRequired () throws IOException
      {
        if (virtual_environment_data != null)
          {
            bad ("\"" + VIRTUAL_ENVIRONMENT_JSON + "\" requires a signed request");
          }
      }

    @Override
    void checkIfNonceIsSpecified () throws IOException
      {
        if (nonce == null)
          {
            bad ("Signed request needs a \"" + NONCE_JSON + "\"");
          }
      }

    @Override
    void writeServerRequest (JSONObjectWriter wr) throws IOException
      {
        //////////////////////////////////////////////////////////////////////////
        // Core session properties
        //////////////////////////////////////////////////////////////////////////
        wr.setString (SERVER_SESSION_ID_JSON, server_session_id);
        
        wr.setString (SUBMIT_URL_JSON, submit_url);
        
        if (server_time == null)
          {
            server_time = new Date ();
          }
        wr.setDateTime (SERVER_TIME_JSON, server_time, true); // Server is UTC

        wr.setString (SESSION_KEY_ALGORITHM_JSON, server_state.provisioning_session_algorithm);

        wr.setInt (SESSION_KEY_LIMIT_JSON, session_key_limit);

        wr.setInt (SESSION_LIFE_TIME_JSON, session_life_time);

        ////////////////////////////////////////////////////////////////////////
        // Server ephemeral key
        ////////////////////////////////////////////////////////////////////////
        wr.setObject (SERVER_EPHEMERAL_KEY_JSON).setPublicKey (server_ephemeral_key);

        ////////////////////////////////////////////////////////////////////////
        // Optional key management key
        ////////////////////////////////////////////////////////////////////////
        if (kmk_root != null)
          {
            JSONObjectWriter kmk_writer = wr.setObject (KEY_MANAGEMENT_KEY_JSON);
            kmk_writer.setPublicKey (kmk_root.key_management_key);
            scanForUpdatedKeys (kmk_writer, kmk_root);
          }

        ////////////////////////////////////////////////////////////////////////
        // Optional request for a virtual environment
        ////////////////////////////////////////////////////////////////////////
        if (virtual_environment_data != null)
          {
            wr.setObject (VIRTUAL_ENVIRONMENT_JSON)
              .setString (TYPE_JSON, virtual_environment_type)
              .setBinary (CONFIGURATION_JSON, virtual_environment_data)
              .setString (FRIENDLY_NAME_JSON, virtual_environment_friendly_name);
          }

        ////////////////////////////////////////////////////////////////////////
        // Signed requests must have a nonce
        ////////////////////////////////////////////////////////////////////////
        setOptionalBinary (wr, NONCE_JSON, nonce);
      }

    @Override
    public String getQualifier ()
      {
        return KeyGen2Messages.PROVISIONING_INITIALIZATION_REQUEST.getName ();
      }
  }
