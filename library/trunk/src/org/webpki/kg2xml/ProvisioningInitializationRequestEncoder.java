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
package org.webpki.kg2xml;

import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;

import java.security.interfaces.RSAPublicKey;

import java.util.Date;
import java.util.Vector;

import org.w3c.dom.Document;

import org.webpki.sks.SecureKeyStore;
import org.webpki.util.ArrayUtil;
import org.webpki.xml.DOMWriterHelper;

import org.webpki.xmldsig.XMLSigner;
import org.webpki.xmldsig.XMLSignatureWrapper;

import org.webpki.crypto.SignerInterface;
import org.webpki.kg2xml.ServerState.ProtocolPhase;

import static org.webpki.kg2xml.KeyGen2Constants.*;


public class ProvisioningInitializationRequestEncoder extends ProvisioningInitializationRequest
  {
    String prefix;  // Default: no prefix
    
    ServerState server_state;
    
    KeyManagementKeyUpdateHolder kmk_root;
    
    boolean output_dsig_ns;

    public class KeyManagementKeyUpdateHolder
      {
        PublicKey key_management_key;
        
        byte[] authorization;
        
        Vector<KeyManagementKeyUpdateHolder> children = new Vector<KeyManagementKeyUpdateHolder> ();
        
        KeyManagementKeyUpdateHolder (PublicKey key_management_key)
          {
            if (key_management_key instanceof RSAPublicKey)
              {
                output_dsig_ns = true;
              }
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
                Signature kmk_verify = Signature.getInstance (key_management_key instanceof RSAPublicKey ? 
                                                                                         "SHA256WithRSA" : "SHA256WithECDSA");
                kmk_verify.initVerify (key_management_key);
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
        super.submit_url = server_state.issuer_uri = submit_url;
        super.session_life_time = server_state.session_life_time = session_life_time;
        super.session_key_limit = server_state.session_key_limit = session_key_limit;
        super.nonce = server_state.vm_nonce;
        server_session_id = server_state.server_session_id;
        server_ephemeral_key = server_state.server_ephemeral_key = server_state.server_crypto_interface.generateEphemeralKey ();
        for (String client_attribute : server_state.basic_capabilities.client_attributes)
          {
            client_attributes.add (client_attribute);
          }
      }


    public KeyManagementKeyUpdateHolder setKeyManagementKey (PublicKey key_management_key)
      {
        return kmk_root = new KeyManagementKeyUpdateHolder (server_state.key_management_key = key_management_key);
      }


    public void setVirtualMachine (byte[] vm_data, String type, String friendly_name)
      {
        virtual_machine_data = vm_data;
        virtual_machine_type = type;
        virtual_machine_friendly_name = friendly_name;
      }


    public void setSessionKeyAlgorithm (String session_key_algorithm)
      {
        server_state.provisioning_session_algorithm = session_key_algorithm;
      }

    
    public void setServerTime (Date server_time)
      {
        super.server_time = server_time;
      }
    
    
    public void setPrefix (String prefix)
      {
        this.prefix = prefix;
      }


    public void signRequest (SignerInterface signer) throws IOException
      {
        output_dsig_ns = true;
        XMLSigner ds = new XMLSigner (signer);
        ds.removeXMLSignatureNS ();
        Document doc = getRootDocument ();
        ds.createEnvelopedSignature (doc, server_session_id);
      }


    private void scanForUpdatedKeys (DOMWriterHelper wr, KeyManagementKeyUpdateHolder kmk) throws IOException
      {
        for (KeyManagementKeyUpdateHolder child : kmk.children)
          {
            wr.addChildElement (UPDATABLE_KEY_MANAGEMENT_KEY_ELEM);
            wr.setBinaryAttribute (AUTHORIZATION_ATTR, child.authorization);
            XMLSignatureWrapper.writePublicKey (wr, child.key_management_key);
            scanForUpdatedKeys (wr, child);
            wr.getParent ();
          }
      }


    protected void toXML (DOMWriterHelper wr) throws IOException
      {
        wr.initializeRootObject (prefix);

        XMLSignatureWrapper.addXMLSignature11NS (wr);
        
        if (output_dsig_ns)
          {
            XMLSignatureWrapper.addXMLSignatureNS (wr);
          }

        //////////////////////////////////////////////////////////////////////////
        // Set top-level attributes
        //////////////////////////////////////////////////////////////////////////
        wr.setStringAttribute (ID_ATTR, server_session_id);
        
        if (nonce != null)
          {
            wr.setBinaryAttribute (NONCE_ATTR, nonce);
          }

        if (server_time == null)
          {
            server_time = new Date ();
          }

        wr.setDateTimeAttribute (SERVER_TIME_ATTR, server_time);

        wr.setStringAttribute (SUBMIT_URL_ATTR, submit_url);
        
        wr.setIntAttribute (SESSION_LIFE_TIME_ATTR, session_life_time);

        wr.setIntAttribute (SESSION_KEY_LIMIT_ATTR, session_key_limit);

        wr.setStringAttribute (SESSION_KEY_ALGORITHM_ATTR, server_state.provisioning_session_algorithm);
        
        if (!client_attributes.isEmpty ())
          {
            wr.setListAttribute (REQUESTED_CLIENT_ATTRIBUTES_ATTR, client_attributes.toArray (new String[0]));
          }
        
        ////////////////////////////////////////////////////////////////////////
        // Server ephemeral key
        ////////////////////////////////////////////////////////////////////////
        wr.addChildElement (SERVER_EPHEMERAL_KEY_ELEM);
        XMLSignatureWrapper.writePublicKey (wr, server_ephemeral_key);
        wr.getParent();

        ////////////////////////////////////////////////////////////////////////
        // Key management key
        ////////////////////////////////////////////////////////////////////////
        if (kmk_root != null)
          {
            wr.addChildElement (KEY_MANAGEMENT_KEY_ELEM);
            XMLSignatureWrapper.writePublicKey (wr, kmk_root.key_management_key);
            scanForUpdatedKeys (wr, kmk_root);
            wr.getParent();
          }

        ////////////////////////////////////////////////////////////////////////
        // We request a VM as well
        ////////////////////////////////////////////////////////////////////////
        if (virtual_machine_data != null)
          {
            wr.addBinary (VIRTUAL_MACHINE_ELEM, virtual_machine_data);
            wr.setStringAttribute (TYPE_ATTR, virtual_machine_type);
            wr.setStringAttribute (FRIENDLY_NAME_ATTR, virtual_machine_friendly_name);
          }
      }
  }
