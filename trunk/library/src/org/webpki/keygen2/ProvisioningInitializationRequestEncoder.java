/*
 *  Copyright 2006-2012 WebPKI.org (http://webpki.org).
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
import java.security.interfaces.RSAPublicKey;

import java.util.Date;

import org.w3c.dom.Document;

import org.webpki.xml.DOMWriterHelper;

import org.webpki.xmldsig.XMLSigner;
import org.webpki.xmldsig.XMLSignatureWrapper;

import org.webpki.crypto.SignerInterface;
import org.webpki.keygen2.ServerState.ProtocolPhase;

import static org.webpki.keygen2.KeyGen2Constants.*;


public class ProvisioningInitializationRequestEncoder extends ProvisioningInitializationRequest
  {
    String prefix;  // Default: no prefix
    
    ServerState server_state;
    

    // Constructors

    public ProvisioningInitializationRequestEncoder (ServerState server_state,
                                                     String submit_url,
                                                     int session_life_time,
                                                     short session_key_limit)  throws IOException
      {
        try
          {
            server_state.checkState (true, ProtocolPhase.PROVISIONING_INITIALIZATION);
            this.server_state = server_state;
            super.submit_url = server_state.issuer_uri = submit_url;
            super.session_life_time = server_state.session_life_time = session_life_time;
            super.session_key_limit = server_state.session_key_limit = session_key_limit;
            server_session_id = server_state.server_session_id;
            server_ephemeral_key = server_state.server_ephemeral_key = server_state.server_crypto_interface.generateEphemeralKey ();
            for (String client_attribute : server_state.basic_capabilities.client_attributes)
              {
                client_attributes.add (client_attribute);
              }
          }
        catch (GeneralSecurityException e)
          {
            throw new IOException (e);
          }
      }


    public void setKeyManagementKey (PublicKey key_management_key)
      {
        super.key_management_key = key_management_key;
        server_state.key_management_key = key_management_key;
      }


    public void setVirtualMachineFriendlyName (String name) throws IOException
      {
        if (key_management_key == null)
          {
            throw new IOException ("\"" + KEY_MANAGEMENT_KEY_ELEM + "\" must be set first");
          }
        virtual_machine_friendly_name = name;
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
        XMLSigner ds = new XMLSigner (signer);
        Document doc = getRootDocument ();
        ds.createEnvelopedSignature (doc, server_session_id);
      }


    protected void toXML (DOMWriterHelper wr) throws IOException
      {
        wr.initializeRootObject (prefix);

        XMLSignatureWrapper.addXMLSignature11NS (wr);
        
        if (key_management_key != null && key_management_key instanceof RSAPublicKey)
          {
            XMLSignatureWrapper.addXMLSignatureNS (wr);
          }

        //////////////////////////////////////////////////////////////////////////
        // Set top-level attributes
        //////////////////////////////////////////////////////////////////////////
        wr.setStringAttribute (ID_ATTR, server_session_id);

        if (server_time == null)
          {
            server_time = new Date ();
          }
        wr.setDateTimeAttribute (SERVER_TIME_ATTR, server_time);

        wr.setStringAttribute (SUBMIT_URL_ATTR, submit_url);
        
        wr.setIntAttribute (SESSION_LIFE_TIME_ATTR, session_life_time);

        wr.setIntAttribute (SESSION_KEY_LIMIT_ATTR, session_key_limit);

        wr.setStringAttribute (XMLSignatureWrapper.ALGORITHM_ATTR, server_state.provisioning_session_algorithm);
        
        if (!client_attributes.isEmpty ())
          {
            wr.setListAttribute (CLIENT_ATTRIBUTES_ATTR, client_attributes.toArray (new String[0]));
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
        if (key_management_key != null)
          {
            wr.addChildElement (KEY_MANAGEMENT_KEY_ELEM);
            XMLSignatureWrapper.writePublicKey (wr, key_management_key);
            if (virtual_machine_friendly_name != null)
              {
                ////////////////////////////////////////////////////////////////////////
                // We request a VM as well
                ////////////////////////////////////////////////////////////////////////
                wr.addChildElement (VIRTUAL_MACHINE_ELEM);
                wr.setStringAttribute (FRIENDLY_NAME_ATTR, virtual_machine_friendly_name);
                try
                  {
                    wr.setBinaryAttribute (AUTHORIZATION_ATTR,
                                           server_state.server_crypto_interface.generateKeyManagementAuthorization (key_management_key,
                                                                                                                    server_ephemeral_key.getEncoded ()));
                  }
                catch (GeneralSecurityException e)
                  {
                    throw new IOException (e);
                  }
                wr.getParent();
              }
            wr.getParent();
          }
      }
  }
