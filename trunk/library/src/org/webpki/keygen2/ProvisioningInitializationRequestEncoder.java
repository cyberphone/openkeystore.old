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

import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

import java.util.Date;

import org.w3c.dom.Document;

import org.webpki.xml.DOMWriterHelper;
import org.webpki.xml.ServerCookie;

import org.webpki.xmldsig.XMLSigner;
import org.webpki.xmldsig.XMLSignatureWrapper;

import org.webpki.crypto.SignerInterface;

import static org.webpki.keygen2.KeyGen2Constants.*;


public class ProvisioningInitializationRequestEncoder extends ProvisioningInitializationRequest
  {
    String prefix;  // Default: no prefix
    

    // Constructors

    public ProvisioningInitializationRequestEncoder (String submit_url,
                                                     int session_life_time,
                                                     short session_key_limit)  throws IOException
      {
        super.submit_url = submit_url;
        super.session_life_time = session_life_time;
        super.session_key_limit = session_key_limit;
      }


    public ServerCookie setServerCookie (ServerCookie server_cookie)
      {
        return super.server_cookie = server_cookie;
      }


    public void setKeyManagementKey (PublicKey key_management_key)
      {
        super.key_management_key = key_management_key;
      }


    public void setSessionKeyAlgorithm (String session_key_algorithm)
      {
        super.algorithm = session_key_algorithm;
      }

    
    public void setServerTime (Date server_time)
      {
        super.server_time = server_time;
      }
    
    
    public ProvisioningInitializationRequestEncoder addClientAttribute (String client_attribute)
      {
        client_attributes.add (client_attribute);
        return this;
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

        wr.setStringAttribute (XMLSignatureWrapper.ALGORITHM_ATTR, algorithm);
        
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
            wr.getParent();
          }
        
        ////////////////////////////////////////////////////////////////////////
        // Optional ServerCookie
        ////////////////////////////////////////////////////////////////////////
        if (server_cookie != null)
          {
            server_cookie.write (wr);
          }
      }

  }
