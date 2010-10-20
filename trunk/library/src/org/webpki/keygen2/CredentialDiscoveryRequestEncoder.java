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
package org.webpki.keygen2;

import java.io.IOException;

import java.util.Vector;

import org.w3c.dom.Document;

import org.webpki.xml.DOMWriterHelper;
import org.webpki.xml.ServerCookie;

import org.webpki.xmldsig.XMLSignatureWrapper;
import org.webpki.xmldsig.XMLSigner;

import org.webpki.crypto.SignerInterface;

import static org.webpki.keygen2.KeyGen2Constants.*;

public class CredentialDiscoveryRequestEncoder extends CredentialDiscoveryRequest
  {
    public class LookupDescriptor
      {
        ServerCryptoInterface server_crypto_interface;

        LookupDescriptor (ServerCryptoInterface server_crypto_interface)
          {
            this.server_crypto_interface = server_crypto_interface;
          }

        String mime_type;
        byte[] image_fingerprint;
        int width;
        int height;
        String logotype_url;
      }

    private String prefix;  // Default: no prefix
    
    Vector<LookupDescriptor> lookup_descriptors = new Vector<LookupDescriptor> ();


    // Constructors

    public CredentialDiscoveryRequestEncoder (ServerCredentialStore server_credential_store,
                                              String submit_url)
      {
        super.server_session_id = server_credential_store.server_session_id;
        super.submit_url = submit_url;
      }


    public ServerCookie setServerCookie (ServerCookie server_cookie)
      {
        return super.server_cookie = server_cookie;
      }


    public void setPrefix (String prefix)
      {
        this.prefix = prefix;
      }


    public void signRequest (SignerInterface signer) throws IOException
      {
        XMLSigner ds = new XMLSigner (signer);
        ds.removeXMLSignatureNS ();
        Document doc = getRootDocument ();
        ds.createEnvelopedSignature (doc, server_session_id);
      }

    
    public LookupDescriptor addLookupDescriptor (ServerCryptoInterface server_crypto_interface)
      {
        LookupDescriptor lo_des = new LookupDescriptor (server_crypto_interface);
        lookup_descriptors.add (lo_des);
        return lo_des;
      }


    protected void toXML (DOMWriterHelper wr) throws IOException
      {
        wr.initializeRootObject (prefix);

        //////////////////////////////////////////////////////////////////////////
        // Set top-level attributes
        //////////////////////////////////////////////////////////////////////////
        wr.setStringAttribute (ID_ATTR, server_session_id);

        wr.setStringAttribute (CLIENT_SESSION_ID_ATTR, client_session_id);

        wr.setStringAttribute (SUBMIT_URL_ATTR, submit_url);
        
        XMLSignatureWrapper.addXMLSignatureNS (wr);

        ////////////////////////////////////////////////////////////////////////
        // Lookup descriptors
        ////////////////////////////////////////////////////////////////////////
        if (lookup_descriptors.isEmpty ())
          {
            throw new IOException ("There must be at least one descriptor defined");
          }
        for (LookupDescriptor im_des : lookup_descriptors)
          {
            wr.addChildElement (ISSUER_LOGOTYPE_ELEM);
            wr.setStringAttribute (MIME_TYPE_ATTR, im_des.mime_type);
            wr.setStringAttribute (LOGOTYPE_URL_ATTR, im_des.logotype_url);
            wr.setIntAttribute (WIDTH_ATTR, im_des.width);
            wr.setIntAttribute (HEIGHT_ATTR, im_des.height);
            wr.setBinaryAttribute (IMAGE_FINGERPRINT_ATTR, im_des.image_fingerprint);
            wr.getParent ();
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
