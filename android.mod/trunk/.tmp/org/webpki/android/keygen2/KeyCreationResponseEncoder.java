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
package org.webpki.android.keygen2;

import java.io.IOException;

import java.util.Vector;

import java.security.PublicKey;

import java.security.interfaces.ECPublicKey;

import org.webpki.android.xml.DOMWriterHelper;

import org.webpki.android.xmldsig.XMLSignatureWrapper;

import static org.webpki.android.keygen2.KeyGen2Constants.*;


public class KeyCreationResponseEncoder extends KeyCreationResponse
  {
    private Vector<GeneratedPublicKey> generated_keys = new Vector<GeneratedPublicKey> ();

    private String prefix;  // Default: no prefix

    private boolean need_ds11_namespace;


    private class GeneratedPublicKey
      {
        String id;

        PublicKey public_key;

        byte[] key_attestation;

        GeneratedPublicKey (String id)
          {
            this.id = id;
            generated_keys.add (this);
          }

      }


    public void addPublicKey (PublicKey public_key, byte[] key_attestation, String id) throws IOException
      {
        GeneratedPublicKey gk = new GeneratedPublicKey (id);
        gk.public_key = public_key;
        if (public_key instanceof ECPublicKey)
          {
            need_ds11_namespace = true;
          }
        gk.key_attestation = key_attestation;
      }


    public void setPrefix (String prefix) throws IOException
      {
        this.prefix = prefix;
      }


    public String getPrefix ()
      {
        return prefix;
      }


    public KeyCreationResponseEncoder (KeyCreationRequestDecoder key_init_req) throws IOException
      {
        client_session_id = key_init_req.getClientSessionID ();
        server_session_id = key_init_req.getServerSessionID ();
      }


    protected void toXML (DOMWriterHelper wr) throws IOException
      {
        wr.initializeRootObject (prefix);

        XMLSignatureWrapper.addXMLSignatureNS (wr);

        if (need_ds11_namespace)
          {
            XMLSignatureWrapper.addXMLSignature11NS (wr);
          }

        wr.setStringAttribute (ID_ATTR, client_session_id);

        wr.setStringAttribute (SERVER_SESSION_ID_ATTR, server_session_id);
      
        for (GeneratedPublicKey gk : generated_keys)
          {
            wr.addChildElement (PUBLIC_KEY_ELEM);
            wr.setStringAttribute (ID_ATTR, gk.id);
            wr.setBinaryAttribute (ATTESTATION_ATTR, gk.key_attestation);
            XMLSignatureWrapper.writePublicKey (wr, gk.public_key);
            wr.getParent ();
          }
      }
  }
