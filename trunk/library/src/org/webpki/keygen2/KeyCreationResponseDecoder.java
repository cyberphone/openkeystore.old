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
package org.webpki.keygen2;

import java.io.IOException;

import java.util.LinkedHashMap;

import java.security.GeneralSecurityException;
import java.security.PublicKey;

import org.webpki.util.ArrayUtil;

import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMAttributeReaderHelper;
import org.webpki.xml.ServerCookie;

import org.webpki.xmldsig.XMLSignatureWrapper;

import static org.webpki.keygen2.KeyGen2Constants.*;

public class KeyCreationResponseDecoder extends KeyCreationResponse
  {
    private LinkedHashMap<String,GeneratedPublicKey> generated_keys = new LinkedHashMap<String,GeneratedPublicKey> ();

    class GeneratedPublicKey
      {
        private GeneratedPublicKey () {}

        String id;

        PublicKey public_key;

        byte[] attestation;
        
        byte[] backup_private_key;

      }


    public ServerCookie getServerCookie ()
      {
        return server_cookie;
      }
    
    
    public void validateAndPopulate (KeyCreationRequestEncoder key_init_request, ServerCryptoInterface server_crypto_interface) throws IOException
      {
        key_init_request.server_credential_store.checkSession (client_session_id, server_session_id);
        if (generated_keys.size () != key_init_request.server_credential_store.requested_keys.size ())
          {
            ServerCredentialStore.bad ("Different number of requested and received keys");
          }
        try
          {
            for (GeneratedPublicKey gpk : generated_keys.values ())
              {
                ServerCredentialStore.KeyProperties kp = key_init_request.server_credential_store.requested_keys.get (gpk.id);
                if (kp == null)
                  {
                    ServerCredentialStore.bad ("Missing key id:" + gpk.id);
                  }
                kp.public_key = gpk.public_key;
                kp.backup_private_key = gpk.backup_private_key;
                MacGenerator attestation = new MacGenerator ();
                // Write key attestation data
                attestation.addString (gpk.id);
                attestation.addArray (gpk.public_key.getEncoded ());
                attestation.addArray (kp.private_key_backup ? kp.backup_private_key : new byte[0]);
                if (!ArrayUtil.compare (key_init_request.server_credential_store.attest (attestation.getResult (),
                                                                                          kp.expected_attest_mac_count,
                                                                                          server_crypto_interface),
                                         kp.attestation = gpk.attestation))
                  {
                    ServerCredentialStore.bad ("Attestation failed for key id:" + gpk.id);
                  }
              }
          }
        catch (GeneralSecurityException e)
          {
            throw new IOException (e);
          }
      }


    /////////////////////////////////////////////////////////////////////////////////////////////
    // XML Reader
    /////////////////////////////////////////////////////////////////////////////////////////////

    protected void fromXML (DOMReaderHelper rd) throws IOException
      {
        DOMAttributeReaderHelper ah = rd.getAttributeHelper ();
        //////////////////////////////////////////////////////////////////////////
        // Get the top-level attributes
        //////////////////////////////////////////////////////////////////////////
        client_session_id = ah.getString (ID_ATTR);

        server_session_id = ah.getString (SERVER_SESSION_ID_ATTR);

        rd.getChild ();

        //////////////////////////////////////////////////////////////////////////
        // Get the child elements
        //////////////////////////////////////////////////////////////////////////
        do
          {
            GeneratedPublicKey gk = new GeneratedPublicKey ();
            rd.getNext (PUBLIC_KEY_ELEM);
            gk.id = ah.getString (ID_ATTR);
            gk.attestation = ah.getBinaryConditional (ATTESTATION_ATTR);
            rd.getChild ();
            gk.public_key = XMLSignatureWrapper.readPublicKey (rd);
            if (rd.hasNext ())
              {
                gk.backup_private_key = rd.getBinary (PRIVATE_KEY_ELEM);
              }
            rd.getParent ();
            if (generated_keys.put (gk.id, gk) != null)
              {
                ServerCredentialStore.bad ("Duplicate key id:" + gk.id);
              }
          }
        while (rd.hasNext (PUBLIC_KEY_ELEM));

        if (rd.hasNext ())  // If not ServerCookie XML validation has gone wrong
          {
            server_cookie = ServerCookie.read (rd);
          }
     }

  }
