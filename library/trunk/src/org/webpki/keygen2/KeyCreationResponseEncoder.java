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

import java.util.Vector;

import java.security.PublicKey;

import org.webpki.json.JSONArrayWriter;
import org.webpki.json.JSONEncoder;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONSignatureEncoder;

import static org.webpki.keygen2.KeyGen2Constants.*;

public class KeyCreationResponseEncoder extends JSONEncoder
  {
    String client_session_id;

    String server_session_id;

    Vector<GeneratedPublicKey> generated_keys = new Vector<GeneratedPublicKey> ();

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
        gk.key_attestation = key_attestation;
      }



    public KeyCreationResponseEncoder (KeyCreationRequestDecoder key_init_req) throws IOException
      {
        client_session_id = key_init_req.getClientSessionID ();
        server_session_id = key_init_req.getServerSessionID ();
      }


    @Override
    protected void writeJSONData (JSONObjectWriter wr) throws IOException
      {
        wr.setString (SERVER_SESSION_ID_JSON, server_session_id);
        
        wr.setString (CLIENT_SESSION_ID_JSON, client_session_id);

        JSONArrayWriter keys = wr.setArray (GENERATED_KEYS_JSON);
        for (GeneratedPublicKey gk : generated_keys)
          {
            JSONObjectWriter key_wr = keys.setObject ();
            key_wr.setString (ID_JSON, gk.id);
            JSONSignatureEncoder.writePublicKey (key_wr, gk.public_key);
            key_wr.setBinary (ATTESTATION_JSON, gk.key_attestation);
          }
      }

    @Override
    protected String getQualifier ()
      {
        return KEY_CREATION_RESPONSE_JSON;
      }

    @Override
    protected String getContext ()
      {
        return KEYGEN2_NS;
      }
  }
