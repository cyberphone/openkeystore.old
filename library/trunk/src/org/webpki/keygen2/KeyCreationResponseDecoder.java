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

import java.util.LinkedHashMap;

import java.security.PublicKey;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONSignatureDecoder;

import static org.webpki.keygen2.KeyGen2Constants.*;

public class KeyCreationResponseDecoder extends KeyGen2Validator
  {
    LinkedHashMap<String,GeneratedPublicKey> generated_keys = new LinkedHashMap<String,GeneratedPublicKey> ();

    String client_session_id;

    String server_session_id;

    class GeneratedPublicKey
      {
        private GeneratedPublicKey () {}

        String id;

        PublicKey public_key;

        byte[] attestation;
      }

    @Override
    protected void unmarshallJSONData (JSONObjectReader rd) throws IOException
      {
        //////////////////////////////////////////////////////////////////////////
        // Get the top-level properties
        //////////////////////////////////////////////////////////////////////////
        server_session_id = getID (rd, SERVER_SESSION_ID_JSON);

        client_session_id = getID (rd, CLIENT_SESSION_ID_JSON);

        //////////////////////////////////////////////////////////////////////////
        // Get the generated keys [1..n]
        //////////////////////////////////////////////////////////////////////////
        for (JSONObjectReader key_rd : getObjectArray (rd, GENERATED_KEYS_JSON))
          {
            GeneratedPublicKey gk = new GeneratedPublicKey ();
            gk.id = key_rd.getString (ID_JSON);
            gk.attestation = key_rd.getBinary (KEY_ATTESTATION_JSON);
            gk.public_key = JSONSignatureDecoder.readPublicKey (key_rd);
            if (generated_keys.put (gk.id, gk) != null)
              {
                ServerState.bad ("Duplicate key id:" + gk.id);
              }
          }
      }

    @Override
    public String getQualifier ()
      {
        return KEY_CREATION_RESPONSE_JSON;
      }
  }
