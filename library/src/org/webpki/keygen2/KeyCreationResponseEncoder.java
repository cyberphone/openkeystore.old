/*
 *  Copyright 2006-2016 WebPKI.org (http://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
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

import static org.webpki.keygen2.KeyGen2Constants.*;

public class KeyCreationResponseEncoder extends JSONEncoder {

    private static final long serialVersionUID = 1L;

    String client_session_id;

    String server_session_id;

    Vector<GeneratedPublicKey> generated_keys = new Vector<GeneratedPublicKey>();

    private class GeneratedPublicKey {
        String id;

        PublicKey public_key;

        byte[] attestation;

        GeneratedPublicKey(String id) {
            this.id = id;
            generated_keys.add(this);
        }

    }


    public void addPublicKey(PublicKey public_key, byte[] attestation, String id) throws IOException {
        GeneratedPublicKey gk = new GeneratedPublicKey(id);
        gk.public_key = public_key;
        gk.attestation = attestation;
    }


    public KeyCreationResponseEncoder(KeyCreationRequestDecoder key_init_req) throws IOException {
        client_session_id = key_init_req.getClientSessionId();
        server_session_id = key_init_req.getServerSessionId();
    }


    @Override
    protected void writeJSONData(JSONObjectWriter wr) throws IOException {
        //////////////////////////////////////////////////////////////////////////
        // Session properties
        //////////////////////////////////////////////////////////////////////////
        wr.setString(SERVER_SESSION_ID_JSON, server_session_id);

        wr.setString(CLIENT_SESSION_ID_JSON, client_session_id);

        //////////////////////////////////////////////////////////////////////////
        // The generated keys
        //////////////////////////////////////////////////////////////////////////
        JSONArrayWriter keys = wr.setArray(GENERATED_KEYS_JSON);
        for (GeneratedPublicKey gk : generated_keys) {
            keys.setObject()
                .setString(ID_JSON, gk.id)
                .setPublicKey(gk.public_key)
                .setBinary(ATTESTATION_JSON, gk.attestation);
        }
    }

    @Override
    public String getQualifier() {
        return KeyGen2Messages.KEY_CREATION_RESPONSE.getName();
    }

    @Override
    public String getContext() {
        return KEYGEN2_NS;
    }
}
