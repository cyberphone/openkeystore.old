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

import java.util.Iterator;

import org.webpki.sks.SecureKeyStore;

import org.webpki.json.JSONArrayWriter;
import org.webpki.json.JSONObjectWriter;

import org.webpki.keygen2.ServerState.PINPolicy;
import org.webpki.keygen2.ServerState.ProtocolPhase;

import static org.webpki.keygen2.KeyGen2Constants.*;


public class KeyCreationRequestEncoder extends ServerEncoder
  {
    private static final long serialVersionUID = 1L;

    String submit_url;

    boolean deferred_certification;

    ServerState server_state;
    
    private String algorithm = SecureKeyStore.ALGORITHM_KEY_ATTEST_1;


    // Constructors

    public KeyCreationRequestEncoder (ServerState server_state, String submit_url) throws IOException
      {
        this.server_state = server_state;
        this.submit_url = submit_url;
        server_state.checkState (true, server_state.current_phase == ProtocolPhase.CREDENTIAL_DISCOVERY ? ProtocolPhase.CREDENTIAL_DISCOVERY : ProtocolPhase.KEY_CREATION);
        server_state.current_phase = ProtocolPhase.KEY_CREATION;
      }


    public void setDeferredCertification (boolean flag)
      {
        deferred_certification = flag;
      }


    public void setKeyAttestationAlgorithm (String key_attestation_algorithm_uri)
      {
        this.algorithm = key_attestation_algorithm_uri;
      }


    void writeKeys (JSONObjectWriter wr, PINPolicy pin_policy) throws IOException
      {
        JSONArrayWriter keys = null;
        for (ServerState.Key req_key : server_state.requested_keys.values ())
          {
            if (req_key.pin_policy == pin_policy)
              {
                if (keys == null)
                  {
                    keys = wr.setArray (KEY_ENTRY_SPECIFIERS_JSON);
                  }
                req_key.writeRequest (keys.setObject ());
              }
          }
      }

    @Override
    void writeServerRequest (JSONObjectWriter wr) throws IOException
      {
        //////////////////////////////////////////////////////////////////////////
        // Set top-level properties
        //////////////////////////////////////////////////////////////////////////
        wr.setString (KEY_ENTRY_ALGORITHM_JSON, algorithm);

        wr.setString (SERVER_SESSION_ID_JSON, server_state.server_session_id);

        wr.setString (CLIENT_SESSION_ID_JSON, server_state.client_session_id);

        wr.setString (SUBMIT_URL_JSON, submit_url);

        if (deferred_certification)
          {
            wr.setBoolean (DEFERRED_CERTIFICATION_JSON, deferred_certification);
          }

        server_state.key_attestation_algorithm = algorithm;

        ////////////////////////////////////////////////////////////////////////
        // There MUST not be zero keys to initialize...
        ////////////////////////////////////////////////////////////////////////
        if (server_state.requested_keys.isEmpty ())
          {
            bad ("Empty request not allowd!");
          }
        if (!server_state.puk_policies.isEmpty ())
          {
            JSONArrayWriter puk = wr.setArray (PUK_POLICY_SPECIFIERS_JSON);
            for (ServerState.PUKPolicy puk_policy : server_state.puk_policies)
              {
                JSONObjectWriter puk_wr = puk.setObject ();
                puk_policy.writePolicy (puk_wr);
                JSONArrayWriter pin = puk_wr.setArray (PIN_POLICY_SPECIFIERS_JSON);
                Iterator<ServerState.PINPolicy> pin_policies = server_state.pin_policies.iterator ();
                while (pin_policies.hasNext ())
                  {
                    ServerState.PINPolicy pin_policy = pin_policies.next ();
                    JSONObjectWriter pin_wr = pin.setObject ();
                    pin_policy.writePolicy (pin_wr);
                    pin_policies.remove ();
                    writeKeys (pin_wr, pin_policy);
                  }
              }
          }
        if (!server_state.pin_policies.isEmpty ())
          {
            JSONArrayWriter pin = wr.setArray (PIN_POLICY_SPECIFIERS_JSON);
            for (ServerState.PINPolicy pin_policy : server_state.pin_policies)
              {
                JSONObjectWriter pin_wr = pin.setObject ();
                pin_policy.writePolicy (pin_wr);
                writeKeys (pin_wr, pin_policy);
              }
          }
        writeKeys (wr, null);
      }

    @Override
    public String getQualifier ()
      {
        return KEY_CREATION_REQUEST_JSON;
      }
  }
