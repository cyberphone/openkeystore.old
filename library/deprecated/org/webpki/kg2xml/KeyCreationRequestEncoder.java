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
package org.webpki.kg2xml;

import java.io.IOException;

import java.security.GeneralSecurityException;

import java.util.Vector;

import org.w3c.dom.Document;

import org.webpki.sks.SecureKeyStore;

import org.webpki.xml.DOMWriterHelper;

import org.webpki.xmldsig.XMLSigner;
import org.webpki.xmldsig.XMLSignatureWrapper;

import org.webpki.crypto.SignerInterface;

import org.webpki.kg2xml.ServerState.ProtocolPhase;

import static org.webpki.kg2xml.KeyGen2Constants.*;


public class KeyCreationRequestEncoder extends KeyCreationRequest
  {
    String submit_url;

    boolean deferred_certification;

    String prefix;  // Default: no prefix

    ServerState server_state;
    
    private boolean need_signature_ns;
    
    Vector<String> written_pin = new Vector<String> ();

    Vector<String> written_puk = new Vector<String> ();

    private String key_entry_algorithm = SecureKeyStore.ALGORITHM_KEY_ATTEST_1;


    // Constructors

    public KeyCreationRequestEncoder (ServerState server_state, String submit_url) throws IOException
      {
        this.server_state = server_state;
        this.submit_url = submit_url;
        server_state.checkState (true, server_state.current_phase == ProtocolPhase.CREDENTIAL_DISCOVERY ? ProtocolPhase.CREDENTIAL_DISCOVERY : ProtocolPhase.KEY_CREATION);
        server_state.current_phase = ProtocolPhase.KEY_CREATION;
      }


    private static void bad (String error_msg) throws IOException
      {
        throw new IOException (error_msg);
      }


    public void setDeferredCertification (boolean flag)
      {
        deferred_certification = flag;
      }


    public void setKeyAttestationAlgorithm (String key_attestation_algorithm_uri)
      {
        this.key_entry_algorithm = key_attestation_algorithm_uri;
      }


    public void setPrefix (String prefix)
      {
        this.prefix = prefix;
      }


    public void signRequest (SignerInterface signer) throws IOException
      {
        XMLSigner ds = new XMLSigner (signer);
        ds.removeXMLSignatureNS ();
        need_signature_ns = true;
        Document doc = getRootDocument ();
        ds.createEnvelopedSignature (doc, server_state.server_session_id);
      }
    
    
    private ServerState.PUKPolicy getPUKPolicy (ServerState.Key kp)
      {
        return kp.pin_policy == null ? null : kp.pin_policy.puk_policy;
      }


    protected void toXML (DOMWriterHelper wr) throws IOException
      {
        wr.initializeRootObject (prefix);

        if (need_signature_ns)
          {
            XMLSignatureWrapper.addXMLSignatureNS (wr);
          }

        //////////////////////////////////////////////////////////////////////////
        // Set top-level attributes
        //////////////////////////////////////////////////////////////////////////
        wr.setStringAttribute (ID_ATTR, server_state.server_session_id);

        wr.setStringAttribute (CLIENT_SESSION_ID_ATTR, server_state.client_session_id);

        wr.setStringAttribute (SUBMIT_URL_ATTR, submit_url);

        wr.setStringAttribute (KEY_ENTRY_ALGORITHM_ATTR, key_entry_algorithm);

        if (deferred_certification)
          {
            wr.setBooleanAttribute (DEFERRED_CERTIFICATION_ATTR, deferred_certification);
          }

        ////////////////////////////////////////////////////////////////////////
        // There MUST not be zero keys to initialize...
        ////////////////////////////////////////////////////////////////////////
        if (server_state.requested_keys.isEmpty ())
          {
            bad ("Empty request not allowd!");
          }
        server_state.key_attestation_algorithm = key_entry_algorithm;
        ServerState.Key last_req_key = null;
        try
          {
            for (ServerState.Key req_key : server_state.requested_keys.values ())
              {
                if (last_req_key != null && getPUKPolicy (last_req_key) != null &&
                    getPUKPolicy (last_req_key) != getPUKPolicy (req_key))
                  {
                    wr.getParent ();
                  }
                if (last_req_key != null && last_req_key.pin_policy != null &&
                    last_req_key.pin_policy != req_key.pin_policy)
                  {
                    wr.getParent ();
                  }
                if (getPUKPolicy (req_key) != null)
                  {
                    if (written_puk.contains (getPUKPolicy (req_key).id))
                      {
                        if (getPUKPolicy (last_req_key) != getPUKPolicy (req_key))
                          {
                            bad ("PUK grouping error");
                          }
                      }
                    else
                      {
                        getPUKPolicy (req_key).writePolicy (wr);
                        written_puk.add (getPUKPolicy (req_key).id);
                      }
                  }
                if (req_key.pin_policy != null)
                  {
                    if (written_pin.contains (req_key.pin_policy.id))
                      {
                        if (last_req_key.pin_policy != req_key.pin_policy)
                          {
                            bad ("PIN grouping error");
                          }
                      }
                    else
                      {
                        req_key.pin_policy.writePolicy (wr);
                        written_pin.add (req_key.pin_policy.id);
                      }
                  }
                req_key.writeRequest (wr);
                last_req_key = req_key;
              }
          }
        catch (GeneralSecurityException e)
          {
            throw new IOException (e);
          }
        if (last_req_key != null && last_req_key.pin_policy != null)
          {
            wr.getParent ();
          }
        if (last_req_key != null && getPUKPolicy (last_req_key) != null)
          {
            wr.getParent ();
          }
      }
  }
