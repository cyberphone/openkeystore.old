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

import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;

import java.security.GeneralSecurityException;

import java.security.cert.X509Certificate;

import java.security.interfaces.ECPublicKey;

import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.SymKeySignerInterface;

import org.webpki.json.JSONArrayWriter;
import org.webpki.json.JSONEncoder;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONSymKeySigner;

import static org.webpki.keygen2.KeyGen2Constants.*;


public class ProvisioningInitializationResponseEncoder extends JSONEncoder
  {
    String server_session_id;
    
    String client_session_id;

    String server_time_verbatim;
    
    Date client_time;
    
    ECPublicKey client_ephemeral_key;
    
    HashMap<String,HashSet<String>> client_attribute_values = new HashMap<String,HashSet<String>> ();

    byte[] attestation;
    
    X509Certificate[] device_certificate_path;  // Is null for the privacy_enabled mode
    
    byte[] server_certificate_fingerprint;  // Optional
    
    JSONSymKeySigner session_signature;


    void addClientAttributeValueClient (String type, String value)
      {
        HashSet<String> set = client_attribute_values.get (type);
        if (set == null)
          {
            client_attribute_values.put (type, set = new HashSet<String> ());
          }
        set.add (value);
      }
    
    // Constructors

    public ProvisioningInitializationResponseEncoder (ProvisioningInitializationRequestDecoder prov_init_req,
                                                      ECPublicKey client_ephemeral_key,
                                                      String client_session_id,
                                                      Date client_time,
                                                      byte[] attestation,
                                                      X509Certificate[] device_certificate_path)  throws IOException
      {
        this.server_session_id = prov_init_req.server_session_id;
        this.server_time_verbatim = prov_init_req.server_time_verbatim;
        this.client_ephemeral_key = client_ephemeral_key;
        this.client_session_id = client_session_id;
        this.client_time = client_time;
        this.attestation = attestation;
        this.device_certificate_path = device_certificate_path;
      }


    public void setServerCertificate (X509Certificate server_certificate) throws IOException
      {
        try
          {
            server_certificate_fingerprint = HashAlgorithms.SHA256.digest (server_certificate.getEncoded ());
          }
        catch (GeneralSecurityException gse)
          {
            throw new IOException (gse);
          }
      }


    public ProvisioningInitializationResponseEncoder setClientAttributeValue (String type, String value)
      {
        addClientAttributeValueClient (type, value);
        return this;
      }


    public void setResponseSigner (SymKeySignerInterface signer) throws IOException
      {
        session_signature = new JSONSymKeySigner (signer);
        session_signature.setKeyID ("derived-session-key");
      }


    @Override
    protected void writeJSONData (JSONObjectWriter wr) throws IOException
      {
        //////////////////////////////////////////////////////////////////////////
        // Set top-level properties
        //////////////////////////////////////////////////////////////////////////
        wr.setString (SERVER_SESSION_ID_JSON, server_session_id);

        wr.setString (CLIENT_SESSION_ID_JSON, client_session_id);

        wr.setBinary (SESSION_ATTESTATION_JSON, attestation);
        
        wr.setString (SERVER_TIME_JSON, server_time_verbatim);

        wr.setDateTime (CLIENT_TIME_JSON, client_time);
        
        if (server_certificate_fingerprint != null)
          {
            wr.setBinary (SERVER_CERT_FP_JSON, server_certificate_fingerprint);
          }

        ////////////////////////////////////////////////////////////////////////
        // Server ephemeral key
        ////////////////////////////////////////////////////////////////////////
        wr.setObject (CLIENT_EPHEMERAL_KEY_JSON).setPublicKey (client_ephemeral_key);

        ////////////////////////////////////////////////////////////////////////
        // Device certificate path
        ////////////////////////////////////////////////////////////////////////
        if (device_certificate_path != null)
          {
            wr.setObject (DEVICE_CERTIFICATE_JSON).setX509CertificatePath (device_certificate_path);
          }

        ////////////////////////////////////////////////////////////////////////
        // Optional ClientAttributes
        ////////////////////////////////////////////////////////////////////////
        if (!client_attribute_values.isEmpty ())
          {
            JSONArrayWriter types = wr.setArray (CLIENT_ATTRIBUTES_JSON);
            for (String type : client_attribute_values.keySet ())
              {
                JSONObjectWriter entry = types.setObject ();
                entry.setString (TYPE_JSON, type);
                JSONArrayWriter values = entry.setArray (VALUES_JSON);
                for (String value : client_attribute_values.get (type))
                  {
                    values.setString (value);
                  }
              }
          }

        ////////////////////////////////////////////////////////////////////////
        // Mandatory session signature
        ////////////////////////////////////////////////////////////////////////
        wr.setSignature (session_signature);
      }

    @Override
    public String getQualifier ()
      {
        return PROVISIONING_INITIALIZATION_RESPONSE_JSON;
      }

    @Override
    public String getContext ()
      {
        return KEYGEN2_NS;
      }
  }
