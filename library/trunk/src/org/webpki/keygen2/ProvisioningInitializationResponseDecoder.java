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
import java.util.LinkedHashSet;
import java.util.LinkedHashMap;

import java.security.cert.X509Certificate;

import java.security.interfaces.ECPublicKey;

import org.webpki.json.JSONArrayReader;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONSignatureDecoder;

import static org.webpki.keygen2.KeyGen2Constants.*;


public class ProvisioningInitializationResponseDecoder extends KeyGen2Validator
  {
    private static final long serialVersionUID = 1L;

    String server_session_id;
    
    String client_session_id;

    Date server_time;
    
    Date client_time;
    
    ECPublicKey client_ephemeral_key;
    
    LinkedHashMap<String,LinkedHashSet<String>> client_attribute_values = new LinkedHashMap<String,LinkedHashSet<String>> ();

    byte[] attestation;
    
    X509Certificate[] device_certificate_path;  // Is null for the privacy_enabled mode
    
    byte[] server_certificate_fingerprint;  // Optional

    JSONSignatureDecoder signature;


    public String getServerSessionID ()
      {
        return server_session_id;
      }

    
    public String getClientSessionID ()
      {
        return client_session_id;
      }


    public Date getServerTime ()
      {
        return server_time;
      }

    
    public Date getClientTime ()
      {
        return client_time;
      }

    
    public ECPublicKey getClientEphemeralKey ()
      {
        return client_ephemeral_key;
      }


    public byte[] getAttestation ()
      {
        return attestation;
      }


    public X509Certificate[] getDeviceCertificatePath ()
      {
        return device_certificate_path;
      }
    

    public byte[] getServerCertificateFingerprint ()
      {
        return server_certificate_fingerprint;
      }


    public LinkedHashMap<String,LinkedHashSet<String>> getClientAttributeValues ()
      {
        return client_attribute_values;
      }


    @Override
    protected void deserializeJSONData (JSONObjectReader rd) throws IOException
      {
        /////////////////////////////////////////////////////////////////////////////////////////
        // Read the top level properties
        /////////////////////////////////////////////////////////////////////////////////////////
        attestation = rd.getBinary (SESSION_ATTESTATION_JSON);
        
        server_session_id = getID (rd, SERVER_SESSION_ID_JSON);

        client_session_id = getID (rd, CLIENT_SESSION_ID_JSON);

        server_time = rd.getDateTime (SERVER_TIME_JSON).getTime ();

        client_time = rd.getDateTime (CLIENT_TIME_JSON).getTime ();

        server_certificate_fingerprint = rd.getBinaryConditional (SERVER_CERT_FP_JSON);
        
        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the ephemeral client key
        /////////////////////////////////////////////////////////////////////////////////////////
        client_ephemeral_key = (ECPublicKey) rd.getObject (CLIENT_EPHEMERAL_KEY_JSON).getPublicKey ();

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the optional device certificate path
        /////////////////////////////////////////////////////////////////////////////////////////
        if (rd.hasProperty (DEVICE_CERTIFICATE_JSON))
          {
            device_certificate_path = rd.getObject (DEVICE_CERTIFICATE_JSON).getX509CertificatePath ();
          }

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the optional client attributes
        /////////////////////////////////////////////////////////////////////////////////////////
        for (JSONObjectReader type_rd : getObjectArrayConditional (rd, CLIENT_ATTRIBUTES_JSON))
          {
            String type = type_rd.getString (TYPE_JSON);
            LinkedHashSet<String> set = new LinkedHashSet<String> ();
            JSONArrayReader values = type_rd.getArray (VALUES_JSON);
            while (values.hasMore ())
              {
                if (!set.add (values.getString ()))
                  {
                    throw new IOException ("Duplicate value for: " + type);
                  }
              }
            if (client_attribute_values.put (type, set) != null)
              {
                throw new IOException ("Duplicate: " + type);
              }
          }

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the mandatory provisioning session data signature
        /////////////////////////////////////////////////////////////////////////////////////////
        signature = rd.getSignature ();
      }

    @Override
    public String getQualifier ()
      {
        return PROVISIONING_INITIALIZATION_RESPONSE_JSON;
      }
  }
