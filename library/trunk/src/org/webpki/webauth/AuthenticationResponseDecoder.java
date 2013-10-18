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
package org.webpki.webauth;

import java.io.IOException;

import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.HashSet;

import java.security.cert.X509Certificate;

import org.webpki.crypto.VerifierInterface;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONSignatureDecoder;
import org.webpki.json.JSONX509Verifier;

import static org.webpki.webauth.WebAuthConstants.*;


public class AuthenticationResponseDecoder extends InputValidator
  {
    private static final long serialVersionUID = 1L;

    GregorianCalendar server_time;

    private GregorianCalendar client_time;

    private JSONSignatureDecoder signature;
    
    byte[] server_certificate_fingerprint;
    
    String request_url;
    
    String id;
    
    X509Certificate[] certificate_path;
    
    String signature_algorithm;

    HashMap<String,HashSet<String>> client_platform_features = new HashMap<String,HashSet<String>> ();


    public String getRequestURL ()
      {
        return request_url;
      }
 
    
    public GregorianCalendar getClientTime ()
      {
        return client_time;
      }


    public String getID ()
      {
        return id;
      }


    public HashMap<String,HashSet<String>> getClientPlatformFeatures ()
      {
        return client_platform_features;
      }


    public void verifySignature (VerifierInterface verifier) throws IOException
      {
        signature.verify (new JSONX509Verifier (verifier));
      }

    /////////////////////////////////////////////////////////////////////////////////////////////
    // JSON Reader
    /////////////////////////////////////////////////////////////////////////////////////////////

    @Override
    protected void unmarshallJSONData (JSONObjectReader rd) throws IOException
      {
        //////////////////////////////////////////////////////////////////////////
        // Get the top-level properties
        //////////////////////////////////////////////////////////////////////////
        id = rd.getString (ID_JSON);

        server_time = rd.getDateTime (SERVER_TIME_JSON);

        request_url = rd.getString (REQUEST_URL_JSON);

        client_time = rd.getDateTime (CLIENT_TIME_JSON);

        server_certificate_fingerprint = rd.getBinaryConditional (SERVER_CERT_FP_JSON);
        
        //////////////////////////////////////////////////////////////////////////
        // Get the optional client platform features
        //////////////////////////////////////////////////////////////////////////
        for (JSONObjectReader feature : InputValidator.getObjectArrayConditional (rd, CLIENT_FEATURES_JSON))
          {
            String type = InputValidator.getURI (feature, TYPE_JSON);
            HashSet<String> set = client_platform_features.get (type);
            if (set != null)
              {
                bad ("Duplicated \"" + TYPE_JSON + "\" : " + type);
              }
            client_platform_features.put (type, set = new HashSet<String> ());
            for (String value : InputValidator.getNonEmptyList (feature, VALUES_JSON))
              {
                set.add (value);
              }
          }

        //////////////////////////////////////////////////////////////////////////
        // Finally, get the signature!
        //////////////////////////////////////////////////////////////////////////
        signature = rd.getSignature ();
        certificate_path = signature.getX509CertificatePath ();
        signature_algorithm = signature.getSignatureAlgorithm ().getURI ();
      }

    @Override
    public String getQualifier ()
      {
        return AUTHENTICATION_RESPONSE_JSON;
      }
  }
