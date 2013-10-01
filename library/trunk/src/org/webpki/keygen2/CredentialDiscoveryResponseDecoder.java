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

import java.security.cert.X509Certificate;

import java.util.Vector;

import org.webpki.crypto.CertificateUtil;

import org.webpki.json.JSONArrayReader;
import org.webpki.json.JSONObjectReader;

import static org.webpki.keygen2.KeyGen2Constants.*;

public class CredentialDiscoveryResponseDecoder extends KeyGen2Validator
  {
    public class MatchingCredential
      {
        MatchingCredential () {}
        
        X509Certificate end_entity_certificate;
        
        String client_session_id;
        
        String server_session_id;
        
        boolean locked;
        
        public String getClientSessionID ()
          {
            return client_session_id;
          }
        
        public String getServerSessionID ()
          {
            return server_session_id;
          }
        
        public X509Certificate getEndEntityCertificate ()
          {
            return end_entity_certificate;
          }
        
        public boolean isLocked ()
          {
            return locked;
          }
      }

    public class LookupResult
      {
        String id;

        LookupResult () { }
        
        Vector<MatchingCredential> matching_credentials = new Vector<MatchingCredential> ();

        LookupResult (JSONObjectReader rd) throws IOException
          {
            id = KeyGen2Validator.getID (rd, ID_JSON);
            JSONArrayReader matches = rd.getArray (MATCHING_CREDENTIALS_JSON);
            while (matches.hasMore ())
              {
                JSONObjectReader match_object = matches.getObject ();
                MatchingCredential matching_credential = new MatchingCredential ();
                matching_credential.client_session_id = KeyGen2Validator.getID (match_object, CLIENT_SESSION_ID_JSON);
                matching_credential.server_session_id = KeyGen2Validator.getID (match_object, SERVER_SESSION_ID_JSON);
                matching_credential.end_entity_certificate = CertificateUtil.getCertificateFromBlob (match_object.getBinary (END_ENTITY_CERTIFICATE_JSON));
                matching_credential.locked = match_object.getBooleanConditional (LOCKED_JSON);
                matching_credentials.add (matching_credential);
              }
          }


        public String getID ()
          {
            return id;
          }
        
        public MatchingCredential[] getMatchingCredentials ()
          {
            return matching_credentials.toArray (new MatchingCredential[0]);
          }
      }

    private Vector<LookupResult> lookup_results = new Vector<LookupResult> ();
    
    String client_session_id;

    String server_session_id;

    public String getServerSessionID ()
      {
        return server_session_id;
      }


    public String getClientSessionID ()
      {
        return client_session_id;
      }


    public LookupResult[] getLookupResults ()
      {
        return lookup_results.toArray (new LookupResult[0]);
      }
    
    
    @Override
    protected void unmarshallJSONData (JSONObjectReader rd) throws IOException
      {
        /////////////////////////////////////////////////////////////////////////////////////////
        // Read the top level properties
        /////////////////////////////////////////////////////////////////////////////////////////
        server_session_id = getID (rd, SERVER_SESSION_ID_JSON);

        client_session_id = getID (rd, SERVER_SESSION_ID_JSON);

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the lookup_results [1..n]
        /////////////////////////////////////////////////////////////////////////////////////////
        JSONArrayReader lookups = rd.getArray (LOOKUP_RESULTS_JSON);
        do 
          {
            LookupResult lookup_result = new LookupResult (lookups.getObject ());
            lookup_results.add (lookup_result);
          }
        while (lookups.hasMore ());
      }

    @Override
    public String getQualifier ()
      {
        return CREDENTIAL_DISCOVERY_RESPONSE_JSON;
      }
  }
