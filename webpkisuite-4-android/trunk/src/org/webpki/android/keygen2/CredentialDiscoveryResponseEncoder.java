/*
 *  Copyright 2006-2014 WebPKI.org (http://webpki.org).
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
package org.webpki.android.keygen2;

import java.io.IOException;

import java.util.LinkedHashMap;
import java.util.Vector;

import java.security.cert.X509Certificate;

import org.webpki.android.json.JSONArrayWriter;
import org.webpki.android.json.JSONEncoder;
import org.webpki.android.json.JSONObjectWriter;

import static org.webpki.android.keygen2.KeyGen2Constants.*;

public class CredentialDiscoveryResponseEncoder extends JSONEncoder
  {
    private static final long serialVersionUID = 1L;

    class MatchingCredential
      {
        X509Certificate[] certificate_path;

        String client_session_id;

        String server_session_id;
        
        boolean locked;
      }
    
    public class LookupResult
      {
        String id;
        
        Vector<MatchingCredential> matching_credentials = new Vector<MatchingCredential> ();

        LookupResult (String id)
          {
            this.id = id;
          }
        
        public void addMatchingCredential (X509Certificate[] certificate_path, String client_session_id, String server_session_id, boolean locked) throws IOException
          {
            MatchingCredential mc = new MatchingCredential ();
            mc.certificate_path = certificate_path;
            mc.client_session_id = client_session_id;
            mc.server_session_id = server_session_id;
            mc.locked = locked;
            matching_credentials.add (mc);
          }
      }

 
    Vector<LookupResult> lookup_results = new Vector<LookupResult> ();
    
    LinkedHashMap<String,CredentialDiscoveryRequestDecoder.LookupSpecifier> ref;

    String client_session_id;

    String server_session_id;


    // Constructors

    public CredentialDiscoveryResponseEncoder (CredentialDiscoveryRequestDecoder cred_disc_dec)
      {
        server_session_id = cred_disc_dec.server_session_id;
        client_session_id = cred_disc_dec.client_session_id;
        this.ref = cred_disc_dec.lookup_specifiers;
      }


    public LookupResult addLookupResult (String id) throws IOException
      {
        LookupResult lo_res = new LookupResult (id);
        if (!ref.containsKey (id))
          {
            throw new IOException ("Non-matching \"ID\": " + id);
          }
        lookup_results.add (lo_res);
        return lo_res;
      }


    @Override
    protected void writeJSONData (JSONObjectWriter wr) throws IOException
      {
        //////////////////////////////////////////////////////////////////////////
        // Set top-level properties
        //////////////////////////////////////////////////////////////////////////
        wr.setString (SERVER_SESSION_ID_JSON, server_session_id);

        wr.setString (CLIENT_SESSION_ID_JSON, client_session_id);

        ////////////////////////////////////////////////////////////////////////
        // Lookup results
        ////////////////////////////////////////////////////////////////////////
        if (lookup_results.isEmpty ())
          {
            throw new IOException ("There must be at least one result defined");
          }
        if (lookup_results.size () != ref.size ())
          {
            throw new IOException ("Missing outputed results");
          }
        JSONArrayWriter lookups = wr.setArray (LOOKUP_RESULTS_JSON);
        for (LookupResult lo_res : lookup_results)
          {
            JSONObjectWriter lookup_writer = lookups.setObject (); 
            lookup_writer.setString (ID_JSON, lo_res.id);
            JSONArrayWriter matcher_array = lookup_writer.setArray (MATCHING_CREDENTIALS_JSON);
            for (MatchingCredential mc : lo_res.matching_credentials)
              {
                JSONObjectWriter match_object = matcher_array.setObject ();
                match_object.setString (SERVER_SESSION_ID_JSON, mc.server_session_id);
                match_object.setString (CLIENT_SESSION_ID_JSON, mc.client_session_id);
                match_object.setX509CertificatePath (mc.certificate_path);
                if (mc.locked)
                  {
                    match_object.setBoolean (LOCKED_JSON, mc.locked);
                  }
              }
          }
      }

    @Override
    public String getQualifier ()
      {
        return CREDENTIAL_DISCOVERY_RESPONSE_JSON;
      }

    @Override
    public String getContext ()
      {
        return KEYGEN2_NS;
      }
  }
