/*
 *  Copyright 2006-2011 WebPKI.org (http://webpki.org).
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
import java.util.Vector;

import org.webpki.xml.DOMWriterHelper;
import org.webpki.xml.ServerCookie;

import static org.webpki.keygen2.KeyGen2Constants.*;

public class CredentialDiscoveryResponseEncoder extends CredentialDiscoveryResponse
  {

    class MatchingCredential
      {
        byte[] certficate_fingerprint;

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
        
        public void addMatchingCredential (byte[] certificate_fingerprint, String client_session_id, String server_session_id, boolean locked)
          {
            MatchingCredential mc = new MatchingCredential ();
            mc.certficate_fingerprint = certificate_fingerprint;
            mc.client_session_id = client_session_id;
            mc.server_session_id = server_session_id;
            mc.locked = locked;
            matching_credentials.add (mc);
          }
      }

 
    private String prefix;  // Default: no prefix
    
    Vector<LookupResult> lookup_results = new Vector<LookupResult> ();
    
    LinkedHashMap<String,CredentialDiscoveryRequestDecoder.LookupSpecifier> ref;


    // Constructors

    public CredentialDiscoveryResponseEncoder (CredentialDiscoveryRequestDecoder cred_disc_dec)
      {
        super.server_session_id = cred_disc_dec.server_session_id;
        super.client_session_id = cred_disc_dec.client_session_id;
        this.ref = cred_disc_dec.lookup_specifiers;
      }


    public ServerCookie setServerCookie (ServerCookie server_cookie)
      {
        return super.server_cookie = server_cookie;
      }


    public void setPrefix (String prefix)
      {
        this.prefix = prefix;
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


    protected void toXML (DOMWriterHelper wr) throws IOException
      {
        wr.initializeRootObject (prefix);

        //////////////////////////////////////////////////////////////////////////
        // Set top-level attributes
        //////////////////////////////////////////////////////////////////////////
        wr.setStringAttribute (ID_ATTR, client_session_id);

        wr.setStringAttribute (SERVER_SESSION_ID_ATTR, server_session_id);

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
        for (LookupResult lo_res : lookup_results)
          {
            wr.addChildElement (LOOKUP_RESULT_ELEM);
            wr.setStringAttribute (ID_ATTR, lo_res.id);
            for (MatchingCredential mc : lo_res.matching_credentials)
              {
                wr.addChildElement (MATCHING_CREDENTIAL_ELEM);
                wr.setStringAttribute (CLIENT_SESSION_ID_ATTR, mc.client_session_id);
                wr.setStringAttribute (SERVER_SESSION_ID_ATTR, mc.server_session_id);
                wr.setBinaryAttribute (CERTIFICATE_FINGERPRINT_ATTR, mc.certficate_fingerprint);
                if (mc.locked)
                  {
                    wr.setBooleanAttribute (LOCKED_ATTR, mc.locked);
                  }
                wr.getParent ();
              }
            wr.getParent ();
          }

        ////////////////////////////////////////////////////////////////////////
        // Optional ServerCookie
        ////////////////////////////////////////////////////////////////////////
        if (server_cookie != null)
          {
            server_cookie.write (wr);
          }
      }
  }
