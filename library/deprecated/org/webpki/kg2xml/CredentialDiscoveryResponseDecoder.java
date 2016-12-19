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

import java.security.cert.X509Certificate;

import java.util.Vector;

import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMAttributeReaderHelper;
import org.webpki.xmldsig.XMLSignatureWrapper;

import static org.webpki.kg2xml.KeyGen2Constants.*;

public class CredentialDiscoveryResponseDecoder extends CredentialDiscoveryResponse
  {
    public class MatchingCredential
      {
        MatchingCredential () {}
        
        X509Certificate[] certificate_path;
        
        String client_session_id;
        
        String server_session_id;
        
        boolean locked;
        
        public String getClientSessionId ()
          {
            return client_session_id;
          }
        
        public String getServerSessionId ()
          {
            return server_session_id;
          }
        
        public X509Certificate[] getCertificatePath ()
          {
            return certificate_path;
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

        LookupResult (DOMReaderHelper rd) throws IOException
          {
            DOMAttributeReaderHelper ah = rd.getAttributeHelper ();
            rd.getNext (LOOKUP_RESULT_ELEM);
            id = ah.getString (ID_ATTR);
            rd.getChild ();
            while (rd.hasNext ())
              {
                rd.getNext (MATCHING_CREDENTIAL_ELEM);
                MatchingCredential mc = new MatchingCredential ();
                mc.client_session_id = ah.getString (CLIENT_SESSION_ID_ATTR);
                mc.server_session_id = ah.getString (SERVER_SESSION_ID_ATTR);
                rd.getChild ();
                mc.certificate_path = XMLSignatureWrapper.readSortedX509DataSubset (rd);
                rd.getParent ();
                mc.locked = ah.getBooleanConditional (LOCKED_ATTR);
                matching_credentials.add (mc);
              }
            rd.getParent ();
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

    public String getServerSessionId ()
      {
        return server_session_id;
      }


    public String getClientSessionId ()
      {
        return client_session_id;
      }


    public LookupResult[] getLookupResults ()
      {
        return lookup_results.toArray (new LookupResult[0]);
      }
    
    
    protected void fromXML (DOMReaderHelper rd) throws IOException
      {
        DOMAttributeReaderHelper ah = rd.getAttributeHelper ();

        /////////////////////////////////////////////////////////////////////////////////////////
        // Read the top level attributes
        /////////////////////////////////////////////////////////////////////////////////////////

        server_session_id = ah.getString (SERVER_SESSION_ID_ATTR);

        client_session_id = ah.getString (ID_ATTR);

        rd.getChild ();

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the lookup_results [1..n]
        /////////////////////////////////////////////////////////////////////////////////////////
        do 
          {
            LookupResult o = new LookupResult (rd);
            lookup_results.add (o);
          }
        while (rd.hasNext (LOOKUP_RESULT_ELEM));
      }
  }
