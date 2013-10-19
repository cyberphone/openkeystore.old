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

import java.math.BigInteger;

import java.security.PublicKey;

import java.util.GregorianCalendar;
import java.util.LinkedHashMap;

import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.CertificateFilter;
import org.webpki.crypto.HashAlgorithms;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONSignatureDecoder;

import org.webpki.util.ArrayUtil;

import static org.webpki.keygen2.KeyGen2Constants.*;

public class CredentialDiscoveryRequestDecoder extends ClientDecoder
  {
    private static final long serialVersionUID = 1L;

    public class LookupSpecifier
      {
        String id;
        
        String issuer_reg_ex;
        String subject_reg_ex;
        BigInteger serial_number;
        String email_reg_ex;
        String policy_rules;
        GregorianCalendar issued_before;
        GregorianCalendar issued_after;

        PublicKey key_management_key;

        LookupSpecifier (JSONObjectReader rd) throws IOException
          {
            id = KeyGen2Validator.getID (rd, ID_JSON);
            if (!ArrayUtil.compare (nonce_reference, rd.getBinary (NONCE_JSON)))
              {
                throw new IOException ("\"" + NONCE_JSON + "\"  error");
              }
            if (rd.hasProperty (SEARCH_FILTER_JSON))
              {
                JSONObjectReader search = rd.getObject (SEARCH_FILTER_JSON);
                if (search.getProperties ().length == 0)
                  {
                    throw new IOException ("Empty \"" + SEARCH_FILTER_JSON + "\" not allowed");
                  }
                issuer_reg_ex = search.getStringConditional (CertificateFilter.CF_ISSUER_REG_EX);
                subject_reg_ex = search.getStringConditional (CertificateFilter.CF_SUBJECT_REG_EX);
                serial_number = KeyGen2Validator.getBigIntegerConditional (search, CertificateFilter.CF_SERIAL_NUMBER);
                email_reg_ex = search.getStringConditional (CertificateFilter.CF_EMAIL_REG_EX);
                policy_rules = search.getStringConditional (CertificateFilter.CF_POLICY_RULES);
                issued_before = KeyGen2Validator.getDateTimeConditional (search, ISSUED_BEFORE_JSON);
                issued_after = KeyGen2Validator.getDateTimeConditional (search, ISSUED_AFTER_JSON);
              }
            JSONSignatureDecoder signature = rd.getSignature ();
            key_management_key = signature.getPublicKey ();
            if (((AsymSignatureAlgorithms) signature.getSignatureAlgorithm ()).getDigestAlgorithm () != HashAlgorithms.SHA256)
              {
                throw new IOException ("Lookup signature must use SHA256");
              }
          }


        public String getID ()
          {
            return id;
          }
        
        public PublicKey getKeyManagementKey ()
          {
            return key_management_key;
          }
        
        public String getSubjectRegEx ()
          {
            return subject_reg_ex;
          }

        public String getIssuerRegEx ()
          {
            return issuer_reg_ex;
          }
        
        public BigInteger getSerialNumber ()
          {
            return serial_number;
          }
        
        public String getEmailRegEx ()
          {
            return email_reg_ex;
          }
        
        public String getPolicyRules ()
          {
            return policy_rules;
          }
        
        public GregorianCalendar getIssuedBefore ()
          {
            return issued_before;
          }

        public GregorianCalendar getIssuedAfter ()
          {
            return issued_after;
          }
      }

    LinkedHashMap<String,LookupSpecifier> lookup_specifiers = new LinkedHashMap<String,LookupSpecifier> ();
    
    String client_session_id;

    String server_session_id;

    String submit_url;

    byte[] nonce_reference;

    public String getServerSessionID ()
      {
        return server_session_id;
      }


    public String getClientSessionID ()
      {
        return client_session_id;
      }


    public String getSubmitURL ()
      {
        return submit_url;
      }


    public LookupSpecifier[] getLookupSpecifiers ()
      {
        return lookup_specifiers.values ().toArray (new LookupSpecifier[0]);
      }
    
    
    @Override
    void readServerRequest (JSONObjectReader rd) throws IOException
      {
        /////////////////////////////////////////////////////////////////////////////////////////
        // Read the top level properties
        /////////////////////////////////////////////////////////////////////////////////////////
        server_session_id = getID (rd, SERVER_SESSION_ID_JSON);

        client_session_id = getID (rd, CLIENT_SESSION_ID_JSON);

        submit_url = getURL (rd, SUBMIT_URL_JSON);
        
        /////////////////////////////////////////////////////////////////////////////////////////
        // Calculate proper nonce
        /////////////////////////////////////////////////////////////////////////////////////////
        MacGenerator mac = new MacGenerator ();
        mac.addString (client_session_id);
        mac.addString (server_session_id);
        nonce_reference = HashAlgorithms.SHA256.digest (mac.getResult ());

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the lookup specifiers [1..n]
        /////////////////////////////////////////////////////////////////////////////////////////
        for (JSONObjectReader spec : getObjectArray (rd, LOOKUP_SPECIFIERS_JSON))
          {
            LookupSpecifier ls = new LookupSpecifier (spec);
            if (lookup_specifiers.put (ls.id, ls) != null)
              {
                throw new IOException ("Duplicate id: " + ls.id);
              }
          }
      }

    @Override
    public String getQualifier ()
      {
        return CREDENTIAL_DISCOVERY_REQUEST_JSON;
      }
  }
