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

import java.security.interfaces.RSAPublicKey;

import java.util.Date;
import java.util.Vector;

import javax.security.auth.x500.X500Principal;

import org.webpki.crypto.AsymKeySignerInterface;
import org.webpki.crypto.CertificateFilter;
import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.AsymSignatureAlgorithms;

import org.webpki.json.JSONArrayWriter;
import org.webpki.json.JSONAsymKeySigner;
import org.webpki.json.JSONObjectWriter;

import org.webpki.keygen2.ServerState.ProtocolPhase;

import static org.webpki.keygen2.KeyGen2Constants.*;

public class CredentialDiscoveryRequestEncoder extends ServerEncoder
  {
    private static final long serialVersionUID = 1L;

    ServerCryptoInterface server_crypto_interface;

    String submit_url;
    
    String server_session_id;
    
    String client_session_id;

    public class LookupDescriptor implements AsymKeySignerInterface
      {
        PublicKey key_management_key;

        String id;
        
        boolean search_filter;

        String issuer_reg_ex;
        String subject_reg_ex;
        BigInteger serial_number;
        String email_reg_ex;
        String policy_rules;
        Date issued_before;
        Date issued_after;
        
        LookupDescriptor (PublicKey key_management_key)
          {
            this.key_management_key = key_management_key;
            this.id = lookup_prefix + ++next_lookup_id_suffix;
          }
        
        private void nullCheck (Object object) throws IOException
          {
            if (object == null)
              {
                bad ("Null search parameter not allowed");
              }
          }

        public LookupDescriptor setSubjectRegEx (String subject_reg_ex) throws IOException
          {
            nullCheck (subject_reg_ex);
            search_filter = true;
            this.subject_reg_ex = subject_reg_ex;
            return this;
          }

        public LookupDescriptor setSubject (X500Principal subject) throws IOException
          {
            nullCheck (subject);
            return setSubjectRegEx (new CertificateFilter ().setSubject (subject).getSubjectRegEx ());
          }

        public LookupDescriptor setIssuerRegEx (String issuer_reg_ex) throws IOException
          {
            nullCheck (issuer_reg_ex);
            search_filter = true;
            this.issuer_reg_ex = issuer_reg_ex;
            return this;
          }

        public LookupDescriptor setIssuer (X500Principal issuer) throws IOException
          {
            nullCheck (issuer);
            return setIssuerRegEx (new CertificateFilter ().setIssuer (issuer).getIssuerRegEx ());
          }

        public LookupDescriptor setSerialNumber (BigInteger serial_number) throws IOException
          {
            nullCheck (serial_number);
            search_filter = true;
            this.serial_number = serial_number;
            return this;
          }

        public LookupDescriptor setEmailRegEx (String email_reg_ex) throws IOException
          {
            nullCheck (email_reg_ex);
            search_filter = true;
            this.email_reg_ex = email_reg_ex;
            return this;
          }

        public LookupDescriptor setEmail (String email) throws IOException
          {
            nullCheck (email);
            return setEmailRegEx (new CertificateFilter ().setEmail (email).getEmailRegEx ());
          }

        public LookupDescriptor setPolicyRules (String policy_rules) throws IOException
          {
            nullCheck (policy_rules);
            search_filter = true;
            this.policy_rules = new CertificateFilter ().setPolicyRules (policy_rules).getPolicyRules ();
            return this;
          }

        public LookupDescriptor setIssuedBefore (Date issued_before) throws IOException
          {
            nullCheck (issued_before);
            search_filter = true;
            this.issued_before = issued_before;
            return this;
          }

        public LookupDescriptor setIssuedAfter (Date issued_after) throws IOException
          {
            nullCheck (issued_after);
            search_filter = true;
            this.issued_after = issued_after;
            return this;
          }

        void write (JSONObjectWriter wr) throws IOException
          {
            wr.setString (ID_JSON, id);
            
            wr.setBinary (NONCE_JSON, nonce);
            
            if (search_filter)
              {
                JSONObjectWriter search_writer = wr.setObject (SEARCH_FILTER_JSON);
                if (subject_reg_ex != null)
                  {
                    search_writer.setString (CertificateFilter.CF_SUBJECT_REG_EX, subject_reg_ex);
                  }
                if (issuer_reg_ex != null)
                  {
                    search_writer.setString (CertificateFilter.CF_ISSUER_REG_EX, issuer_reg_ex);
                  }
                if (serial_number != null)
                  {
                    search_writer.setBigInteger (CertificateFilter.CF_SERIAL_NUMBER, serial_number);
                  }
                if (email_reg_ex != null)
                  {
                    search_writer.setString (CertificateFilter.CF_EMAIL_REG_EX, email_reg_ex);
                  }
                if (policy_rules != null)
                  {
                    search_writer.setString (CertificateFilter.CF_POLICY_RULES, policy_rules);
                  }
                if (issued_before != null)
                  {
                    search_writer.setDateTime (ISSUED_BEFORE_JSON, issued_before);
                  }
                if (issued_after != null)
                  {
                    search_writer.setDateTime (ISSUED_AFTER_JSON, issued_after);
                  }
              }
            JSONAsymKeySigner signer = new JSONAsymKeySigner (this);
            signer.setSignatureAlgorithm (key_management_key instanceof RSAPublicKey ?
                                                  AsymSignatureAlgorithms.RSA_SHA256 : AsymSignatureAlgorithms.ECDSA_SHA256);
            wr.setSignature (signer);
          }

        @Override
        public PublicKey getPublicKey () throws IOException
          {
            return key_management_key;
          }

        @Override
        public byte[] signData (byte[] data, AsymSignatureAlgorithms algorithm) throws IOException
          {
            return server_crypto_interface.generateKeyManagementAuthorization (key_management_key, data);
          }
      }


    Vector<LookupDescriptor> lookup_descriptors = new Vector<LookupDescriptor> ();

    String lookup_prefix = "Lookup.";
    
    byte[] nonce;
    
    int next_lookup_id_suffix = 0;
    
    // Constructors

    public CredentialDiscoveryRequestEncoder (ServerState server_state, String submit_url) throws IOException
      {
        server_state.checkState (true, ProtocolPhase.CREDENTIAL_DISCOVERY);
        client_session_id = server_state.client_session_id;
        server_session_id = server_state.server_session_id;
        server_crypto_interface = server_state.server_crypto_interface;
        this.submit_url = submit_url;
      }


    public LookupDescriptor addLookupDescriptor (PublicKey key_management_key)
      {
        LookupDescriptor lo_des = new LookupDescriptor (key_management_key);
        lookup_descriptors.add (lo_des);
        return lo_des;
      }


    @Override
    void writeServerRequest (JSONObjectWriter wr) throws IOException
      {
        //////////////////////////////////////////////////////////////////////////
        // Set top-level properties
        //////////////////////////////////////////////////////////////////////////
        wr.setString (SERVER_SESSION_ID_JSON, server_session_id);

        wr.setString (CLIENT_SESSION_ID_JSON, client_session_id);

        wr.setString (SUBMIT_URL_JSON, submit_url);

        ////////////////////////////////////////////////////////////////////////
        // Lookup descriptors
        ////////////////////////////////////////////////////////////////////////
        if (lookup_descriptors.isEmpty ())
          {
            bad ("There must be at least one descriptor defined");
          }
        MacGenerator concat = new MacGenerator ();
        concat.addString (client_session_id);
        concat.addString (server_session_id);
        nonce = HashAlgorithms.SHA256.digest (concat.getResult ());
        JSONArrayWriter array = wr.setArray (LOOKUP_SPECIFIERS_JSON);
        for (LookupDescriptor im_des : lookup_descriptors)
          {
            im_des.write (array.setObject ());
          }
      }

    @Override
    public String getQualifier ()
      {
        return CREDENTIAL_DISCOVERY_REQUEST_JSON;
      }
  }
