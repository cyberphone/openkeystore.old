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

import java.math.BigInteger;

import java.security.PublicKey;

import java.security.interfaces.ECPublicKey;

import java.util.Date;
import java.util.Vector;

import javax.security.auth.x500.X500Principal;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMWriterHelper;
import org.webpki.xml.XMLObjectWrapper;

import org.webpki.xmldsig.XMLAsymKeySigner;
import org.webpki.xmldsig.XMLEnvelopedInput;
import org.webpki.xmldsig.XMLSignatureWrapper;
import org.webpki.xmldsig.XMLSigner;

import org.webpki.crypto.AsymKeySignerInterface;
import org.webpki.crypto.CertificateFilter;
import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.SignerInterface;

import org.webpki.kg2xml.ServerState.ProtocolPhase;

import static org.webpki.kg2xml.KeyGen2Constants.*;

public class CredentialDiscoveryRequestEncoder extends CredentialDiscoveryRequest
  {
    ServerCryptoInterface server_crypto_interface;

    public class LookupDescriptor extends XMLObjectWrapper implements XMLEnvelopedInput, AsymKeySignerInterface
      {
        PublicKey key_management_key;

        String id;
        
        boolean search_filter;

        String issuer_reg_ex;
        String subject_reg_ex;
        BigInteger serial_number;
        String email_reg_ex;
        String[] policy_rules;
        Date issued_before;
        Date issued_after;
        
        Document root;
        

        LookupDescriptor (PublicKey key_management_key)
          {
            this.key_management_key = key_management_key;
            this.id = lookup_prefix + ++next_lookup_id_suffix;
          }
        
        private void nullCheck (Object object) throws IOException
          {
            if (object == null)
              {
                throw new IOException ("Null search parameter not allowed");
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
  
        public LookupDescriptor setPolicyRules (String[] policy_rules) throws IOException
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


        @Override
        public String element ()
          {
            return LOOKUP_SPECIFIER_ELEM;
          }

        @Override
        protected void fromXML (DOMReaderHelper rd) throws IOException
          {
            throw new IOException ("Should not be called");
          }

        @Override
        protected boolean hasQualifiedElements ()
          {
            return true;
          }

        @Override
        protected void init () throws IOException
          {
          }

        @Override
        public String namespace ()
          {
            return KEYGEN2_NS;
          }

        @Override
        protected void toXML (DOMWriterHelper wr) throws IOException
          {
            wr.initializeRootObject (prefix);

            wr.setBinaryAttribute (NONCE_ATTR, nonce);
            
            wr.setStringAttribute (ID_ATTR, id);
            if (search_filter)
              {
                wr.addChildElement (SEARCH_FILTER_ELEM);
                if (subject_reg_ex != null)
                  {
                    wr.setStringAttribute (CertificateFilter.CF_SUBJECT_REG_EX, subject_reg_ex);
                  }
                if (issuer_reg_ex != null)
                  {
                    wr.setStringAttribute (CertificateFilter.CF_ISSUER_REG_EX, issuer_reg_ex);
                  }
                if (serial_number != null)
                  {
                    wr.setBigIntegerAttribute (CertificateFilter.CF_SERIAL_NUMBER, serial_number);
                  }
                if (email_reg_ex != null)
                  {
                    wr.setStringAttribute (CertificateFilter.CF_EMAIL_REG_EX, email_reg_ex);
                  }
                if (policy_rules != null)
                  {
                    wr.setListAttribute (CertificateFilter.CF_POLICY_RULES, policy_rules);
                  }
                if (issued_before != null)
                  {
                    wr.setDateTimeAttribute (ISSUED_BEFORE_ATTR, issued_before);
                  }
                if (issued_after != null)
                  {
                    wr.setDateTimeAttribute (ISSUED_AFTER_ATTR, issued_after);
                  }
                wr.getParent ();
              }
          }

        @Override
        public Document getEnvelopeRoot () throws IOException
          {
            return root = getRootDocument ();
          }

        @Override
        public Element getInsertElem () throws IOException
          {
            return null;
          }

        @Override
        public String getReferenceURI () throws IOException
          {
            return id;
          }

        @Override
        public XMLSignatureWrapper getSignature () throws IOException
          {
            throw new IOException ("Should not be called");
          }

        @Override
        public Element getTargetElem () throws IOException
          {
            return null;
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

 
    private String prefix;  // Default: no prefix
    
    Vector<LookupDescriptor> lookup_descriptors = new Vector<LookupDescriptor> ();

    String lookup_prefix = "Lookup.";
    
    byte[] nonce;
    
    int next_lookup_id_suffix = 0;
    
    boolean ecc_keys;

    // Constructors

    public CredentialDiscoveryRequestEncoder (ServerState server_state, String submit_url) throws IOException
      {
        server_state.checkState (true, ProtocolPhase.CREDENTIAL_DISCOVERY);
        client_session_id = server_state.client_session_id;
        server_session_id = server_state.server_session_id;
        server_crypto_interface = server_state.server_crypto_interface;
        super.submit_url = submit_url;
      }


    public void setPrefix (String prefix)
      {
        this.prefix = prefix;
      }


    public void signRequest (SignerInterface signer) throws IOException
      {
        XMLSigner ds = new XMLSigner (signer);
        ds.removeXMLSignatureNS ();
        Document doc = getRootDocument ();
        ds.createEnvelopedSignature (doc, server_session_id);
      }

    
    public LookupDescriptor addLookupDescriptor (PublicKey key_management_key)
      {
        LookupDescriptor lo_des = new LookupDescriptor (key_management_key);
        lookup_descriptors.add (lo_des);
        if (key_management_key instanceof ECPublicKey)
          {
            ecc_keys = true;
          }
        return lo_des;
      }


    protected void toXML (DOMWriterHelper wr) throws IOException
      {
        wr.initializeRootObject (prefix);

        //////////////////////////////////////////////////////////////////////////
        // Set top-level attributes
        //////////////////////////////////////////////////////////////////////////
        wr.setStringAttribute (ID_ATTR, server_session_id);

        wr.setStringAttribute (CLIENT_SESSION_ID_ATTR, client_session_id);

        wr.setStringAttribute (SUBMIT_URL_ATTR, submit_url);
        
        XMLSignatureWrapper.addXMLSignatureNS (wr);
        
        if (ecc_keys)
          {
            XMLSignatureWrapper.addXMLSignature11NS (wr);
          }

        ////////////////////////////////////////////////////////////////////////
        // Lookup descriptors
        ////////////////////////////////////////////////////////////////////////
        if (lookup_descriptors.isEmpty ())
          {
            throw new IOException ("There must be at least one descriptor defined");
          }
        MacGenerator concat = new MacGenerator ();
        concat.addString (client_session_id);
        concat.addString (server_session_id);
        nonce = HashAlgorithms.SHA256.digest (concat.getResult ());
        for (LookupDescriptor im_des : lookup_descriptors)
          {
            XMLAsymKeySigner ds = new XMLAsymKeySigner (im_des);
            ds.setSignatureAlgorithm (im_des.key_management_key instanceof ECPublicKey ? AsymSignatureAlgorithms.ECDSA_SHA256 : AsymSignatureAlgorithms.RSA_SHA256);
            ds.removeXMLSignatureNS ();
            ds.createEnvelopedSignature (im_des);
            im_des.root.getDocumentElement ().removeAttributeNS ("http://www.w3.org/2000/xmlns/", prefix == null ? "xmlns" : prefix);
            wr.addWrapped (im_des);
          }
      }
  }
