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
package org.webpki.kg2xml;

import java.io.IOException;

import java.math.BigInteger;

import java.security.PublicKey;

import java.security.interfaces.ECPublicKey;

import java.util.Date;
import java.util.Vector;

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
        BigInteger serial;
        String email_address;
        String policy;
        String[] excluded_policies;
        Date issued_before;
        Date issued_after;
        
        Document root;
        

        LookupDescriptor (PublicKey key_management_key)
          {
            this.key_management_key = key_management_key;
            this.id = lookup_prefix + ++next_lookup_id_suffix;
          }
        
        public LookupDescriptor setSubjectRegEx (String subject_reg_ex)
          {
            search_filter = true;
            this.subject_reg_ex = subject_reg_ex;
            return this;
          }

        public LookupDescriptor setIssuerRegEx (String issuer_reg_ex)
          {
            search_filter = true;
            this.issuer_reg_ex = issuer_reg_ex;
            return this;
          }

        public LookupDescriptor setSerial (BigInteger serial)
          {
            search_filter = true;
            this.serial = serial;
            return this;
          }

        public LookupDescriptor setEmailAddress (String email_address)
          {
            search_filter = true;
            this.email_address = email_address;
            return this;
          }

        public LookupDescriptor setPolicy (String policy)
          {
            search_filter = true;
            this.policy = policy;
            return this;
          }

        public LookupDescriptor setExcludedPolicies (String[] excluded_policies)
          {
            search_filter = true;
            this.excluded_policies = excluded_policies;
            return this;
          }

        public LookupDescriptor setIssuedBefore (Date issued_before)
          {
            search_filter = true;
            this.issued_before = issued_before;
            return this;
          }

        public LookupDescriptor setIssuedAfter (Date issued_after)
          {
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
                    wr.setStringAttribute (SUBJECT_ATTR, subject_reg_ex);
                  }
                if (issuer_reg_ex != null)
                  {
                    wr.setStringAttribute (ISSUER_ATTR, issuer_reg_ex);
                  }
                if (serial != null)
                  {
                    wr.setBigIntegerAttribute (SERIAL_ATTR, serial);
                  }
                if (email_address != null)
                  {
                    wr.setStringAttribute (EMAIL_ATTR, email_address);
                  }
                if (policy != null)
                  {
                    wr.setStringAttribute (POLICY_ATTR, policy);
                  }
                if (excluded_policies != null)
                  {
                    wr.setListAttribute (EXCLUDED_POLICIES_ATTR, excluded_policies);
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
