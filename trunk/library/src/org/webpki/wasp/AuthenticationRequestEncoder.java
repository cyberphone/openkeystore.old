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
package org.webpki.wasp;

import java.io.IOException;

import java.util.Vector;
import java.util.Date;

import java.security.SecureRandom;

import org.w3c.dom.Document;

import org.webpki.xml.DOMWriterHelper;

import org.webpki.xmldsig.XMLSigner;
import org.webpki.xmldsig.CanonicalizationAlgorithms;

import org.webpki.crypto.SignerInterface;
import org.webpki.crypto.CertificateFilter;
import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.wasp.SignatureRequestEncoder;

import static org.webpki.wasp.WASPConstants.*;


public class AuthenticationRequestEncoder extends AuthenticationRequest
  {
    Date server_time;

    Vector<AuthenticationProfile> auth_profiles = new Vector<AuthenticationProfile> ();

    Vector<CertificateFilter> cert_filters = new Vector<CertificateFilter> ();

    ClientPlatformRequest client_platform_request;

     private String prefix;  // Default: no prefix


    public class AuthenticationProfile
      {
        boolean signed_key_info;

        boolean extended_cert_path;

        CanonicalizationAlgorithms canonicalization_algorithm = CanonicalizationAlgorithms.C14N_EXCL;

        HashAlgorithms digest_algorithm = HashAlgorithms.SHA256;

        SignatureAlgorithms signature_algorithm = SignatureAlgorithms.RSA_SHA256;


        AuthenticationProfile ()
          {
          }


        public void setSignedKeyInfo (boolean flag)
          {
            this.signed_key_info = flag;
          }


        public void setExtendedCertPath (boolean flag)
          {
            this.extended_cert_path = flag;
          }


        public void setCanonicalizationAlgorithm (CanonicalizationAlgorithms canonicalization_algorithm)
          {
            this.canonicalization_algorithm = canonicalization_algorithm;
          }


        public void setDigestAlgorithm (HashAlgorithms digest_algorithm)
          {
            this.digest_algorithm = digest_algorithm;
          }


        public void setSignatureAlgorithm (SignatureAlgorithms signature_algorithm)
          {
            this.signature_algorithm = signature_algorithm;
          }


        void write (DOMWriterHelper wr) throws IOException
          {
            wr.addEmptyElement (AUTHENTICATION_PROFILE_ELEM);
            if (signed_key_info)
              {
                wr.setBooleanAttribute (SIGNED_KEY_INFO_ATTR, true);
              }
            if (extended_cert_path)
              {
                wr.setBooleanAttribute (EXTENDED_CERT_PATH_ATTR, true);
              }
            if (canonicalization_algorithm != CanonicalizationAlgorithms.C14N_EXCL)
              {
                wr.setStringAttribute (CN_ALG_ATTR, canonicalization_algorithm.getURI ());
              }
            if (digest_algorithm != HashAlgorithms.SHA256)
              {
                wr.setStringAttribute (DIGEST_ALG_ATTR, digest_algorithm.getURI ());
              }
            if (signature_algorithm != SignatureAlgorithms.RSA_SHA256)
              {
                wr.setStringAttribute (SIGNATURE_ALG_ATTR, signature_algorithm.getURI ());
              }
          }
      }


    // Constructors

    @SuppressWarnings("unused")
    private AuthenticationRequestEncoder () {}


    public AuthenticationRequestEncoder (String submit_url, String cancel_url)
      {
        this.submit_url = submit_url;
        this.cancel_url = cancel_url;
      }


    public AuthenticationRequestEncoder (String submit_url)
      {
        this (submit_url, null);
      }


    public AuthenticationProfile addAuthenticationProfile ()
      {
        AuthenticationProfile ap = new AuthenticationProfile ();
        auth_profiles.add (ap);
        return ap;
      }


    public CertificateFilter addCertificateFilter (CertificateFilter cf)
      {
        cert_filters.add (cf);
        return cf;
      }


    public void setID (String id)
      {
        this.id = id;
      }


    public void setServerTime (Date server_time)
      {
        this.server_time = server_time;
      }


    public void setLanguages (String[] languages)
      {
        this.languages = languages;
      }


    public void setPrefix (String prefix)
      {
        this.prefix = prefix;
      }


    public ClientPlatformRequest createClientPlatformRequest ()
      {
        return client_platform_request = new ClientPlatformRequest ();
      }


    protected void toXML (DOMWriterHelper wr) throws IOException
      {
        wr.initializeRootObject (prefix);

        //////////////////////////////////////////////////////////////////////////
        // Set top-level attributes
        //////////////////////////////////////////////////////////////////////////
        if (id == null)
          {
            id = "_auth." + Long.toHexString (new Date().getTime()) + Long.toHexString(new SecureRandom ().nextLong());
          }
        wr.setStringAttribute (ID_ATTR, id);

        if (server_time == null)
          {
            server_time = new Date ();
          }
        wr.setDateTimeAttribute (SERVER_TIME_ATTR, server_time);

        wr.setStringAttribute (SUBMIT_URL_ATTR, submit_url);

        if (cancel_url != null)
          {
            wr.setStringAttribute (CANCEL_URL_ATTR, cancel_url);
          }

        if (languages != null)
          {
            wr.setListAttribute (LANGUAGES_ATTR, languages);
          }

        if (expires > 0)
          {
            wr.setIntAttribute (EXPIRES_ATTR, expires);
          }

        //////////////////////////////////////////////////////////////////////////
        // Authentication profiles
        //////////////////////////////////////////////////////////////////////////
        if (auth_profiles.isEmpty ())
          {
            addAuthenticationProfile ();
          }
        for (AuthenticationProfile ap : auth_profiles)
          {
            ap.write (wr);
          }

        //////////////////////////////////////////////////////////////////////////
        // Certificate filters (optional)
        //////////////////////////////////////////////////////////////////////////
        for (CertificateFilter cf : cert_filters)
          {
            SignatureRequestEncoder.writeCertificateFilter (wr, cf);
          }

        //////////////////////////////////////////////////////////////////////////
        // Optional "client platform request"
        //////////////////////////////////////////////////////////////////////////
        if (client_platform_request != null)
          {
            client_platform_request.write (wr);
          }
      }


    public void signRequest (SignerInterface signer) throws IOException
      {
        XMLSigner ds = new XMLSigner (signer);
        Document doc = getRootDocument ();
        ds.createEnvelopedSignature (doc, id);
      }

  }
