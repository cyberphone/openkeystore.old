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

import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMAttributeReaderHelper;

import org.webpki.xmldsig.XMLVerifier;
import org.webpki.xmldsig.XMLSignatureWrapper;
import org.webpki.xmldsig.CanonicalizationAlgorithms;

import org.webpki.crypto.VerifierInterface;
import org.webpki.crypto.CertificateFilter;
import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;

import static org.webpki.wasp.WASPConstants.*;


public class AuthenticationRequestDecoder extends AuthenticationRequest
  {
    private String server_time;

    private Vector<AuthenticationProfile> auth_profiles = new Vector<AuthenticationProfile> ();

    private Vector<CertificateFilter> cert_filters = new Vector<CertificateFilter> ();  // Optional

    private ClientPlatformRequest client_platform_request;                              // Optional

    private XMLSignatureWrapper signature;                                              // Optional


    public class AuthenticationProfile
      {
        boolean signed_key_info;

        boolean extended_cert_path;

        String canonicalization_algorithm;

        String digest_algorithm;

        String signature_algorithm;

        AuthenticationProfile ()
          {
          }


        public boolean getSignedKeyInfo ()
          {
            return signed_key_info;
          }


        public boolean getExtendedCertPath ()
          {
            return extended_cert_path;
          }


        public CanonicalizationAlgorithms getCanonicalizationAlgorithm () throws IOException
          {
            return canonicalization_algorithm == null ? null : CanonicalizationAlgorithms.getAlgorithmFromURI (canonicalization_algorithm);
          }


        public HashAlgorithms getDigestAlgorithm () throws IOException
          {
            return digest_algorithm == null ? null : HashAlgorithms.getAlgorithmFromURI (digest_algorithm);
          }


        public SignatureAlgorithms getSignatureAlgorithm () throws IOException
          {
            return signature_algorithm == null ? null : SignatureAlgorithms.getAlgorithmFromURI (signature_algorithm);
          }

      }


    private void readAuthenticationProfile (DOMReaderHelper rd) throws IOException
      {
        rd.getNext (AUTHENTICATION_PROFILE_ELEM);
        DOMAttributeReaderHelper ah = rd.getAttributeHelper ();
        AuthenticationProfile ap = new AuthenticationProfile ();
        ap.signed_key_info = ah.getBooleanConditional (SIGNED_KEY_INFO_ATTR);

        ap.extended_cert_path = ah.getBooleanConditional (EXTENDED_CERT_PATH_ATTR);

        ap.canonicalization_algorithm = ah.getStringConditional (CN_ALG_ATTR);

        ap.digest_algorithm = ah.getStringConditional (DIGEST_ALG_ATTR);

        ap.signature_algorithm = ah.getStringConditional (SIGNATURE_ALG_ATTR);

        if ((ap.canonicalization_algorithm == null || CanonicalizationAlgorithms.testAlgorithmURI (ap.canonicalization_algorithm)) &&
            (ap.digest_algorithm == null || HashAlgorithms.testAlgorithmURI (ap.digest_algorithm)) &&
            (ap.signature_algorithm == null || SignatureAlgorithms.testAlgorithmURI (ap.signature_algorithm)))
          {
            auth_profiles.add (ap);
          }
      }



    public AuthenticationProfile[] getAuthenticationProfiles ()
      {
        return auth_profiles.toArray (new AuthenticationProfile[0]);
      }


    public CertificateFilter[] getCertificateFilters ()
      {
        return cert_filters.toArray (new CertificateFilter[0]);
      }


    public String getID ()
      {
        return id;
      }


    public String getServerTime ()
      {
        return server_time;
      }


    public String getSubmitURL ()
      {
        return submit_url;
      }


    public String getCancelURL ()
      {
        return cancel_url;
      }


    public ClientPlatformRequest getClientPlatformRequest ()
      {
        return client_platform_request;
      }


    public String[] getLanguages ()
      {
        return languages;
      }


    public int getExpires ()
      {
        return expires;
      }


    public void verifySignature (VerifierInterface verifier) throws IOException
      {
        new XMLVerifier (verifier).validateEnvelopedSignature (this, null, signature, id);
      }


    public boolean isSigned ()
      {
        return signature != null;
      }

    /////////////////////////////////////////////////////////////////////////////////////////////
    // XML Reader
    /////////////////////////////////////////////////////////////////////////////////////////////

    protected void fromXML (DOMReaderHelper rd) throws IOException
      {
        DOMAttributeReaderHelper ah = rd.getAttributeHelper ();

        /////////////////////////////////////////////////////////////////////////////////////////
        // Read the top level attributes
        /////////////////////////////////////////////////////////////////////////////////////////

        id = ah.getString (ID_ATTR);

        server_time = ah.getString (SERVER_TIME_ATTR);

        submit_url = ah.getString (SUBMIT_URL_ATTR);

        cancel_url = ah.getStringConditional (CANCEL_URL_ATTR);

        languages = ah.getListConditional (LANGUAGES_ATTR);

        expires = ah.getIntConditional (EXPIRES_ATTR, -1);  // Default: no timeout and associated GUI

        rd.getChild ();
        
        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the authentication profiles [1..n]
        /////////////////////////////////////////////////////////////////////////////////////////
        do
          {
            readAuthenticationProfile (rd);
          }
        while (rd.hasNext (AUTHENTICATION_PROFILE_ELEM));
        if (auth_profiles.isEmpty ())
          {
            throw new IOException ("No matching AuthenticationProfile found");
          }

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the certificate filters [0..n]
        /////////////////////////////////////////////////////////////////////////////////////////
        while (rd.hasNext (CERTIFICATE_FILTER_ELEM))
          {
            cert_filters.add (SignatureRequestDecoder.readCertificateFilter (rd));
          }

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the optional client platform request data [0..1]
        /////////////////////////////////////////////////////////////////////////////////////////
        if (rd.hasNext (ClientPlatformRequest.CLIENT_PLATFORM_REQUEST_ELEM))
          {
            client_platform_request = ClientPlatformRequest.read (rd);
          }

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the signature [0..1]
        /////////////////////////////////////////////////////////////////////////////////////////
        if (rd.hasNext (XMLSignatureWrapper.SIGNATURE_ELEM))
          {
            signature = (XMLSignatureWrapper)wrap (rd.getNext ());
          }
      }

  }
