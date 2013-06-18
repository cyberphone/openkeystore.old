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

import java.util.Date;

import org.w3c.dom.Document;

import org.webpki.xml.DOMWriterHelper;

import org.webpki.xmldsig.XMLSigner;

import org.webpki.crypto.SignerInterface;
import org.webpki.crypto.CertificateFilter;
import org.webpki.crypto.URLFriendlyRandom;

import org.webpki.util.ArrayUtil;
import org.webpki.wasp.SignatureRequestEncoder;

import static org.webpki.wasp.WASPConstants.*;


public class AuthenticationRequestEncoder extends AuthenticationRequest
  {
    Date server_time;

    private String prefix;  // Default: no prefix


    public AuthenticationRequestEncoder (String submit_url, String abort_url)
      {
        this.submit_url = submit_url;
        this.abort_url = abort_url;
      }


    public AuthenticationRequestEncoder (String submit_url)
      {
        this (submit_url, null);
      }


    public AuthenticationProfile addAuthenticationProfile ()
      {
        AuthenticationProfile ap = new AuthenticationProfile ();
        authentication_profiles.add (ap);
        return ap;
      }


    public AuthenticationRequestEncoder addCertificateFilter (CertificateFilter cf)
      {
        certificate_filters.add (cf);
        return this;
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


    public AuthenticationRequestEncoder requestClientPlatformFeature (String feature_uri)
      {
        requested_client_platform_features.add (feature_uri);
        return this;
      }


    protected void toXML (DOMWriterHelper wr) throws IOException
      {
        wr.initializeRootObject (prefix);

        //////////////////////////////////////////////////////////////////////////
        // Set top-level attributes
        //////////////////////////////////////////////////////////////////////////
        if (id == null)
          {
            id = "_auth." + Long.toHexString (new Date ().getTime ()) + URLFriendlyRandom.generate (20);
          }
        wr.setStringAttribute (ID_ATTR, id);

        if (server_time == null)
          {
            server_time = new Date ();
          }
        wr.setDateTimeAttribute (SERVER_TIME_ATTR, server_time);

        wr.setStringAttribute (SUBMIT_URL_ATTR, submit_url);

        if (abort_url != null)
          {
            wr.setStringAttribute (ABORT_URL_ATTR, abort_url);
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
        // Optional "client platform features"
        //////////////////////////////////////////////////////////////////////////
        if (!requested_client_platform_features.isEmpty ())
          {
            wr.setListAttribute (CLIENT_PLATFORM_FEATURES_ATTR, requested_client_platform_features.toArray (new String[0]));
          }

        //////////////////////////////////////////////////////////////////////////
        // Authentication profiles
        //////////////////////////////////////////////////////////////////////////
        if (authentication_profiles.isEmpty ())
          {
            addAuthenticationProfile ();
          }
        for (AuthenticationProfile ap : authentication_profiles)
          {
            wr.addEmptyElement (AUTHENTICATION_PROFILE_ELEM);
            if (ap.signed_key_info)
              {
                wr.setBooleanAttribute (SIGNED_KEY_INFO_ATTR, true);
              }
            if (ap.extended_cert_path)
              {
                wr.setBooleanAttribute (EXTENDED_CERT_PATH_ATTR, true);
              }
            if (ap.canonicalization_algorithm != null)
              {
                wr.setStringAttribute (CN_ALG_ATTR, ap.canonicalization_algorithm.getURI ());
              }
            if (ap.digest_algorithm != null)
              {
                wr.setStringAttribute (DIGEST_ALG_ATTR, ap.digest_algorithm.getURI ());
              }
            if (ap.signature_algorithm != null)
              {
                wr.setStringAttribute (SIGNATURE_ALG_ATTR, ap.signature_algorithm.getURI ());
              }
          }

        //////////////////////////////////////////////////////////////////////////
        // Certificate filters (optional)
        //////////////////////////////////////////////////////////////////////////
        for (CertificateFilter cf : certificate_filters)
          {
            SignatureRequestEncoder.writeCertificateFilter (wr, cf);
          }
      }


    public void signRequest (SignerInterface signer) throws IOException
      {
        XMLSigner ds = new XMLSigner (signer);
        Document doc = getRootDocument ();
        ds.createEnvelopedSignature (doc, id);
      }


    private void bad (String mismatch) throws IOException
      {
        throw new IOException ("Mismatch between request and response: " + mismatch);
      }


    public void checkRequestResponseIntegrity (AuthenticationResponseDecoder areresp, byte[] expected_fingerprint) throws IOException
      {
        if (expected_fingerprint != null &&
            (areresp.server_certificate_fingerprint == null || !ArrayUtil.compare (areresp.server_certificate_fingerprint, expected_fingerprint)))
          {
            bad ("Server certificate fingerprint");
          }
        if (!id.equals (areresp.id))
          {
            bad ("ID attributes");
          }
        if (!DOMWriterHelper.formatDateTime (server_time).equals (DOMWriterHelper.formatDateTime (areresp.server_time.getTime ())))
          {
            bad ("ServerTime attribute");
          }
        if (certificate_filters.size () > 0 && areresp.signer_certpath != null)
          {
            for (CertificateFilter cf : certificate_filters)
              {
                if (cf.matches (areresp.signer_certpath, null, null))
                  {
                    return;
                  }
              }
            bad ("Certificates does not match filter(s)");
          }
      }
  }
