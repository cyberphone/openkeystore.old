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
package org.webpki.webauth;

import java.io.IOException;

import java.util.Date;
import java.util.LinkedHashSet;
import java.util.Vector;

import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.CertificateFilter;

import org.webpki.json.JSONArrayWriter;
import org.webpki.json.JSONObjectWriter;

import org.webpki.util.ArrayUtil;
import org.webpki.util.Base64URL;
import org.webpki.util.ISODateTime;

import static org.webpki.webauth.WebAuthConstants.*;

public class AuthenticationRequestEncoder extends ServerEncoder
  {
    String id;

    String submit_url;

    String abort_url;                                                          // Optional

    String[] languages;                                                        // Optional
    
    boolean full_path;                                                         // Optional
    
    boolean extended_cert_path_set;                                            // Optional
    boolean extended_cert_path;

    int expires;
    
    LinkedHashSet<String> algorithms = new LinkedHashSet<String> ();

    Vector<CertificateFilter> certificate_filters = new Vector<CertificateFilter> ();

    Vector<String> requested_client_platform_features = new Vector<String> ();
    
    Date server_time;

    public AuthenticationRequestEncoder (String submit_url, String abort_url)
      {
        this.submit_url = submit_url;
        this.abort_url = abort_url;
      }


    public AuthenticationRequestEncoder (String submit_url)
      {
        this (submit_url, null);
      }


    public AuthenticationRequestEncoder addSignatureAlgorithm (AsymSignatureAlgorithms algorithm)
      {
        algorithms.add (algorithm.getURI());
        return this;
      }


    public AuthenticationRequestEncoder addCertificateFilter (CertificateFilter cf)
      {
        certificate_filters.add (cf);
        return this;
      }

    
    public AuthenticationRequestEncoder setExtendedCertPath (boolean extended_cert_path)
      {
        this.extended_cert_path = extended_cert_path;
        extended_cert_path_set = true;
        return this;
      }


    public AuthenticationRequestEncoder setID (String id)
      {
        this.id = id;
        return this;
      }


    public AuthenticationRequestEncoder setServerTime (Date server_time)
      {
        this.server_time = server_time;
        return this;
      }


    public AuthenticationRequestEncoder setLanguages (String[] languages)
      {
        this.languages = languages;
        return this;
      }


    public AuthenticationRequestEncoder requestClientPlatformFeature (String feature_uri)
      {
        requested_client_platform_features.add (feature_uri);
        return this;
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
        if (!ISODateTime.formatDateTime (server_time).equals (ISODateTime.formatDateTime (areresp.server_time.getTime ())))
          {
            bad ("ServerTime attribute");
          }
        if (certificate_filters.size () > 0 && areresp.certificate_path != null)
          {
            for (CertificateFilter cf : certificate_filters)
              {
                if (cf.matches (areresp.certificate_path, null, null))
                  {
                    return;
                  }
              }
            bad ("Certificates does not match filter(s)");
          }
      }

    @Override
    void writeServerRequest(JSONObjectWriter wr) throws IOException
      {
        //////////////////////////////////////////////////////////////////////////
        // Set top-level attributes
        //////////////////////////////////////////////////////////////////////////
        if (id == null)
          {
            id = Long.toHexString (new Date().getTime());
            id += Base64URL.generateURLFriendlyRandom (MAX_ID_LENGTH - id.length ());
          }
        wr.setString (ID_ATTR, id);

        if (server_time == null)
          {
            server_time = new Date ();
          }
        wr.setDateTime (SERVER_TIME_ATTR, server_time);

        wr.setString (SUBMIT_URL_ATTR, submit_url);

        if (abort_url != null)
          {
            wr.setString (ABORT_URL_ATTR, abort_url);
          }

        if (languages != null)
          {
            wr.setStringArray (LANGUAGES_ATTR, languages);
          }

        if (expires > 0)
          {
            wr.setInt (EXPIRES_ATTR, expires);
          }

        if (extended_cert_path_set)
          {
            wr.setBoolean (EXTENDED_CERT_PATH_ATTR, extended_cert_path);
          }
        
        if (algorithms.isEmpty ())
          {
            bad ("Missing \"" + SIGNATURE_ALGORITHMS_ATTR + "\"");
          }
        wr.setStringArray (SIGNATURE_ALGORITHMS_ATTR, algorithms.toArray (new String[0]));

        //////////////////////////////////////////////////////////////////////////
        // Optional "client platform features"
        //////////////////////////////////////////////////////////////////////////
        if (!requested_client_platform_features.isEmpty ())
          {
            wr.setStringArray (REQUESTED_CLIENT_FEATURES_ATTR, requested_client_platform_features.toArray (new String[0]));
          }

        //////////////////////////////////////////////////////////////////////////
        // Certificate filters (optional)
        //////////////////////////////////////////////////////////////////////////
        if (!certificate_filters.isEmpty ())
          {
            JSONArrayWriter cf_arr = wr.setArray (CERTIFICATE_FILTER_ELEM);
            for (CertificateFilter cf : certificate_filters)
              {
                CertificateFilterWriter.write (cf_arr.setObject (), cf);
              }
          }
      }

    @Override
    public String getQualifier ()
      {
        return AUTHENTICATION_REQUEST_ATTR;
      }
  }
