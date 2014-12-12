/*
 *  Copyright 2006-2014 WebPKI.org (http://webpki.org).
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
import org.webpki.crypto.KeyContainerTypes;

import org.webpki.json.JSONArrayWriter;
import org.webpki.json.JSONObjectWriter;

import org.webpki.util.ArrayUtil;
import org.webpki.util.Base64URL;
import org.webpki.util.ISODateTime;

import static org.webpki.webauth.WebAuthConstants.*;

public class AuthenticationRequestEncoder extends ServerEncoder
  {
    private static final long serialVersionUID = 1L;

    String id;

    String submit_url;

    String abort_url;                                                          // Optional

    String[] language_list;                                                    // Optional
    
    String[] key_container_list;                                               // Optional
    
    boolean full_path;                                                         // Optional
    
    boolean extended_cert_path_set;                                            // Optional
    boolean extended_cert_path;

    int expires;
    
    LinkedHashSet<String> algorithms = new LinkedHashSet<String> ();

    Vector<CertificateFilter> certificate_filters = new Vector<CertificateFilter> ();

    Vector<String> requested_client_features = new Vector<String> ();
    
    Date server_time;

    public AuthenticationRequestEncoder (String submit_url, String optional_abort_url)
      {
        this.submit_url = submit_url;
        this.abort_url = optional_abort_url;
      }


    public AuthenticationRequestEncoder addSignatureAlgorithm (AsymSignatureAlgorithms algorithm)
      {
        algorithms.add (algorithm.getURI());
        return this;
      }


    public AuthenticationRequestEncoder addCertificateFilter (CertificateFilter certificate_filter)
      {
        certificate_filters.add (certificate_filter);
        return this;
      }

    
    public AuthenticationRequestEncoder setExtendedCertPath (boolean extended_cert_path)
      {
        this.extended_cert_path = extended_cert_path;
        extended_cert_path_set = true;
        return this;
      }

    public AuthenticationRequestEncoder setTargetKeyContainerList (KeyContainerTypes[] optional_list_of_granted_types) throws IOException
      {
        this.key_container_list = KeyContainerTypes.parseOptionalKeyContainerList (optional_list_of_granted_types);
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


    public AuthenticationRequestEncoder setPreferredLanguages (String[] language_list)
      {
        this.language_list = language_list;
        return this;
      }


    public AuthenticationRequestEncoder requestClientFeature (String feature_uri)
      {
        requested_client_features.add (feature_uri);
        return this;
      }

    public void checkRequestResponseIntegrity (AuthenticationResponseDecoder authenication_response, 
                                              byte[] expected_server_certificate_fingerprint) throws IOException
      {
        if (expected_server_certificate_fingerprint != null &&
            (authenication_response.server_certificate_fingerprint == null || 
             !ArrayUtil.compare (authenication_response.server_certificate_fingerprint,
                                 expected_server_certificate_fingerprint)))
          {
            bad ("Server certificate fingerprint");
          }
        if (!id.equals (authenication_response.id))
          {
            bad ("ID attributes");
          }
        if (!ISODateTime.formatDateTime (server_time, true).equals (ISODateTime.formatDateTime (authenication_response.server_time.getTime (), true)))
          {
            bad ("ServerTime attribute");
          }
        boolean sig_alg_found = false;
        for (String sig_alg : algorithms)
          {
            if (sig_alg.equals (authenication_response.signature_algorithm))
              {
                sig_alg_found = true;
                break;
              }
          }
        if (!sig_alg_found)
          {
            bad ("Wrong signature algorithm: " + authenication_response.signature_algorithm);
          }
        if (extended_cert_path && certificate_filters.size () > 0 && authenication_response.certificate_path != null)
          {
            for (CertificateFilter cf : certificate_filters)
              {
                if (cf.matches (authenication_response.certificate_path))
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
        wr.setString (ID_JSON, id);

        if (server_time == null)
          {
            server_time = new Date ();
          }
        wr.setDateTime (SERVER_TIME_JSON, server_time, true);  // Server UTC

        wr.setString (SUBMIT_URL_JSON, submit_url);

        if (abort_url != null)
          {
            wr.setString (ABORT_URL_JSON, abort_url);
          }

        if (language_list != null)
          {
            wr.setStringArray (PREFERRED_LANGUAGES_JSON, language_list);
          }

        if (key_container_list != null)
          {
            wr.setStringArray (KeyContainerTypes.KCT_TARGET_KEY_CONTAINERS, key_container_list);
          }

        if (expires > 0)
          {
            wr.setInt (EXPIRES_JSON, expires);
          }

        if (extended_cert_path_set)
          {
            wr.setBoolean (EXTENDED_CERT_PATH_JSON, extended_cert_path);
          }
        
        if (algorithms.isEmpty ())
          {
            bad ("Missing \"" + SIGNATURE_ALGORITHMS_JSON + "\"");
          }
        wr.setStringArray (SIGNATURE_ALGORITHMS_JSON, algorithms.toArray (new String[0]));

        //////////////////////////////////////////////////////////////////////////
        // Optional "client platform features"
        //////////////////////////////////////////////////////////////////////////
        if (!requested_client_features.isEmpty ())
          {
            wr.setStringArray (REQUESTED_CLIENT_FEATURES_JSON, requested_client_features.toArray (new String[0]));
          }

        //////////////////////////////////////////////////////////////////////////
        // Certificate filters (optional)
        //////////////////////////////////////////////////////////////////////////
        if (!certificate_filters.isEmpty ())
          {
            JSONArrayWriter cf_arr = wr.setArray (CERTIFICATE_FILTERS_JSON);
            for (CertificateFilter cf : certificate_filters)
              {
                CertificateFilterWriter.write (cf_arr.setObject (), cf);
              }
          }
      }

    @Override
    public String getQualifier ()
      {
        return AUTHENTICATION_REQUEST_MSG;
      }
  }
