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

import java.util.LinkedHashSet;
import java.util.Vector;

import org.webpki.crypto.CertificateFilter;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.KeyContainerTypes;

import org.webpki.json.JSONObjectReader;

import static org.webpki.webauth.WebAuthConstants.*;


public class AuthenticationRequestDecoder extends ClientDecoder
  {
    private static final long serialVersionUID = 1L;

    String server_time;

    String id;
    
    LinkedHashSet<AsymSignatureAlgorithms> algorithms = new LinkedHashSet<AsymSignatureAlgorithms> ();
    
    LinkedHashSet<String> client_features = new LinkedHashSet<String> ();
    
    Vector<CertificateFilter> certificate_filters = new Vector<CertificateFilter> ();

    String submit_url;

    String abort_url;

    String[] languages;
    
    LinkedHashSet<KeyContainerTypes> key_container_list;

    int expires;
    
    boolean extended_cert_path;
    
    public AsymSignatureAlgorithms[] getSignatureAlgorithms ()
      {
        return algorithms.toArray (new AsymSignatureAlgorithms[0]);
      }


    public CertificateFilter[] getCertificateFilters ()
      {
        return certificate_filters.toArray (new CertificateFilter[0]);
      }

    
    public LinkedHashSet<KeyContainerTypes> getOptionalKeyContainerList ()
      {
        return key_container_list;
      }


    public String getID ()
      {
        return id;
      }


    public String getServerTime ()
      {
        return server_time;
      }


    public String getSubmitUrl ()
      {
        return submit_url;
      }


    public String getOptionalAbortURL ()
      {
        return abort_url;
      }


    public String[] getRequestedClientFeatures ()
      {
        return client_features.toArray (new String[0]);
      }


    public String[] getOptionalLanguageList ()
      {
        return languages;
      }


    public int getExpires ()
      {
        return expires;
      }
    
    public boolean wantsExtendedCertPath ()
      {
        return extended_cert_path;
      }

    
    /////////////////////////////////////////////////////////////////////////////////////////////
    // JSON Reader
    /////////////////////////////////////////////////////////////////////////////////////////////

    @Override
    void readServerRequest (JSONObjectReader rd) throws IOException
      {
        /////////////////////////////////////////////////////////////////////////////////////////
        // Read the top level properties
        /////////////////////////////////////////////////////////////////////////////////////////
        id = InputValidator.getID (rd, ID_JSON);

        server_time = rd.getString (SERVER_TIME_JSON);

        submit_url = rd.getString (SUBMIT_URL_JSON);

        abort_url = rd.getStringConditional (ABORT_URL_JSON);

        languages = InputValidator.getListConditional (rd, PREFERRED_LANGUAGES_JSON);
        
        key_container_list = KeyContainerTypes.getOptionalKeyContainerSet (InputValidator.getListConditional (rd, KeyContainerTypes.KCT_TARGET_KEY_CONTAINERS));
        
        extended_cert_path = rd.getBooleanConditional (EXTENDED_CERT_PATH_JSON);

        expires = rd.hasProperty (EXPIRES_JSON) ? rd.getInt (EXPIRES_JSON) : -1;  // Default: no timeout and associated GUI

        /////////////////////////////////////////////////////////////////////////////////////////
        // Optional client features [0..1]
        /////////////////////////////////////////////////////////////////////////////////////////
        String[] features = InputValidator.getURIListConditional (rd, CLIENT_FEATURES_JSON);
        if (features != null) for (String feature : features)
          {
            if (!client_features.add (feature))
              {
                bad ("Duplicate \"" + CLIENT_FEATURES_JSON + "\"  :" + feature);
              }
          }
        
        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the signature algorithms [1..n]
        /////////////////////////////////////////////////////////////////////////////////////////
        for (String sig_alg_string : InputValidator.getURIList (rd, SIGNATURE_ALGORITHMS_JSON))
          {
            AsymSignatureAlgorithms sig_alg = AsymSignatureAlgorithms.getAlgorithmFromID (sig_alg_string);
            if (!algorithms.add (sig_alg))
              {
                bad ("Duplicate \"" + SIGNATURE_ALGORITHMS_JSON + "\" : " + sig_alg_string);
              }
            if (sig_alg.getDigestAlgorithm() == null)
              {
                bad ("Not a proper signature algorithm: " + sig_alg_string);
              }
          }

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the optional certificate filters [0..n]
        /////////////////////////////////////////////////////////////////////////////////////////
        for (JSONObjectReader cf : InputValidator.getObjectArrayConditional (rd, CERTIFICATE_FILTERS_JSON))
          {
            certificate_filters.add (CertificateFilterReader.read (cf));
          }
      }

    @Override
    public String getQualifier ()
      {
        return AUTHENTICATION_REQUEST_JSON;
      }
  }
