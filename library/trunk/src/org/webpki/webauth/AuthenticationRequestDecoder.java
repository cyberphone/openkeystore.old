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
import java.util.LinkedHashSet;
import java.util.Vector;

import org.webpki.crypto.CertificateFilter;
import org.webpki.crypto.AsymSignatureAlgorithms;

import org.webpki.json.JSONObjectReader;

import static org.webpki.webauth.WebAuthConstants.*;


public class AuthenticationRequestDecoder extends ClientDecoder
  {
    String server_time;

    String id;
    
    LinkedHashSet<AsymSignatureAlgorithms> algorithms = new LinkedHashSet<AsymSignatureAlgorithms> ();
    
    LinkedHashSet<String> client_features = new LinkedHashSet<String> ();
    
    Vector<CertificateFilter> certificate_filters = new Vector<CertificateFilter> ();

	String submit_url;

	String abort_url;

	String[] languages;

	int expires;
    
    public AsymSignatureAlgorithms[] getSignatureAlgorithms ()
      {
        return algorithms.toArray (new AsymSignatureAlgorithms[0]);
      }


    public CertificateFilter[] getCertificateFilters ()
      {
        return certificate_filters.isEmpty() ? null : certificate_filters.toArray (new CertificateFilter[0]);
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


    public String getAbortURL ()
      {
        return abort_url;
      }


    public String[] getRequestedClientPlatformFeatures ()
      {
        return client_features.toArray (new String[0]);
      }


    public String[] getLanguages ()
      {
        return languages;
      }


    public int getExpires ()
      {
        return expires;
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
        id = InputValidator.getID (rd, ID_ATTR);

        server_time = rd.getString (SERVER_TIME_ATTR);

        submit_url = rd.getString (SUBMIT_URL_ATTR);

        abort_url = rd.getStringConditional (ABORT_URL_ATTR);

        languages = InputValidator.getListConditional (rd, LANGUAGES_ATTR);

        expires = rd.hasProperty (EXPIRES_ATTR) ? rd.getInt (EXPIRES_ATTR) : -1;  // Default: no timeout and associated GUI

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the signature algorithms [1..n]
        /////////////////////////////////////////////////////////////////////////////////////////
        for (String sig_alg_string : InputValidator.getURIList (rd, SIGNATURE_ALG_ATTR))
          {
        	AsymSignatureAlgorithms sig_alg = AsymSignatureAlgorithms.getAlgorithmFromURI (sig_alg_string);
        	if (!algorithms.add (sig_alg))
			  {
        		bad ("Duplicate \"" + SIGNATURE_ALG_ATTR + "\" : " + sig_alg_string);
			  }
        	if (sig_alg.getDigestAlgorithm() == null)
              {
        		bad ("Not a proper signature algorithm: " + sig_alg_string);
        	  }
          }

        /////////////////////////////////////////////////////////////////////////////////////////
        // Optional client features [0..1]
        /////////////////////////////////////////////////////////////////////////////////////////
        String[] features = InputValidator.getURIListConditional (rd, CLIENT_FEATURES_ATTR);
        if (features != null) for (String feature : features)
          {
        	if (!client_features.add (feature))
        	  {
        		bad ("Duplicate \"" + CLIENT_FEATURES_ATTR + "\"  :" + feature);
        	  }
          }
        
        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the optional certificate filters [0..n]
        /////////////////////////////////////////////////////////////////////////////////////////
        for (JSONObjectReader cf : InputValidator.getObjectArrayConditional (rd, CERTIFICATE_FILTER_ELEM))
          {
        	certificate_filters.add (CertificateFilterReader.read (cf));
          }
      }
  }
