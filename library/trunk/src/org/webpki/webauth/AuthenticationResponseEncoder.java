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

import java.security.GeneralSecurityException;

import java.security.cert.X509Certificate;

import java.util.Date;

import org.webpki.crypto.HashAlgorithms;

import org.webpki.json.JSONEncoder;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONX509Signer;

import static org.webpki.webauth.WebAuthConstants.*;


public class AuthenticationResponseEncoder extends JSONEncoder
  {
    private String server_time;

    private Date client_time;
    
    byte[] server_certificate_fingerprint;
    
    String id;
    
    String request_url;
    
    JSONX509Signer signer;


    public AuthenticationResponseEncoder (JSONX509Signer signer,
                                          AuthenticationRequestDecoder auth_req_decoder,
                                          String request_url,
                                          Date client_time,
                                          X509Certificate server_certificate) throws IOException
      {
        this.signer = signer;
        this.id = auth_req_decoder.getID ();
        this.server_time = auth_req_decoder.getServerTime ();
        this.request_url = request_url;
        this.client_time = client_time;
        if (server_certificate != null)
          {
            try
              {
                this.server_certificate_fingerprint = HashAlgorithms.SHA256.digest (server_certificate.getEncoded ());
              }
            catch (GeneralSecurityException e)
              {
                throw new IOException (e);
              }
          }
      }

/*
    public AuthenticationResponseEncoder addClientPlatformFeature (ClientPlatformFeature client_platform_feature)
      {
        client_platform_features.add (client_platform_feature);
        return this;
      }
*/

    @Override
    protected void writeJSONData (JSONObjectWriter wr) throws IOException
      {
        wr.setString (ID_ATTR, id);

        wr.setString (SERVER_TIME_ATTR, server_time);

        wr.setString (REQUEST_URL_ATTR, request_url);

        wr.setDateTime (CLIENT_TIME_ATTR, client_time);

        if (server_certificate_fingerprint != null)
          {
            wr.setBinary (SERVER_CERT_FP_ATTR, server_certificate_fingerprint);
          }
/*        
        for (ClientPlatformFeature client_platform_feature : client_platform_features)
          {
            client_platform_feature.write (wr);
          }
*/
        wr.setSignature (signer);
      }

    @Override
    protected String getContext ()
      {
        return WebAuthConstants.WEBAUTH_NS;
      }
  }
