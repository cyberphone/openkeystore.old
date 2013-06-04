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

import java.security.GeneralSecurityException;

import java.security.cert.X509Certificate;

import java.util.Date;

import org.w3c.dom.Element;

import org.webpki.xml.DOMWriterHelper;

import org.webpki.xmldsig.XMLSigner;

import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.SignerInterface;

import static org.webpki.wasp.WASPConstants.*;


public class AuthenticationResponseEncoder extends AuthenticationResponse
  {
    private String server_time;

    private Date client_time;

    private boolean add_new_line = true;

    private String prefix;  // Default: no prefix


    public void setPrefix (String prefix) throws IOException
      {
        this.prefix = prefix;
      }


    public String getPrefix ()
      {
        return prefix;
      }


    public void createSignedResponse (SignerInterface signer,
                                      AuthenticationRequestDecoder auth_req_decoder,
                                      String request_url,
                                      Date client_time,
                                      X509Certificate server_certificate) throws IOException
      {
        this.id = auth_req_decoder.getID ();
        this.server_time = auth_req_decoder.getServerTime ();
        this.request_url = request_url;
        this.submit_url = auth_req_decoder.getSubmitURL ();
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
        Element elem = forcedDOMRewrite ();
        if (add_new_line)
          {
            elem.appendChild (getRootDocument ().createTextNode ("\n"));
          }
        
        AuthenticationRequestDecoder.AuthenticationProfile selected_auth_profile = auth_req_decoder.getAuthenticationProfiles ()[0];
        XMLSigner ds = new XMLSigner (signer);
        ds.setSignatureAlgorithm (selected_auth_profile.getSignatureAlgorithm ());
        ds.setDigestAlgorithm (selected_auth_profile.getDigestAlgorithm ());
        ds.setTransformAlgorithm (selected_auth_profile.getCanonicalizationAlgorithm ());
        ds.setCanonicalizationAlgorithm  (selected_auth_profile.getCanonicalizationAlgorithm ());
        ds.setExtendedCertPath (selected_auth_profile.getExtendedCertPath ());
        ds.setSignedKeyInfo (selected_auth_profile.getSignedKeyInfo ());

        ds.createEnvelopedSignature (getRootDocument (), id);
      }


    protected void toXML (DOMWriterHelper wr) throws IOException
      {
        wr.initializeRootObject (prefix);

        wr.setStringAttribute (ID_ATTR, id);

        wr.setStringAttribute (SERVER_TIME_ATTR, server_time);

        wr.setStringAttribute (SUBMIT_URL_ATTR, submit_url);

        wr.setStringAttribute (REQUEST_URL_ATTR, request_url);

        wr.setDateTimeAttribute (CLIENT_TIME_ATTR, client_time);

        if (server_certificate_fingerprint != null)
          {
            wr.setBinaryAttribute (SERVER_CERT_FP_ATTR, server_certificate_fingerprint);
          }
      }

  }
