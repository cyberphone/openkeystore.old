/*
 *  Copyright 2006-2012 WebPKI.org (http://webpki.org).
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
package org.webpki.mobile.android.wasp;

import java.io.IOException;

import java.security.cert.X509Certificate;
import java.util.Date;

import android.os.AsyncTask;

import org.webpki.mobile.android.proxy.BaseProxyActivity;
import org.webpki.mobile.android.proxy.InterruptedProtocolException;

import org.webpki.android.wasp.AuthenticationResponseEncoder;

import org.webpki.android.crypto.CertificateInfo;
import org.webpki.android.crypto.SignatureAlgorithms;
import org.webpki.android.crypto.SignerInterface;

/**
 * This worker class creates the actual authentication response.
 */
public class WebAuthResponseCreation extends AsyncTask<Void, String, String>
  {
    private WebAuthActivity webauth_activity;
    
    private byte[] authorization;
    
    private int key_handle;

    public WebAuthResponseCreation (WebAuthActivity webauth_activity, byte[] authorization, int key_handle)
      {
        this.webauth_activity = webauth_activity;
        this.authorization = authorization;
        this.key_handle = key_handle;
      }

    @Override
    protected String doInBackground (Void... params)
      {
        try
          {
            publishProgress (BaseProxyActivity.PROGRESS_AUTHENTICATING);

            AuthenticationResponseEncoder authentication_response = new AuthenticationResponseEncoder ();

            authentication_response.createSignedResponse (new SignerInterface ()
              {
                @Override
                public boolean authorizationFailed () throws IOException
                  {
                    return false;
                  }
  
                @Override
                public CertificateInfo getSignerCertificateInfo () throws IOException
                  {
                    return null;
                  }
  
                @Override
                public X509Certificate[] prepareSigning (boolean full_path) throws IOException
                  {
                    X509Certificate[] cert_path = webauth_activity.sks.getKeyAttributes (key_handle).getCertificatePath ();
                    return full_path ? cert_path : new X509Certificate[]{cert_path[0]};
                  }
  
                @Override
                public byte[] signData (byte[] data, SignatureAlgorithms sign_alg) throws IOException
                  {
                    return webauth_activity.sks.signHashedData (key_handle,
                                                                sign_alg.getURI (),
                                                                null,
                                                                authorization,
                                                                sign_alg.getDigestAlgorithm ().digest (data));
                  }},
                  webauth_activity.authentication_request,
                  webauth_activity.authentication_request.getSubmitURL (),
                  new Date (),
                  webauth_activity.getServerCertificate ());
            webauth_activity.postXMLData (webauth_activity.authentication_request.getSubmitURL (), authentication_response, true);
            return webauth_activity.getRedirectURL ();
          }
        catch (Exception e)
          {
            webauth_activity.logException (e);
          }
        return null;
      }

    @Override
    protected void onPostExecute (String result)
      {
        if (webauth_activity.userHasAborted ())
          {
            return;
          }
        if (result != null)
          {
            webauth_activity.launchBrowser (result);
          }
        else
          {
            webauth_activity.showFailLog ();
          }
      }
  }
