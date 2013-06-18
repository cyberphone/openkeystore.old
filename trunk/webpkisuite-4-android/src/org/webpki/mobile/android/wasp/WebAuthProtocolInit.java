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

import android.os.AsyncTask;

import android.widget.Button;
import android.widget.TextView;

import android.util.Log;
import android.view.View;

import java.net.MalformedURLException;
import java.net.URL;

import java.security.cert.X509Certificate;

import org.webpki.android.crypto.CertificateFilter;

import org.webpki.android.sks.EnumeratedKey;

import org.webpki.android.wasp.AuthenticationRequestDecoder;

import org.webpki.mobile.android.R;
import org.webpki.mobile.android.sks.SKSImplementation;
import org.webpki.mobile.android.sks.SKSStore;

public class WebAuthProtocolInit extends AsyncTask<Void, String, Boolean>
  {
    private WebAuthActivity webauth_activity;
    
    SKSImplementation sks;

    public WebAuthProtocolInit (WebAuthActivity webauth_activity)
      {
        this.webauth_activity = webauth_activity;
      }

    @Override
    protected Boolean doInBackground (Void... params)
      {
        try
          {
            webauth_activity.getProtocolInvocationData ();
            webauth_activity.addSchema (AuthenticationRequestDecoder.class);
            webauth_activity.authentication_request = (AuthenticationRequestDecoder) webauth_activity.parseXML (webauth_activity.initial_request_data);
            webauth_activity.setAbortURL (webauth_activity.authentication_request.getAbortURL ());
             EnumeratedKey ek = new EnumeratedKey ();
             sks = SKSStore.createSKS (WebAuthActivity.WEBAUTH, webauth_activity, false);
             while ((ek = sks.enumerateKeys (ek.getKeyHandle ())) != null)
              {
                Log.i (WebAuthActivity.WEBAUTH, "KeyHandle=" + ek.getKeyHandle ());
                X509Certificate[] cert_path = sks.getKeyAttributes (ek.getKeyHandle ()).getCertificatePath ();
                if (webauth_activity.authentication_request.getCertificateFilters ().length > 0)
                  {
                    boolean did_it = false;
                    for (CertificateFilter cf : webauth_activity.authentication_request.getCertificateFilters ())
                      {
                        if (cf.matches (cert_path, null, null))
                          {
                            did_it = true;
                            break;
                          }
                      }
                    if (!did_it)
                      {
                        continue;
                      }
                  }
                webauth_activity.matching_keys.add (ek.getKeyHandle ());
              }
            return true;
          }
        catch (Exception e)
          {
            webauth_activity.logException (e);
          }
        return false;
      }

    @Override
    protected void onPostExecute (Boolean success)
      {
        if (webauth_activity.userHasAborted ())
          {
            return;
          }
        webauth_activity.noMoreWorkToDo ();
        if (webauth_activity.matching_keys.isEmpty ())
          {
            webauth_activity.unconditionalAbort ("You have no matching credentials");
            return;
          }
        if (success)
          {
            try
              {
                ((TextView) webauth_activity.findViewById (R.id.partyInfo)).setText (new URL (webauth_activity.getInitializationURL ()).getHost ());
              }
            catch (MalformedURLException e)
              {
              }
            webauth_activity.findViewById (R.id.primaryWindow).setVisibility (View.VISIBLE);
            final Button ok = (Button) webauth_activity.findViewById (R.id.OKbutton);
            final Button cancel = (Button) webauth_activity.findViewById (R.id.cancelButton);
            ok.requestFocus ();
            ok.setOnClickListener (new View.OnClickListener ()
              {
                @Override
                public void onClick (View v)
                  {
                    webauth_activity.findViewById (R.id.primaryWindow).setVisibility (View.INVISIBLE);
                    webauth_activity.logOK ("The user hit OK");
//                    webauth_activity.setContentView (R.layout.activity_webauth_pin);
                    new WebAuthResponseCreation (webauth_activity,
                                                 new byte[]{'1','2','3','5'},
                                                 webauth_activity.matching_keys.firstElement ()).execute ();
                  }
              });
            cancel.setOnClickListener (new View.OnClickListener ()
              {
                @Override
                public void onClick (View v)
                  {
                    webauth_activity.conditionalAbort (null);
                  }
              });
          }
        else
          {
            webauth_activity.showFailLog ();
          }
      }
  }
