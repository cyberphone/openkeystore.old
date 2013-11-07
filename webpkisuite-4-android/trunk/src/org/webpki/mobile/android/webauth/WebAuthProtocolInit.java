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
package org.webpki.mobile.android.webauth;

import android.os.AsyncTask;

import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.TextView.OnEditorActionListener;
import android.widget.Toast;

import android.util.Log;

import android.view.KeyEvent;
import android.view.View;

import android.view.inputmethod.EditorInfo;

import java.io.IOException;

import java.security.cert.X509Certificate;

import java.security.interfaces.RSAPublicKey;

import org.webpki.mobile.android.R;

import org.webpki.android.sks.AppUsage;
import org.webpki.android.sks.EnumeratedKey;
import org.webpki.android.sks.KeyAttributes;

import org.webpki.android.crypto.AsymSignatureAlgorithms;
import org.webpki.android.crypto.CertificateFilter;
import org.webpki.android.crypto.KeyContainerTypes;

import org.webpki.android.webauth.AuthenticationRequestDecoder;

import org.webpki.mobile.android.sks.SKSImplementation;
import org.webpki.mobile.android.sks.SKSStore;

import org.webpki.mobile.android.util.CredentialListDataFactory;

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
            webauth_activity.addDecoder (AuthenticationRequestDecoder.class);
            webauth_activity.authentication_request = (AuthenticationRequestDecoder) webauth_activity.getInitialReguest ();
            webauth_activity.setAbortURL (webauth_activity.authentication_request.getOptionalAbortURL ());
            EnumeratedKey ek = new EnumeratedKey ();
            sks = SKSStore.createSKS (WebAuthActivity.WEBAUTH, webauth_activity, false);

            ////////////////////////////////////////////////////////////////////////////////////
            // Maybe the requester wants better protected keys...
            ////////////////////////////////////////////////////////////////////////////////////
            if (webauth_activity.authentication_request.getOptionalKeyContainerList () != null &&
                !webauth_activity.authentication_request.getOptionalKeyContainerList ().contains (KeyContainerTypes.SOFTWARE))
              {
                throw new IOException ("The requester asked for another key container type: " + webauth_activity.authentication_request.getOptionalKeyContainerList ().toString ());
              }

            ////////////////////////////////////////////////////////////////////////////////////
            // Passed that hurdle, now check keys for compliance...
            ////////////////////////////////////////////////////////////////////////////////////
            while ((ek = sks.enumerateKeys (ek.getKeyHandle ())) != null)
              {
                Log.i (WebAuthActivity.WEBAUTH, "KeyHandle=" + ek.getKeyHandle ());
                KeyAttributes ka = sks.getKeyAttributes (ek.getKeyHandle ());

                ////////////////////////////////////////////////////////////////////////////////////
                // All keys are NOT usable (or intended) for PKI-based authentication...
                ////////////////////////////////////////////////////////////////////////////////////
                if (ka.isSymmetricKey () || 
                    (ka.getAppUsage () != AppUsage.AUTHENTICATION && ka.getAppUsage () != AppUsage.UNIVERSAL))
                  {
                    continue;
                  }
                X509Certificate[] cert_path = ka.getCertificatePath ();
                boolean did_it = false;
                boolean rsa_flag = cert_path[0].getPublicKey () instanceof RSAPublicKey;
                AsymSignatureAlgorithms signature_algorithm = null;
                for (AsymSignatureAlgorithms sig_alg : webauth_activity.authentication_request.getSignatureAlgorithms ())
                  {
                    if (rsa_flag == sig_alg.isRSA () && SKSStore.isSupported (sig_alg.getURI ()))
                      {
                        signature_algorithm = sig_alg;
                        did_it = true;
                        break;
                      }
                  }
                if (!did_it)
                  {
                    continue;
                  }
                if (webauth_activity.authentication_request.getCertificateFilters ().length > 0)
                  {
                    did_it = false;
                    ////////////////////////////////////////////////////////////////////////////////////
                    // The requester wants to discriminate keys further...
                    ////////////////////////////////////////////////////////////////////////////////////
                    for (CertificateFilter cf : webauth_activity.authentication_request.getCertificateFilters ())
                      {
                        if (cf.matches (cert_path))
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
                webauth_activity.matching_keys.put (ek.getKeyHandle (), signature_algorithm);
              }
            return true;
          }
        catch (Exception e)
          {
            webauth_activity.logException (e);
          }
        return false;
      }

    int firstKey ()
      {
        return webauth_activity.matching_keys.keySet ().iterator ().next ();
      }

    @Override
    protected void onPostExecute (Boolean success)
      {
        if (webauth_activity.userHasAborted () || webauth_activity.initWasRejected ())
          {
            return;
          }
        webauth_activity.noMoreWorkToDo ();
        if (success)
          {
            ///////////////////////////////////////////////////////////////////////////////////
            // Successfully recieved the request, now show the domain name of the requester
            ///////////////////////////////////////////////////////////////////////////////////
            ((TextView) webauth_activity.findViewById (R.id.partyInfo)).setText (webauth_activity.getRequestingHost ());
            ((TextView)webauth_activity.findViewById (R.id.partyInfo)).setOnClickListener (new View.OnClickListener ()
              {
                @Override
                public void onClick (View v)
                  {
                    Toast.makeText (webauth_activity, "Requesting Party Properties - Not yet implemented!", Toast.LENGTH_LONG).show ();
                  }
              });

            final Button ok = (Button) webauth_activity.findViewById (R.id.OKbutton);
            final Button cancel = (Button) webauth_activity.findViewById (R.id.cancelButton);
            ok.requestFocus ();
            ok.setOnClickListener (new View.OnClickListener ()
              {
                @Override
                public void onClick (View v)
                  {
                    webauth_activity.logOK ("The user hit OK");

                    ///////////////////////////////////////////////////////////////////////////////////
                    // We have no keys at all or no keys that matches the filter criterions, abort
                    ///////////////////////////////////////////////////////////////////////////////////
                    if (webauth_activity.matching_keys.isEmpty ())
                      {
                        webauth_activity.showAlert ("You have no matching credentials");
                        return;
                      }
                    try
                      {
                        ///////////////////////////////////////////////////////////////////////////////////
                        // Seem we got something here to authenticate with!
                        ///////////////////////////////////////////////////////////////////////////////////
                        if (((CheckBox) webauth_activity.findViewById (R.id.grantCheckBox)).isChecked ())
                          {
                            sks.setGrant (firstKey (), webauth_activity.getRequestingHost (), true);
                          }
                        webauth_activity.setContentView (R.layout.activity_webauth_pin);
                        ((LinearLayout)webauth_activity.findViewById (R.id.credential_element)).setOnClickListener (new View.OnClickListener ()
                          {
                            @Override
                            public void onClick (View v)
                              {
                                Toast.makeText (webauth_activity, "Credential Properties - Not yet implemented!", Toast.LENGTH_LONG).show ();
                              }
                          });
                        CredentialListDataFactory credential_data_factory = new CredentialListDataFactory (webauth_activity, sks);
                        ((ImageView) webauth_activity.findViewById (R.id.auth_cred_logo)).setImageBitmap (credential_data_factory.getListIcon (firstKey ()));
                        String friendly_name = credential_data_factory.getFriendlyName (firstKey ());
                        ((TextView) webauth_activity.findViewById (R.id.auth_cred_domain)).setText (friendly_name == null ? credential_data_factory.getDomain (firstKey ()) : friendly_name);
                        if (android.os.Build.VERSION.SDK_INT < 16)
                          {
                            webauth_activity.findViewById (R.id.pinWindow).setVisibility (View.GONE);
                            webauth_activity.findViewById (R.id.pinWindow).setVisibility (View.VISIBLE);
                          }
                        final Button ok = (Button) webauth_activity.findViewById (R.id.OKbutton);
                        Button cancel = (Button) webauth_activity.findViewById (R.id.cancelButton);
                        final EditText pin = (EditText) webauth_activity.findViewById (R.id.editpin1); 
                        pin.setSelected (true);
                        pin.requestFocus ();
                        ok.setOnClickListener (new View.OnClickListener ()
                          {
                            @Override
                            public void onClick (View v)
                              {
                                new WebAuthResponseCreation (webauth_activity,
                                                             pin.getText ().toString (),
                                                             firstKey ()).execute ();
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
                        pin.setOnEditorActionListener (new OnEditorActionListener ()
                          {
                            @Override
                            public boolean onEditorAction (TextView v, int actionId, KeyEvent event)
                              {
                                if ((actionId & EditorInfo.IME_MASK_ACTION) != 0)
                                  {
                                    ok.performClick ();
                                  }
                                return false;
                              }
                          });
                      }
                    catch (Exception e)
                      {
                        throw new RuntimeException (e);
                      }
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
            try
              {
                if (!webauth_activity.matching_keys.isEmpty () &&
                    sks.isGranted (firstKey (), webauth_activity.getRequestingHost ()))
                  {
                    ((CheckBox) webauth_activity.findViewById (R.id.grantCheckBox)).setChecked (true);
                    ok.performClick ();
                  }
              }
            catch (Exception e)
              {
                throw new RuntimeException (e);
              }
          }
        else
          {
            webauth_activity.showFailLog ();
          }
      }
  }
