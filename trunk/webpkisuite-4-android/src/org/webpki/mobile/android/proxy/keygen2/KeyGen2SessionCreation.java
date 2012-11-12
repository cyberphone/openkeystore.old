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
package org.webpki.mobile.android.proxy.keygen2;

import java.io.IOException;

import java.security.GeneralSecurityException;

import java.util.Date;
import java.util.Iterator;

import android.os.AsyncTask;

import android.text.Editable;
import android.text.InputFilter;
import android.text.TextWatcher;
import android.view.View;

import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import org.webpki.mobile.android.proxy.BaseProxyActivity;
import org.webpki.mobile.android.proxy.InterruptedProtocolException;
import org.webpki.mobile.android.proxy.R;

import org.webpki.android.crypto.MacAlgorithms;
import org.webpki.android.crypto.SymKeySignerInterface;

import org.webpki.android.keygen2.KeyCreationRequestDecoder;
import org.webpki.android.keygen2.PlatformNegotiationResponseEncoder;
import org.webpki.android.keygen2.ProvisioningInitializationRequestDecoder;
import org.webpki.android.keygen2.ProvisioningInitializationResponseEncoder;

import org.webpki.android.sks.PassphraseFormat;
import org.webpki.android.sks.ProvisioningSession;
import org.webpki.android.sks.DeviceInfo;

import org.webpki.android.xml.XMLObjectWrapper;

/**
 * This part does the real work
 */
public class KeyGen2SessionCreation extends AsyncTask<Void, String, String>
  {
    private KeyGen2Activity keygen2_activity;

    class PINDialog
      {
        private EditText pin1;
        private EditText pin2;
        private TextView pin_err;
        private byte[] last_pin;

        KeyCreationRequestDecoder.KeyObject key;

        private void upperCasePIN (EditText pin)
          {
            InputFilter[] old_filter = pin.getEditableText ().getFilters ();
            InputFilter[] new_filter = new InputFilter[old_filter.length + 1];
            for (int i = 0; i < old_filter.length; i++)
              {
                new_filter[i] = old_filter[i];
              }
            new_filter[old_filter.length] = new InputFilter.AllCaps ();
            pin.getEditableText ().setFilters (new_filter);
          }

        private boolean checkPIN ()
          {
            try
              {
                last_pin = pin1.getText ().toString ().getBytes ("UTF-8");
                if (last_pin.length < 4 || last_pin.length > 8)
                  {
                    pin_err.setText ("PIN must be 4-8 characters");
                  }
                else
                  {
                    if (pin1.getText ().toString ().equals (pin2.getText ().toString ()))
                      {
                        pin_err.setText ("");
                        return true;
                      }
                    pin_err.setText ("Retyped PIN doesn't match the first PIN");
                  }
              }
            catch (IOException e)
              {
              }
            return false;
          }

        PINDialog (final Iterator<KeyCreationRequestDecoder.KeyObject> iter)
          {
            key = iter.next ();
            keygen2_activity.setContentView (key.getPINPolicy ().getFormat () == PassphraseFormat.NUMERIC ? R.layout.activity_keygen2_numeric_pin : R.layout.activity_keygen2_pin);

            Button ok = (Button) keygen2_activity.findViewById (R.id.OKbutton);
            ok.setVisibility (View.VISIBLE);
            Button cancel = (Button) keygen2_activity.findViewById (R.id.cancelButton);
            cancel.setVisibility (View.VISIBLE);

            pin1 = (EditText) keygen2_activity.findViewById (R.id.editpin1);
            pin2 = (EditText) keygen2_activity.findViewById (R.id.editpin2);
            if (key.getPINPolicy ().getFormat () == PassphraseFormat.ALPHANUMERIC)
              {
                upperCasePIN (pin1);
                upperCasePIN (pin2);
              }
            pin_err = (TextView) keygen2_activity.findViewById (R.id.errorPIN);
            checkPIN ();
            pin1.addTextChangedListener (new TextWatcher ()
              {
                @Override
                public void afterTextChanged (Editable s)
                  {
                    checkPIN ();
                  }

                @Override
                public void beforeTextChanged (CharSequence s, int start, int count, int after)
                  {
                  }

                @Override
                public void onTextChanged (CharSequence s, int start, int before, int count)
                  {
                  }
              });
            pin2.addTextChangedListener (new TextWatcher ()
              {
                @Override
                public void afterTextChanged (Editable s)
                  {
                    checkPIN ();
                  }

                @Override
                public void beforeTextChanged (CharSequence s, int start, int count, int after)
                  {
                  }

                @Override
                public void onTextChanged (CharSequence s, int start, int before, int count)
                  {
                  }
              });
            ok.setOnClickListener (new View.OnClickListener ()
              {
                @Override
                public void onClick (View v)
                  {
                    if (checkPIN ())
                      {
                        key.setUserPIN (last_pin);
                        if (iter.hasNext ())
                          {
                            new PINDialog (iter);
                          }
                        else
                          {
                            new KeyGen2KeyCreation (keygen2_activity).execute ();
                          }
                      }
                    else
                      {
                        keygen2_activity.showAlert ("Please correct PIN");
                      }
                  }
              });
            cancel.setOnClickListener (new View.OnClickListener ()
              {
                @Override
                public void onClick (View v)
                  {
                    keygen2_activity.finish ();
                  }
              });
          }
      }

    public KeyGen2SessionCreation (KeyGen2Activity keygen2_activity)
      {
        this.keygen2_activity = keygen2_activity;
      }

    @Override
    protected String doInBackground (Void... params)
      {
        try
          {
            publishProgress (BaseProxyActivity.PROGRESS_SESSION);

            DeviceInfo device_info = keygen2_activity.sks.getDeviceInfo ();
            PlatformNegotiationResponseEncoder platform_response = new PlatformNegotiationResponseEncoder (keygen2_activity.platform_request);
            keygen2_activity.postXMLData (keygen2_activity.platform_request.getSubmitURL (), platform_response, false);

            keygen2_activity.prov_init_request = (ProvisioningInitializationRequestDecoder) keygen2_activity.parseResponse ();
            Date client_time = new Date ();
            ProvisioningSession session = keygen2_activity.sks.createProvisioningSession (keygen2_activity.prov_init_request.getSessionKeyAlgorithm (), keygen2_activity.platform_request.getPrivacyEnabledFlag (), keygen2_activity.prov_init_request.getServerSessionID (), keygen2_activity.prov_init_request.getServerEphemeralKey (), keygen2_activity.prov_init_request.getSubmitURL (), // IssuerURI
            keygen2_activity.prov_init_request.getKeyManagementKey (), (int) (client_time.getTime () / 1000), keygen2_activity.prov_init_request.getSessionLifeTime (), keygen2_activity.prov_init_request.getSessionKeyLimit ());

            keygen2_activity.provisioning_handle = session.getProvisioningHandle ();

            ProvisioningInitializationResponseEncoder prov_sess_response = new ProvisioningInitializationResponseEncoder (session.getClientEphemeralKey (), keygen2_activity.prov_init_request.getServerSessionID (), session.getClientSessionID (), keygen2_activity.prov_init_request.getServerTime (), client_time, session.getAttestation (), keygen2_activity.platform_request.getPrivacyEnabledFlag () ? null : device_info.getCertificatePath ());

            if (keygen2_activity.getServerCertificate () != null)
              {
                prov_sess_response.setServerCertificate (keygen2_activity.getServerCertificate ());
              }

            /*
             * No specific attributes are supported yet (if ever...) for (String
             * client_attribute : prov_sess_req.getClientAttributes ()) { if
             * (client_attribute.equals
             * (KeyGen2URIs.CLIENT_ATTRIBUTES.IMEI_NUMBER)) {
             * prov_sess_response.setClientAttributeValue (client_attribute,
             * "490154203237518"); } else if (client_attribute.equals
             * (KeyGen2URIs.CLIENT_ATTRIBUTES.IP_ADDRESS)) {
             * prov_sess_response.setClientAttributeValue (client_attribute,
             * "fe80::4465:62dc:5fa5:4766%10") .setClientAttributeValue
             * (client_attribute, "192.168.0.202"); } }
             */

            prov_sess_response.signRequest (new SymKeySignerInterface ()
              {
                public MacAlgorithms getMacAlgorithm () throws IOException, GeneralSecurityException
                  {
                    return MacAlgorithms.HMAC_SHA256;
                  }

                public byte[] signData (byte[] data) throws IOException, GeneralSecurityException
                  {
                    return keygen2_activity.sks.signProvisioningSessionData (keygen2_activity.provisioning_handle, data);
                  }
              });

            keygen2_activity.postXMLData (keygen2_activity.prov_init_request.getSubmitURL (), prov_sess_response, false);
            XMLObjectWrapper xml_object = keygen2_activity.parseResponse ();
            if (xml_object instanceof KeyCreationRequestDecoder)
              {
                keygen2_activity.key_creation_request = (KeyCreationRequestDecoder) xml_object;
                return KeyGen2Activity.CONTINUE_EXECUTION;
              }
            throw new IOException ("Unexpected object: " + xml_object.element ());
          }
        catch (InterruptedProtocolException e)
          {
            return keygen2_activity.getRedirectURL ();
          }
        catch (Exception e)
          {
            keygen2_activity.logException (e);
          }
        return null;
      }

    @Override
    public void onProgressUpdate (String... message)
      {
        keygen2_activity.showHeavyWork (message[0]);
      }

    @Override
    protected void onPostExecute (String result)
      {
        keygen2_activity.noMoreWorkToDo ();
        if (result != null)
          {
            if (result.equals (BaseProxyActivity.CONTINUE_EXECUTION))
              {
                try
                  {
                    Iterator<KeyCreationRequestDecoder.KeyObject> iter = keygen2_activity.key_creation_request.getKeyObjects ().iterator ();
                    if (iter.hasNext ())
                      {
                        new PINDialog (iter);
                      }
                    else
                      {
                        new KeyGen2KeyCreation (keygen2_activity).execute ();
                      }
                  }
                catch (Exception e)
                  {
                    keygen2_activity.logException (e);
                    keygen2_activity.showFailLog ();
                  }
              }
            else
              {
                keygen2_activity.launchBrowser (result);
              }
          }
        else
          {
            keygen2_activity.showFailLog ();
          }
      }
  }
