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
import android.text.InputType;
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

import org.webpki.android.sks.AppUsage;
import org.webpki.android.sks.Grouping;
import org.webpki.android.sks.PassphraseFormat;
import org.webpki.android.sks.ProvisioningSession;
import org.webpki.android.sks.DeviceInfo;

import org.webpki.android.xml.XMLObjectWrapper;

/**
 * This worker class creates the SKS/KeyGen2 SessionKey.
 * Optionally credentials are looked-up and PINs are set.
 */
public class KeyGen2SessionCreation extends AsyncTask<Void, String, String>
  {
    private KeyGen2Activity keygen2_activity;
    
    private int pin_count;
    private boolean multiple_pins;

    private class PINDialog
      {
        private EditText pin1;
        private EditText pin2;
        private TextView pin_err;
        private boolean equal_pins;

        KeyCreationRequestDecoder.UserPINDescriptor upd;

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

        private boolean checkPIN (boolean set_value)
          {
            String pin = pin1.getText ().toString ();
            equal_pins = pin1.getText ().toString ().equals (pin2.getText ().toString ());
            KeyCreationRequestDecoder.UserPINError res = upd.setPIN (pin, set_value && equal_pins);
            if (res == null)
              {
                pin_err.setText ("");
                return true;
              }
            else
              {
                KeyCreationRequestDecoder.PINPolicy pin_policy = upd.getPINPolicy ();
                String error = "PIN syntax error";
                if (res.length_error)
                  {
                    error = "PINs must be " + pin_policy.getMinLength () + "-" + pin_policy.getMaxLength () +
                            (pin_policy.getFormat () == PassphraseFormat.NUMERIC ? " digits" : " characters");
                  }
                else if (res.syntax_error)
                  {
                    switch (pin_policy.getFormat ())
                      {
                        case NUMERIC:
                          error = "PINs must only contain 0-9";
                          break;

                        case ALPHANUMERIC:
                          error = "PINs must only contain 0-9 A-Z";
                          break;

                        case BINARY:
                          error = "PINs must be a hexadecimal string";
                          break;
                      }
                  }
                else if (res.pattern_error != null)
                  {
                    switch (res.pattern_error)
                      {
                        case SEQUENCE:
                          error = "PINs must not be a sequence";
                          break;

                        case TWO_IN_A_ROW:
                          error = "PINs must not contain two equal\ncharacters in a row";
                          break;

                        case THREE_IN_A_ROW:
                          error = "PINs must not contain three equal\ncharacters in a row";
                          break;

                        case REPEATED:
                          error = "PINs must not contain the same\ncharacters twice";
                          break;

                        case MISSING_GROUP:
                          error = "PINs must be a mix of A-Z " + (pin_policy.getFormat () == PassphraseFormat.ALPHANUMERIC ? 
                                           "0-9" : "a-z 0-9\nand control characters");
                          break;
                      }
                  }
                else if (res.unique_error)
                  {
                    error = "PINs for " + upd.getAppUsage ().getXMLName () + " and " + res.unique_error_app_usage.getXMLName () + " must not be equal";
                  }
                pin_err.setText (error);
              }
            return false;
          }

        PINDialog (final Iterator<KeyCreationRequestDecoder.UserPINDescriptor> iter)
          {
            if (iter.hasNext ())
              {
                upd = iter.next ();
                keygen2_activity.setContentView (R.layout.activity_keygen2_pin);
    
                Button ok = (Button) keygen2_activity.findViewById (R.id.OKbutton);
                Button cancel = (Button) keygen2_activity.findViewById (R.id.cancelButton);
    
                pin1 = (EditText) keygen2_activity.findViewById (R.id.editpin1);
                pin2 = (EditText) keygen2_activity.findViewById (R.id.editpin2);
                if (upd.getPINPolicy ().getFormat () != PassphraseFormat.NUMERIC)
                  {
                    pin1.setInputType (InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
                    pin2.setInputType (InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
                  }
                if (upd.getPINPolicy ().getFormat () == PassphraseFormat.ALPHANUMERIC)
                  {
                    upperCasePIN (pin1);
                    upperCasePIN (pin2);
                  }
                pin_err = (TextView) keygen2_activity.findViewById (R.id.errorPIN);
                TextView set_pin_text = (TextView) keygen2_activity.findViewById (R.id.setPINtext);
                StringBuffer lead_text = new StringBuffer ("Set ");
                if (upd.getPINPolicy ().getGrouping () == Grouping.SIGNATURE_PLUS_STANDARD)
                  {
                    lead_text.append (upd.getAppUsage () == AppUsage.SIGNATURE ? "signature " : "standard ");
                  }
                else if (upd.getPINPolicy ().getGrouping () == Grouping.UNIQUE)
                  {
                    if (upd.getAppUsage () != AppUsage.UNIVERSAL)
                      {
                        lead_text.append (upd.getAppUsage ().getXMLName ());
                        lead_text.append (' ');
                      }
                  }
                lead_text.append ("PIN");
                if (multiple_pins)
                  {
                    lead_text.append (" #").append (++pin_count);
                  }
                set_pin_text.setText (lead_text);
                checkPIN (false);
                pin1.addTextChangedListener (new TextWatcher ()
                  {
                    @Override
                    public void afterTextChanged (Editable s)
                      {
                        checkPIN (false);
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
                        if (checkPIN (true))
                          {
                            if (equal_pins)
                              {
                                new PINDialog (iter);
                              }
                            else
                              {
                                keygen2_activity.showAlert ("The retyped PIN doesn't match the original");
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
            else
              {
                keygen2_activity.findViewById (R.id.primaryWindow).setVisibility (View.INVISIBLE);
                new KeyGen2KeyCreation (keygen2_activity).execute ();
              }
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
            PlatformNegotiationResponseEncoder platform_response = 
                new PlatformNegotiationResponseEncoder (keygen2_activity.platform_request);
            keygen2_activity.postXMLData (keygen2_activity.platform_request.getSubmitURL (), platform_response, false);

            keygen2_activity.prov_init_request = (ProvisioningInitializationRequestDecoder) keygen2_activity.parseResponse ();
            Date client_time = new Date ();
            ProvisioningSession session = 
                keygen2_activity.sks.createProvisioningSession (keygen2_activity.prov_init_request.getSessionKeyAlgorithm (),
                                                                keygen2_activity.platform_request.getPrivacyEnabledFlag (),
                                                                keygen2_activity.prov_init_request.getServerSessionID (),
                                                                keygen2_activity.prov_init_request.getServerEphemeralKey (),
                                                                keygen2_activity.prov_init_request.getSubmitURL (), // IssuerURI
                                                                keygen2_activity.prov_init_request.getKeyManagementKey (),
                                                                (int) (client_time.getTime () / 1000),
                                                                keygen2_activity.prov_init_request.getSessionLifeTime (),
                                                                keygen2_activity.prov_init_request.getSessionKeyLimit ());

            keygen2_activity.provisioning_handle = session.getProvisioningHandle ();

            ProvisioningInitializationResponseEncoder prov_sess_response =
                new ProvisioningInitializationResponseEncoder (session.getClientEphemeralKey (),
                                                               keygen2_activity.prov_init_request.getServerSessionID (),
                                                               session.getClientSessionID (),
                                                               keygen2_activity.prov_init_request.getServerTime (),
                                                               client_time,
                                                               session.getAttestation (),
                                                               keygen2_activity.platform_request.getPrivacyEnabledFlag () ? null : device_info.getCertificatePath ());

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
                    ///////////////////////////////////////////////////////////////////////////
                    // Note: There may be zero PINs but the test in the constructor fixes that
                    ///////////////////////////////////////////////////////////////////////////
                    multiple_pins = keygen2_activity.key_creation_request.getUserPINDescriptors ().size () > 1;
                    new PINDialog (keygen2_activity.key_creation_request.getUserPINDescriptors ().iterator ());
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
