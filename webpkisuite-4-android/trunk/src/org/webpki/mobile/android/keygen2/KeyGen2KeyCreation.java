/*
 *  Copyright 2006-2015 WebPKI.org (http://webpki.org).
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
package org.webpki.mobile.android.keygen2;

import java.io.IOException;

import java.security.GeneralSecurityException;

import android.os.AsyncTask;

import org.webpki.mobile.android.proxy.BaseProxyActivity;
import org.webpki.mobile.android.proxy.InterruptedProtocolException;

import org.webpki.util.ArrayUtil;

import org.webpki.crypto.HashAlgorithms;

import org.webpki.keygen2.KeyCreationRequestDecoder;
import org.webpki.keygen2.KeyCreationResponseEncoder;
import org.webpki.keygen2.ProvisioningFinalizationRequestDecoder;
import org.webpki.keygen2.ProvisioningFinalizationResponseEncoder;

import org.webpki.sks.EnumeratedKey;
import org.webpki.sks.KeyAttributes;
import org.webpki.sks.EnumeratedProvisioningSession;
import org.webpki.sks.KeyData;
import org.webpki.sks.PatternRestriction;

/**
 * This worker class creates keys.
 * If keys are only managed, this class will not be instantiated.
 */
public class KeyGen2KeyCreation extends AsyncTask<Void, String, String>
  {
    private KeyGen2Activity keygen2_activity;

    public KeyGen2KeyCreation (KeyGen2Activity keygen2_activity)
      {
        this.keygen2_activity = keygen2_activity;
      }

    private void postProvisioning (ProvisioningFinalizationRequestDecoder.PostOperation post_operation, int handle) throws IOException, GeneralSecurityException
      {
        EnumeratedProvisioningSession old_provisioning_session = new EnumeratedProvisioningSession ();
        while (true)
          {
            if ((old_provisioning_session = keygen2_activity.sks.enumerateProvisioningSessions (old_provisioning_session.getProvisioningHandle (), false)) == null)
              {
                throw new IOException ("Old provisioning session not found:" +
                                       post_operation.getClientSessionId () + 
                                       "/" +
                                       post_operation.getServerSessionId ());
              }
            if (old_provisioning_session.getClientSessionId ().equals (post_operation.getClientSessionId ()) &&
                old_provisioning_session.getServerSessionId ().equals (post_operation.getServerSessionId ()))
              {
                break;
              }
          }
        EnumeratedKey ek = new EnumeratedKey ();
        while (true)
          {
            if ((ek = keygen2_activity.sks.enumerateKeys (ek.getKeyHandle ())) == null)
              {
                throw new IOException ("Old key not found");
              }
            if (ek.getProvisioningHandle () == old_provisioning_session.getProvisioningHandle ())
              {
                KeyAttributes ka = keygen2_activity.sks.getKeyAttributes (ek.getKeyHandle ());
                if (ArrayUtil.compare (HashAlgorithms.SHA256.digest (ka.getCertificatePath ()[0].getEncoded ()),
                                                                     post_operation.getCertificateFingerprint ()))
                  {
                    switch (post_operation.getPostOperation ())
                      {
                        case ProvisioningFinalizationRequestDecoder.PostOperation.CLONE_KEY_PROTECTION:
                          keygen2_activity.sks.postCloneKeyProtection (handle,
                                                                       ek.getKeyHandle (),
                                                                       post_operation.getAuthorization (),
                                                                       post_operation.getMac ());
                          break;

                        case ProvisioningFinalizationRequestDecoder.PostOperation.UPDATE_KEY:
                          keygen2_activity.sks.postUpdateKey (handle,
                                                              ek.getKeyHandle (),
                                                              post_operation.getAuthorization (),
                                                              post_operation.getMac ());
                          break;

                        case ProvisioningFinalizationRequestDecoder.PostOperation.UNLOCK_KEY:
                          keygen2_activity.sks.postUnlockKey (handle,
                                                              ek.getKeyHandle (),
                                                              post_operation.getAuthorization (),
                                                              post_operation.getMac ());
                          break;

                        default:
                          keygen2_activity.sks.postDeleteKey (handle,
                                                              ek.getKeyHandle (),
                                                              post_operation.getAuthorization (),
                                                              post_operation.getMac ());
                      }
                    return;
                  }
              }
          }
      }

    @Override
    protected String doInBackground (Void... params)
      {
        try
          {
            publishProgress (BaseProxyActivity.PROGRESS_KEYGEN);

            KeyCreationResponseEncoder key_creation_response = new KeyCreationResponseEncoder (keygen2_activity.key_creation_request);

            int pin_policy_handle = 0;
            int puk_policy_handle = 0;
            for (KeyCreationRequestDecoder.KeyObject key : keygen2_activity.key_creation_request.getKeyObjects ())
              {
                if (key.getPINPolicy () == null)
                  {
                    pin_policy_handle = 0;
                    puk_policy_handle = 0;
                  }
                else
                  {
                    if (key.isStartOfPINPolicy ())
                      {
                        if (key.isStartOfPUKPolicy ())
                          {
                            KeyCreationRequestDecoder.PUKPolicy puk_policy = key.getPINPolicy ().getPUKPolicy ();
                            puk_policy_handle = keygen2_activity.sks.createPukPolicy (keygen2_activity.provisioning_handle,
                                                                                      puk_policy.getID (),
                                                                                      puk_policy.getEncryptedValue (),
                                                                                      puk_policy.getFormat ().getSksValue (),
                                                                                      puk_policy.getRetryLimit (),
                                                                                      puk_policy.getMac ());
                          }
                        KeyCreationRequestDecoder.PINPolicy pin_policy = key.getPINPolicy ();
                        pin_policy_handle = keygen2_activity.sks.createPinPolicy (keygen2_activity.provisioning_handle,
                                                                                  pin_policy.getID (),
                                                                                  puk_policy_handle,
                                                                                  pin_policy.getUserDefinedFlag (),
                                                                                  pin_policy.getUserModifiableFlag (),
                                                                                  pin_policy.getFormat ().getSksValue (),
                                                                                  pin_policy.getRetryLimit (),
                                                                                  pin_policy.getGrouping ().getSksValue (),
                                                                                  PatternRestriction.getSksValue (pin_policy.getPatternRestrictions ()),
                                                                                  pin_policy.getMinLength (),
                                                                                  pin_policy.getMaxLength (),
                                                                                  pin_policy.getInputMethod ().getSksValue (),
                                                                                  pin_policy.getMac ());
                      }
                  }
                KeyData key_data = keygen2_activity.sks.createKeyEntry (keygen2_activity.provisioning_handle,
                                                                        key.getID (),
                                                                        keygen2_activity.key_creation_request.getKeyEntryAlgorithm (),
                                                                        key.getServerSeed (),
                                                                        key.isDevicePINProtected (),
                                                                        pin_policy_handle,
                                                                        key.getSKSPINValue (),
                                                                        key.getEnablePINCachingFlag (),
                                                                        key.getBiometricProtection ().getSksValue (),
                                                                        key.getExportProtection ().getSksValue (),
                                                                        key.getDeleteProtection ().getSksValue (),
                                                                        key.getAppUsage ().getSksValue (),
                                                                        key.getFriendlyName (),
                                                                        key.getKeySpecifier ().getKeyAlgorithm ().getURI (), 
                                                                        key.getKeySpecifier ().getKeyParameters (),
                                                                        key.getEndorsedAlgorithms (),
                                                                        key.getMac ());
                key_creation_response.addPublicKey (key_data.getPublicKey (), key_data.getAttestation (), key.getID ());
              }

            keygen2_activity.postJSONData (keygen2_activity.key_creation_request.getSubmitUrl (), key_creation_response, false);

            publishProgress (BaseProxyActivity.PROGRESS_DEPLOY_CERTS);

            ProvisioningFinalizationRequestDecoder prov_final_request = (ProvisioningFinalizationRequestDecoder) keygen2_activity.parseJSONResponse ();

            //////////////////////////////////////////////////////////////////////////
            // Note: we could have used the saved provisioning_handle but that
            // would not work for certifications that are delayed. The following
            // code is working for fully interactive and delayed scenarios by
            // using SKS as state-holder
             //////////////////////////////////////////////////////////////////////////
            EnumeratedProvisioningSession eps = new EnumeratedProvisioningSession ();
            while (true)
              {
                if ((eps = keygen2_activity.sks.enumerateProvisioningSessions (eps.getProvisioningHandle (), true)) == null)
                  {
                    throw new IOException ("Provisioning session not found:" + 
                                           prov_final_request.getClientSessionId () +
                                           "/" +
                                           prov_final_request.getServerSessionId ());
                  }
                if (eps.getClientSessionId ().equals (prov_final_request.getClientSessionId ()) &&
                    eps.getServerSessionId ().equals (prov_final_request.getServerSessionId ()))
                  {
                    break;
                  }
              }

            //////////////////////////////////////////////////////////////////////////
            // Final check, do these keys match the request?
            //////////////////////////////////////////////////////////////////////////
            for (ProvisioningFinalizationRequestDecoder.IssuedCredential key : prov_final_request.getIssuedCredentials ())
              {
                int key_handle = keygen2_activity.sks.getKeyHandle (eps.getProvisioningHandle (),
                                                                    key.getId ());
                keygen2_activity.sks.setCertificatePath (key_handle,
                                                         key.getCertificatePath (),
                                                         key.getMac ());

                //////////////////////////////////////////////////////////////////////////
                // There may be a symmetric key
                //////////////////////////////////////////////////////////////////////////
                if (key.getOptionalSymmetricKey () != null)
                  {
                    keygen2_activity.sks.importSymmetricKey (key_handle,
                                                             key.getOptionalSymmetricKey (),
                                                             key.getSymmetricKeyMac ());
                  }

                //////////////////////////////////////////////////////////////////////////
                // There may be a private key
                //////////////////////////////////////////////////////////////////////////
                if (key.getOptionalPrivateKey () != null)
                  {
                    keygen2_activity.sks.importPrivateKey (key_handle,
                                                           key.getOptionalPrivateKey (),
                                                           key.getPrivateKeyMac ());
                  }

                //////////////////////////////////////////////////////////////////////////
                // There may be extensions
                //////////////////////////////////////////////////////////////////////////
                for (ProvisioningFinalizationRequestDecoder.Extension extension : key.getExtensions ())
                  {
                    keygen2_activity.sks.addExtension (key_handle,
                                                       extension.getExtensionType (),
                                                       extension.getSubType (),
                                                       extension.getQualifier (),
                                                       extension.getExtensionData (),
                                                       extension.getMac ());
                  }

                //////////////////////////////////////////////////////////////////////////
                // There may be an postUpdateKey or postCloneKeyProtection
                //////////////////////////////////////////////////////////////////////////
                ProvisioningFinalizationRequestDecoder.PostOperation post_operation = key.getPostOperation ();
                if (post_operation != null)
                  {
                    postProvisioning (post_operation, key_handle);
                  }
              }

            //////////////////////////////////////////////////////////////////////////
            // There may be any number of postUnlockKey
            //////////////////////////////////////////////////////////////////////////
            for (ProvisioningFinalizationRequestDecoder.PostOperation post_unl : prov_final_request.getPostUnlockKeys ())
              {
                postProvisioning (post_unl, eps.getProvisioningHandle ());
              }

            //////////////////////////////////////////////////////////////////////////
            // There may be any number of postDeleteKey
            //////////////////////////////////////////////////////////////////////////
            for (ProvisioningFinalizationRequestDecoder.PostOperation post_del : prov_final_request.getPostDeleteKeys ())
              {
                postProvisioning (post_del, eps.getProvisioningHandle ());
              }

            publishProgress (BaseProxyActivity.PROGRESS_FINAL);

            //////////////////////////////////////////////////////////////////////////
            // Create final and attested message
            //////////////////////////////////////////////////////////////////////////
            keygen2_activity.postJSONData (prov_final_request.getSubmitUrl (),
                                          new ProvisioningFinalizationResponseEncoder (prov_final_request,
                                                                                       keygen2_activity.sks.closeProvisioningSession (eps.getProvisioningHandle (),
                                                                                       prov_final_request.getCloseSessionNonce (),
                                                                                       prov_final_request.getCloseSessionMac ())),
                                          true);
            return keygen2_activity.getRedirectURL ();
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
        if (keygen2_activity.userHasAborted ())
          {
            return;
          }
        if (result != null)
          {
            keygen2_activity.launchBrowser (result);
          }
        else
          {
            keygen2_activity.showFailLog ();
          }
      }
  }
