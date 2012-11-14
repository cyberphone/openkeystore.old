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

import android.os.AsyncTask;

import org.webpki.mobile.android.proxy.BaseProxyActivity;
import org.webpki.mobile.android.proxy.InterruptedProtocolException;

import org.webpki.android.util.ArrayUtil;

import org.webpki.android.crypto.HashAlgorithms;

import org.webpki.android.keygen2.KeyCreationRequestDecoder;
import org.webpki.android.keygen2.KeyCreationResponseEncoder;
import org.webpki.android.keygen2.ProvisioningFinalizationRequestDecoder;
import org.webpki.android.keygen2.ProvisioningFinalizationResponseEncoder;

import org.webpki.android.sks.EnumeratedKey;
import org.webpki.android.sks.KeyAttributes;
import org.webpki.android.sks.EnumeratedProvisioningSession;
import org.webpki.android.sks.KeyData;
import org.webpki.android.sks.PatternRestriction;

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
                                       post_operation.getClientSessionID () + 
                                       "/" +
                                       post_operation.getServerSessionID ());
              }
            if (old_provisioning_session.getClientSessionID ().equals (post_operation.getClientSessionID ()) &&
                old_provisioning_session.getServerSessionID ().equals (post_operation.getServerSessionID ()))
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
                                                                       post_operation.getMAC ());
                          break;

                        case ProvisioningFinalizationRequestDecoder.PostOperation.UPDATE_KEY:
                          keygen2_activity.sks.postUpdateKey (handle,
                                                              ek.getKeyHandle (),
                                                              post_operation.getAuthorization (),
                                                              post_operation.getMAC ());
                          break;

                        case ProvisioningFinalizationRequestDecoder.PostOperation.UNLOCK_KEY:
                          keygen2_activity.sks.postUnlockKey (handle,
                                                              ek.getKeyHandle (),
                                                              post_operation.getAuthorization (),
                                                              post_operation.getMAC ());
                          break;

                        default:
                          keygen2_activity.sks.postDeleteKey (handle,
                                                              ek.getKeyHandle (),
                                                              post_operation.getAuthorization (),
                                                              post_operation.getMAC ());
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
                            puk_policy_handle = keygen2_activity.sks.createPUKPolicy (keygen2_activity.provisioning_handle,
                                                                                      puk_policy.getID (),
                                                                                      puk_policy.getEncryptedValue (),
                                                                                      puk_policy.getFormat ().getSKSValue (),
                                                                                      puk_policy.getRetryLimit (),
                                                                                      puk_policy.getMAC ());
                          }
                        KeyCreationRequestDecoder.PINPolicy pin_policy = key.getPINPolicy ();
                        pin_policy_handle = keygen2_activity.sks.createPINPolicy (keygen2_activity.provisioning_handle,
                                                                                  pin_policy.getID (),
                                                                                  puk_policy_handle,
                                                                                  pin_policy.getUserDefinedFlag (),
                                                                                  pin_policy.getUserModifiableFlag (),
                                                                                  pin_policy.getFormat ().getSKSValue (),
                                                                                  pin_policy.getRetryLimit (),
                                                                                  pin_policy.getGrouping ().getSKSValue (),
                                                                                  PatternRestriction.getSKSValue (pin_policy.getPatternRestrictions ()),
                                                                                  pin_policy.getMinLength (),
                                                                                  pin_policy.getMaxLength (),
                                                                                  pin_policy.getInputMethod ().getSKSValue (),
                                                                                  pin_policy.getMAC ());
                      }
                  }
                KeyData key_data = keygen2_activity.sks.createKeyEntry (keygen2_activity.provisioning_handle,
                                                                        key.getID (),
                                                                        keygen2_activity.key_creation_request.getAlgorithm (),
                                                                        key.getServerSeed (),
                                                                        key.isDevicePINProtected (),
                                                                        pin_policy_handle,
                                                                        key.getSKSPINValue (),
                                                                        key.getEnablePINCachingFlag (),
                                                                        key.getBiometricProtection ().getSKSValue (),
                                                                        key.getExportProtection ().getSKSValue (),
                                                                        key.getDeleteProtection ().getSKSValue (),
                                                                        key.getAppUsage ().getSKSValue (),
                                                                        key.getFriendlyName (),
                                                                        key.getKeySpecifier ().getKeyAlgorithm ().getURI (), 
                                                                        key.getKeySpecifier ().getParameters (),
                                                                        key.getEndorsedAlgorithms (),
                                                                        key.getMAC ());
                key_creation_response.addPublicKey (key_data.getPublicKey (), key_data.getAttestation (), key.getID ());
              }

            keygen2_activity.postXMLData (keygen2_activity.key_creation_request.getSubmitURL (), key_creation_response, false);

            publishProgress (BaseProxyActivity.PROGRESS_DEPLOY_CERTS);

            ProvisioningFinalizationRequestDecoder prov_final_request = (ProvisioningFinalizationRequestDecoder) keygen2_activity.parseResponse ();

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
                                           prov_final_request.getClientSessionID () +
                                           "/" +
                                           prov_final_request.getServerSessionID ());
                  }
                if (eps.getClientSessionID ().equals (prov_final_request.getClientSessionID ()) &&
                    eps.getServerSessionID ().equals (prov_final_request.getServerSessionID ()))
                  {
                    break;
                  }
              }

            //////////////////////////////////////////////////////////////////////////
            // Final check, do these keys match the request?
            //////////////////////////////////////////////////////////////////////////
            for (ProvisioningFinalizationRequestDecoder.DeployedKeyEntry key : prov_final_request.getDeployedKeyEntrys ())
              {
                int key_handle = keygen2_activity.sks.getKeyHandle (eps.getProvisioningHandle (),
                                                                    key.getID ());
                keygen2_activity.sks.setCertificatePath (key_handle,
                                                         key.getCertificatePath (),
                                                         key.getMAC ());

                //////////////////////////////////////////////////////////////////////////
                // There may be a symmetric key
                //////////////////////////////////////////////////////////////////////////
                if (key.getEncryptedSymmetricKey () != null)
                  {
                    keygen2_activity.sks.importSymmetricKey (key_handle,
                                                             key.getEncryptedSymmetricKey (),
                                                             key.getSymmetricKeyMac ());
                  }

                //////////////////////////////////////////////////////////////////////////
                // There may be a private key
                //////////////////////////////////////////////////////////////////////////
                if (key.getEncryptedPrivateKey () != null)
                  {
                    keygen2_activity.sks.importPrivateKey (key_handle,
                                                           key.getEncryptedPrivateKey (),
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
                                                       extension.getMAC ());
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
            keygen2_activity.postXMLData (prov_final_request.getSubmitURL (),
                                          new ProvisioningFinalizationResponseEncoder (prov_final_request,
                                                                                       keygen2_activity.sks.closeProvisioningSession (eps.getProvisioningHandle (),
                                                                                       prov_final_request.getCloseSessionNonce (),
                                                                                       prov_final_request.getCloseSessionMAC ())),
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
        keygen2_activity.noMoreWorkToDo ();
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
