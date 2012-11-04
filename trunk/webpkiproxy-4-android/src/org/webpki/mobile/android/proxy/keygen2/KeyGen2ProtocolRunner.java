package org.webpki.mobile.android.proxy.keygen2;

import java.io.IOException;

import java.security.GeneralSecurityException;

import java.util.Date;

import android.os.AsyncTask;

import org.webpki.mobile.android.proxy.BaseProxyActivity;
import org.webpki.mobile.android.proxy.InterruptedProtocolException;

import org.webpki.android.util.ArrayUtil;

import org.webpki.android.crypto.MacAlgorithms;
import org.webpki.android.crypto.SymKeySignerInterface;
import org.webpki.android.crypto.HashAlgorithms;

import org.webpki.android.keygen2.KeyCreationRequestDecoder;
import org.webpki.android.keygen2.KeyCreationResponseEncoder;
import org.webpki.android.keygen2.PlatformNegotiationResponseEncoder;
import org.webpki.android.keygen2.ProvisioningInitializationRequestDecoder;
import org.webpki.android.keygen2.ProvisioningInitializationResponseEncoder;
import org.webpki.android.keygen2.ProvisioningFinalizationRequestDecoder;
import org.webpki.android.keygen2.ProvisioningFinalizationResponseEncoder;

import org.webpki.android.sks.ProvisioningSession;
import org.webpki.android.sks.DeviceInfo;
import org.webpki.android.sks.EnumeratedKey;
import org.webpki.android.sks.KeyAttributes;
import org.webpki.android.sks.EnumeratedProvisioningSession;
import org.webpki.android.sks.KeyData;
import org.webpki.android.sks.PatternRestriction;

/**
 * This part does the real work
 */
public class KeyGen2ProtocolRunner extends AsyncTask<Void, String, String> 
{
	private KeyGen2Activity keygen2_activity;
	
	public KeyGen2ProtocolRunner (KeyGen2Activity keygen2_activity)
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
                     post_operation.getClientSessionID () + "/" +
                     post_operation.getServerSessionID ());
            }
          if (old_provisioning_session.getClientSessionID ().equals(post_operation.getClientSessionID ()) &&
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
              if (ArrayUtil.compare (HashAlgorithms.SHA256.digest (ka.getCertificatePath ()[0].getEncoded ()), post_operation.getCertificateFingerprint ()))
                {
                  switch (post_operation.getPostOperation ())
                    {
                      case ProvisioningFinalizationRequestDecoder.PostOperation.CLONE_KEY_PROTECTION:
                    	  keygen2_activity.sks.postCloneKeyProtection (handle, ek.getKeyHandle (), post_operation.getAuthorization (), post_operation.getMAC ());
                        break;

                      case ProvisioningFinalizationRequestDecoder.PostOperation.UPDATE_KEY:
                    	  keygen2_activity.sks.postUpdateKey (handle, ek.getKeyHandle (),  post_operation.getAuthorization (), post_operation.getMAC ());
                        break;

                      case ProvisioningFinalizationRequestDecoder.PostOperation.UNLOCK_KEY:
                    	  keygen2_activity.sks.postUnlockKey (handle, ek.getKeyHandle (),  post_operation.getAuthorization (), post_operation.getMAC ());
                        break;

                      default:
                    	  keygen2_activity.sks.postDeleteKey (handle, ek.getKeyHandle (), post_operation.getAuthorization (), post_operation.getMAC ());
                    }
                  return;
                }
            }
        }
    }
	@Override
	protected String doInBackground(Void... params)
	{
		try
		{
			DeviceInfo device_info = keygen2_activity.sks.getDeviceInfo();
        	PlatformNegotiationResponseEncoder platform_response = new PlatformNegotiationResponseEncoder (keygen2_activity.platform_request);
        	keygen2_activity.postXMLData(keygen2_activity.platform_request.getSubmitURL(), platform_response, false);
            
            publishProgress (BaseProxyActivity.PROGRESS_SESSION);

            keygen2_activity.prov_init_request = (ProvisioningInitializationRequestDecoder) keygen2_activity.parseResponse ();
            Date client_time = new Date ();
            ProvisioningSession session = 
            	keygen2_activity.sks.createProvisioningSession (keygen2_activity.prov_init_request.getSessionKeyAlgorithm (),
                		  			                            keygen2_activity.platform_request.getPrivacyEnabledFlag(),
                		  			                            keygen2_activity.prov_init_request.getServerSessionID (),
                		  			                            keygen2_activity.prov_init_request.getServerEphemeralKey (),
                		  			                            keygen2_activity.prov_init_request.getSubmitURL (), // IssuerURI
                		  			                            keygen2_activity.prov_init_request.getKeyManagementKey (),
                		  			                            (int)(client_time.getTime () / 1000),
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
            
/* No specific attributes are supported yet (if ever...)
            for (String client_attribute : prov_sess_req.getClientAttributes ())
              {
                if (client_attribute.equals (KeyGen2URIs.CLIENT_ATTRIBUTES.IMEI_NUMBER))
                  {
                    prov_sess_response.setClientAttributeValue (client_attribute, "490154203237518");
                  }
                else if (client_attribute.equals (KeyGen2URIs.CLIENT_ATTRIBUTES.IP_ADDRESS))
                  {
                    prov_sess_response.setClientAttributeValue (client_attribute, "fe80::4465:62dc:5fa5:4766%10")
                                      .setClientAttributeValue (client_attribute, "192.168.0.202");
                  }
              }
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
            
            keygen2_activity.postXMLData(keygen2_activity.prov_init_request.getSubmitURL(), prov_sess_response, false);

            publishProgress (BaseProxyActivity.PROGRESS_KEYGEN);

            keygen2_activity.key_creation_request = (KeyCreationRequestDecoder) keygen2_activity.parseResponse ();
            KeyCreationResponseEncoder key_creation_response = new KeyCreationResponseEncoder (keygen2_activity.key_creation_request);

            int pin_policy_handle = 0;
            int puk_policy_handle = 0;
            for (KeyCreationRequestDecoder.KeyObject key : keygen2_activity.key_creation_request.getKeyObjects ())
	            {
	              byte[] pin_value = key.getPresetPIN ();
	              if (key.getPINPolicy () == null)
	                {
	                  pin_policy_handle = 0;
	                  puk_policy_handle = 0;
	                }
	              else
	                {
	                  if (key.getPINPolicy ().getUserDefinedFlag ())
	                    {
	                      pin_value = new byte[]{'1','2','3','4'};
	                    }
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
	                                                                   puk_policy.getMAC());
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
	                                                     pin_value,
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
	              key_creation_response.addPublicKey (key_data.getPublicKey (),
	                                              key_data.getAttestation (),
	                                              key.getID ());
	            }

            keygen2_activity.postXMLData(keygen2_activity.key_creation_request.getSubmitURL(), key_creation_response, false);

            publishProgress (BaseProxyActivity.PROGRESS_DEPLOY_CERTS);

            ProvisioningFinalizationRequestDecoder prov_final_request = (ProvisioningFinalizationRequestDecoder) keygen2_activity.parseResponse ();
			 /* 
			    Note: we could have used the saved provisioning_handle but that would not
			    work for certifications that are delayed.  The following code is working
			    for fully interactive and delayed scenarios by using SKS as state-holder
			 */
			 EnumeratedProvisioningSession eps = new EnumeratedProvisioningSession ();
			 while (true)
			   {
			     if ((eps = keygen2_activity.sks.enumerateProvisioningSessions (eps.getProvisioningHandle (), true)) == null)
			       {
			         throw new IOException ("Provisioning session not found:" + 
			                prov_final_request.getClientSessionID () + "/" +
			                prov_final_request.getServerSessionID ());
			       }
			     if (eps.getClientSessionID ().equals(prov_final_request.getClientSessionID ()) &&
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
			     int key_handle = keygen2_activity.sks.getKeyHandle (eps.getProvisioningHandle (), key.getID ());
			     keygen2_activity.sks.setCertificatePath (key_handle, key.getCertificatePath (), key.getMAC ());
			
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
            keygen2_activity.postXMLData(prov_final_request.getSubmitURL(),
			     new ProvisioningFinalizationResponseEncoder (prov_final_request,
			    		 keygen2_activity.sks.closeProvisioningSession (eps.getProvisioningHandle (),
			                                                                                prov_final_request.getCloseSessionNonce (),
		                                                                                prov_final_request.getCloseSessionMAC ())), true);
            return keygen2_activity.getRedirectURL();
		}
		catch (InterruptedProtocolException e)
		{
			return keygen2_activity.getRedirectURL();
		}
		catch (Exception e)
		{
            keygen2_activity.logException (e);
		}
		return null;
	}

	@Override
	public void onProgressUpdate(String... message)
	{
		keygen2_activity.updateWorkIndicator (message[0]);
	}

	@Override
    protected void onPostExecute(String result)
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
