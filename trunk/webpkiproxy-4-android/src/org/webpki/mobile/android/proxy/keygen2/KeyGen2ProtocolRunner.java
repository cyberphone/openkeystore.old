package org.webpki.mobile.android.proxy.keygen2;

import java.io.IOException;

import java.security.GeneralSecurityException;

import java.util.Date;

import android.os.AsyncTask;

import org.webpki.mobile.android.proxy.BaseProxyActivity;
import org.webpki.mobile.android.proxy.InterruptedProtocolException;

import org.webpki.android.crypto.MacAlgorithms;
import org.webpki.android.crypto.SymKeySignerInterface;

import org.webpki.android.keygen2.PlatformNegotiationResponseEncoder;
import org.webpki.android.keygen2.ProvisioningInitializationRequestDecoder;
import org.webpki.android.keygen2.ProvisioningInitializationResponseEncoder;

import org.webpki.android.sks.ProvisioningSession;
import org.webpki.android.sks.DeviceInfo;

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

	@Override
	protected String doInBackground(Void... params)
	{
		try
		{
			DeviceInfo device_info = keygen2_activity.sks.getDeviceInfo();
        	PlatformNegotiationResponseEncoder platform_response = new PlatformNegotiationResponseEncoder (keygen2_activity.platform_request);
        	keygen2_activity.postXMLData(keygen2_activity.platform_request.getSubmitURL(), platform_response, false);
            
            publishProgress (BaseProxyActivity.PROGRESS_SESSION);

            keygen2_activity.prov_sess_req = (ProvisioningInitializationRequestDecoder) keygen2_activity.parseResponse ();
            Date client_time = new Date ();
            ProvisioningSession session = 
            	keygen2_activity.sks.createProvisioningSession (keygen2_activity.prov_sess_req.getSessionKeyAlgorithm (),
                		  			                            keygen2_activity.platform_request.getPrivacyEnabledFlag(),
                		  			                            keygen2_activity.prov_sess_req.getServerSessionID (),
                		  			                            keygen2_activity.prov_sess_req.getServerEphemeralKey (),
                		  			                            keygen2_activity.prov_sess_req.getSubmitURL (), // IssuerURI
                		  			                            keygen2_activity.prov_sess_req.getKeyManagementKey (),
                		  			                            (int)(client_time.getTime () / 1000),
                		  			                            keygen2_activity.prov_sess_req.getSessionLifeTime (),
                		  			                            keygen2_activity.prov_sess_req.getSessionKeyLimit ());

            keygen2_activity.provisioning_handle = session.getProvisioningHandle ();
            
            ProvisioningInitializationResponseEncoder prov_sess_response = 
                  new ProvisioningInitializationResponseEncoder (session.getClientEphemeralKey (),
                		                                         keygen2_activity.prov_sess_req.getServerSessionID (),
                		                                         session.getClientSessionID (),
                		                                         keygen2_activity.prov_sess_req.getServerTime (),
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
            
            keygen2_activity.postXMLData(keygen2_activity.prov_sess_req.getSubmitURL(), prov_sess_response, true);

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
