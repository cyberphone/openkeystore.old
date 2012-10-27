package org.webpki.mobile.android.proxy.keygen2;

import java.io.IOException;
import java.math.BigInteger;

import java.util.Date;

import android.os.AsyncTask;

import org.webpki.android.keygen2.PlatformNegotiationResponseEncoder;
import org.webpki.android.sks.DeviceInfo;
import org.webpki.android.crypto.MacAlgorithms;
import org.webpki.android.crypto.SymKeySignerInterface;
import org.webpki.android.keygen2.KeyGen2URIs;
import org.webpki.android.keygen2.ProvisioningInitializationRequestDecoder;
import org.webpki.android.keygen2.ProvisioningInitializationResponseEncoder;
import org.webpki.android.sks.ProvisioningSession;

import org.webpki.mobile.android.proxy.BaseProxyActivity;
import org.webpki.mobile.android.proxy.InterruptedProtocolException;

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
			DeviceInfo dev_info = keygen2_activity.sks.getDeviceInfo();
			keygen2_activity.logOK ("Device Cert:\n" + dev_info.getCertificatePath()[0].toString());
        	PlatformNegotiationResponseEncoder platform_response = new PlatformNegotiationResponseEncoder (keygen2_activity.platform_request);
        	keygen2_activity.postXMLData(keygen2_activity.platform_request.getSubmitURL(), platform_response, false);
            
            publishProgress (BaseProxyActivity.PROGRESS_KEYGEN);
/*
            prov_sess_req = (ProvisioningInitializationRequestDecoder) client_xml_cache.parse (xmldata);
            Date client_time = new Date ();
            ProvisioningSession sess = 
                  sks.createProvisioningSession (prov_sess_req.getSessionKeyAlgorithm (),
                                                 platform_req.getPrivacyEnabledFlag(),
                                                 prov_sess_req.getServerSessionID (),
                                                 prov_sess_req.getServerEphemeralKey (),
                                                 prov_sess_req.getSubmitURL (), // IssuerURI
                                                 prov_sess_req.getKeyManagementKey (),
                                                 (int)(client_time.getTime () / 1000),
                                                 prov_sess_req.getSessionLifeTime (),
                                                 prov_sess_req.getSessionKeyLimit ());
            provisioning_handle = sess.getProvisioningHandle ();
            
            ProvisioningInitializationResponseEncoder prov_sess_response = 
                  new ProvisioningInitializationResponseEncoder (sess.getClientEphemeralKey (),
                                                                 prov_sess_req.getServerSessionID (),
                                                                 sess.getClientSessionID (),
                                                                 prov_sess_req.getServerTime (),
                                                                 client_time,
                                                                 sess.getAttestation (),
                                                                 platform_req.getPrivacyEnabledFlag () ? null : device_info.getCertificatePath ());
            if (https)
              {
                prov_sess_response.setServerCertificate (server_certificate);
              }

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

            prov_sess_response.signRequest (new SymKeySignerInterface ()
              {
                public MacAlgorithms getMacAlgorithm () throws IOException, GeneralSecurityException
                  {
                    return MacAlgorithms.HMAC_SHA256;
                  }

                public byte[] signData (byte[] data) throws IOException, GeneralSecurityException
                  {
                    return sks.signProvisioningSessionData (provisioning_handle, data);
                  }
              });
*/
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
