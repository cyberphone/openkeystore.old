package org.webpki.mobile.android.proxy;

import java.io.IOException;
import java.math.BigInteger;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

import org.webpki.android.keygen2.PlatformNegotiationResponseEncoder;

import android.content.Intent;
import android.net.Uri;
import android.os.AsyncTask;

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
        	PlatformNegotiationResponseEncoder platform_response = new PlatformNegotiationResponseEncoder (keygen2_activity.platform_request);
        	keygen2_activity.addOptionalCookies();
        	keygen2_activity.https_wrapper.makePostRequest(keygen2_activity.platform_request.getSubmitURL(), platform_response.writeXML());
            keygen2_activity.logOK ("Sent \"PlatformNegotiationResponse\"");
            KeyPairGenerator generator = KeyPairGenerator.getInstance ("EC");
            ECGenParameterSpec eccgen = new ECGenParameterSpec ("secp256r1");
            generator.initialize (eccgen, new SecureRandom ());
            KeyPair kp = generator.generateKeyPair ();
            
            publishProgress (WebPKIActivity.PROGRESS_KEYGEN);

            int rsa_key_size = 2048;
            BigInteger exponent = RSAKeyGenParameterSpec.F4;
            RSAKeyGenParameterSpec alg_par_spec = new RSAKeyGenParameterSpec (rsa_key_size, exponent);
            SecureRandom secure_random = new SecureRandom ();
            KeyPairGenerator kpg = KeyPairGenerator.getInstance ("RSA");
            kpg.initialize (alg_par_spec, secure_random);
            KeyPair key_pair = kpg.generateKeyPair ();

            if (keygen2_activity.https_wrapper.getResponseCode() == 302)
            {
            	keygen2_activity.logOK ("Found redirect=" + keygen2_activity.https_wrapper.getHeaderValue("Location"));
            	return keygen2_activity.https_wrapper.getHeaderValue("Location");
            }
            else
            {
            	throw new IOException ("Missing redirect");
            }
		}
		catch (GeneralSecurityException e)
		{
            keygen2_activity.logException (e);
		}
		catch (IOException e)
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
          	Intent intent = new Intent(Intent.ACTION_VIEW).setData(Uri.parse(result));
	        keygen2_activity.startActivity(intent);
	        keygen2_activity.finish ();
		}
		else
		{
			keygen2_activity.showFailLog ();
		}
	}
}