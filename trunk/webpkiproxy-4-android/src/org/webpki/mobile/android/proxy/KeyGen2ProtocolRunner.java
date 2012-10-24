package org.webpki.mobile.android.proxy;

import java.io.IOException;

import android.os.AsyncTask;

import android.util.Log;

import org.webpki.android.keygen2.PlatformNegotiationRequestDecoder;
import org.webpki.android.keygen2.PlatformNegotiationResponseEncoder;

import org.webpki.android.net.HTTPSWrapper;

import org.webpki.android.xml.XMLSchemaCache;


public class KeyGen2ProtocolRunner extends AsyncTask<Void, String, String> 
{
	private KeyGen2Activity keygen2_activity;
	
	private static final String KG2 = "KeyGen2";
	
	public KeyGen2ProtocolRunner (KeyGen2Activity keygen2_activity)
	{
		this.keygen2_activity = keygen2_activity;
	}

	@Override
	protected String doInBackground(Void ...params)
	{
		try
		{
			WebPKIInvocationData invocation_data = keygen2_activity.getWebPKIInvocationData();	
            publishProgress ("Read Invocation, Cookie=" + invocation_data.cookie == null ? "N/A" : invocation_data.cookie);
			XMLSchemaCache schema_cache = new XMLSchemaCache ();
			schema_cache.addWrapper(PlatformNegotiationRequestDecoder.class);
            publishProgress ("Added XML Schemas");
        	PlatformNegotiationRequestDecoder platform_request = (PlatformNegotiationRequestDecoder) schema_cache.parse(invocation_data.xmldata);
            publishProgress ("Decoded \"PlatformNegotiationRequest\"");
        	PlatformNegotiationResponseEncoder platform_response = new PlatformNegotiationResponseEncoder (platform_request);
            HTTPSWrapper wrap = new HTTPSWrapper ();
        	if (invocation_data.cookie != null)
        	{
        		wrap.setHeader("Cookie", invocation_data.cookie);
        	}
            wrap.makePostRequest(platform_request.getSubmitURL(), platform_response.writeXML());
            publishProgress ("Sent \"PlatformNegotiationResponse\"");
		}
		catch (IOException e)
		{
			Log.e(KG2, e.getMessage());
            publishProgress ("Failed: " + e.getLocalizedMessage());
		}
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	protected void onProgressUpdate(String... progress)
	{
		keygen2_activity.text_view.append("\n" + progress[0]);
	}
}
