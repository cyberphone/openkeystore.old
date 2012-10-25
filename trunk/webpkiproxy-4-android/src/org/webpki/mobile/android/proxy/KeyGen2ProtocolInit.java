package org.webpki.mobile.android.proxy;

import java.io.IOException;

import android.content.Intent;
import android.net.Uri;
import android.os.AsyncTask;

import android.util.Log;
import android.widget.Button;
import android.widget.RelativeLayout;

import android.view.View;
import android.view.View.OnClickListener;


import org.webpki.android.keygen2.PlatformNegotiationRequestDecoder;
import org.webpki.android.keygen2.PlatformNegotiationResponseEncoder;

import org.webpki.android.net.HTTPSWrapper;

import org.webpki.android.xml.XMLSchemaCache;


public class KeyGen2ProtocolInit extends AsyncTask<Void, String, String> 
{
	private KeyGen2Activity keygen2_activity;
	
	private static final String KG2 = "KeyGen2";
	
	public KeyGen2ProtocolInit (KeyGen2Activity keygen2_activity)
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
            keygen2_activity.schema_cache = new XMLSchemaCache ();
            keygen2_activity.schema_cache.addWrapper(PlatformNegotiationRequestDecoder.class);
            publishProgress ("Added XML Schemas");
            keygen2_activity.platform_request = (PlatformNegotiationRequestDecoder) keygen2_activity.schema_cache.parse(invocation_data.xmldata);
            publishProgress ("Decoded \"PlatformNegotiationRequest\"");
        	PlatformNegotiationResponseEncoder platform_response = new PlatformNegotiationResponseEncoder (keygen2_activity.platform_request);
            HTTPSWrapper wrap = new HTTPSWrapper ();
        	if (invocation_data.cookie != null)
        	{
        		wrap.setHeader("Cookie", invocation_data.cookie);
        	}
            wrap.makePostRequest(keygen2_activity.platform_request.getSubmitURL(), platform_response.writeXML());
            publishProgress ("Sent \"PlatformNegotiationResponse\"");
            if (wrap.getResponseCode() == 302)
            {
            	publishProgress ("Found redirect=" + wrap.getHeaderValue("Location"));
            	return wrap.getHeaderValue("Location");
            }
            else
            {
            	throw new IOException ("Missing redirect");
            }
		}
		catch (IOException e)
		{
            publishProgress ("Failed: " + e.getLocalizedMessage());
		}
		return null;
	}

	@Override
	protected void onProgressUpdate(String... progress)
	{
		Log.e(KG2, progress[0]);
		keygen2_activity.text_view.append("\n" + progress[0]);
	}

	@Override
    protected void onPostExecute(String result)
	{
		if (result != null)
		{
			keygen2_activity.noMoreWorkToDo ();

			Button ok = (Button) keygen2_activity.findViewById(R.id.OKbutton);
			ok.setVisibility(View.VISIBLE);
			ok.setTag(result);

			View cancel = keygen2_activity.findViewById(R.id.cancelButton);
			RelativeLayout.LayoutParams layoutParams =(RelativeLayout.LayoutParams)cancel.getLayoutParams();
			layoutParams.addRule(RelativeLayout.ALIGN_PARENT_LEFT);
			cancel.setLayoutParams(layoutParams);

			ok.setOnClickListener(new OnClickListener()
	        {
	            @Override
	            public void onClick(View v)
	            {
	    			Intent intent = new Intent(Intent.ACTION_VIEW).setData(Uri.parse((String) v.getTag()));
	    			keygen2_activity.startActivity(intent);
	            }
	        });
		}
    }
}
