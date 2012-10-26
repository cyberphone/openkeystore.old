package org.webpki.mobile.android.proxy;

import java.io.IOException;
import java.security.Security;

import android.os.AsyncTask;

import android.widget.Button;
import android.widget.RelativeLayout;

import android.view.View;

import org.webpki.android.keygen2.PlatformNegotiationRequestDecoder;

import org.spongycastle.jce.provider.BouncyCastleProvider;

public class KeyGen2ProtocolInit extends AsyncTask<Void, String, Boolean> 
{
	private KeyGen2Activity keygen2_activity;
	
	public KeyGen2ProtocolInit (KeyGen2Activity keygen2_activity)
	{
		this.keygen2_activity = keygen2_activity;
	}

	@Override
	protected Boolean doInBackground(Void ...params)
	{
		try
		{
			keygen2_activity.getWebPKIInvocationData();	
			Security.insertProviderAt(new BouncyCastleProvider(), 1);
            keygen2_activity.schema_cache.addWrapper(PlatformNegotiationRequestDecoder.class);
            keygen2_activity.logOK ("Added XML Schemas");
            keygen2_activity.platform_request = (PlatformNegotiationRequestDecoder) keygen2_activity.schema_cache.parse(keygen2_activity.initial_request_data);
            keygen2_activity.logOK ("Decoded \"PlatformNegotiationRequest\"");
            return true;
		}
		catch (IOException e)
		{
            keygen2_activity.logException (e);
		}
		return false;
	}

	@Override
    protected void onPostExecute(Boolean success)
	{
		keygen2_activity.noMoreWorkToDo ();
		if (success)
		{
			Button ok = (Button) keygen2_activity.findViewById(R.id.OKbutton);
			ok.setVisibility(View.VISIBLE);

			View cancel = keygen2_activity.findViewById(R.id.cancelButton);
			RelativeLayout.LayoutParams layoutParams =(RelativeLayout.LayoutParams)cancel.getLayoutParams();
			layoutParams.addRule(RelativeLayout.ALIGN_PARENT_LEFT);
			cancel.setLayoutParams(layoutParams);

			ok.setOnClickListener(new View.OnClickListener()
	        {
	            @Override
	            public void onClick(View v)
	            {
	                keygen2_activity.showHeavyWork (WebPKIActivity.PROGRESS_LOOKUP);
	            	keygen2_activity.logOK("The user hit OK");
	            	new KeyGen2ProtocolRunner (keygen2_activity).execute();
	            }
	        });
		}
		else
		{
			keygen2_activity.showFailLog ();
		}
    }
}
