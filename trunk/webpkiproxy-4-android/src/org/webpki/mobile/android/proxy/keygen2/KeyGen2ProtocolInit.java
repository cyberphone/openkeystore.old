package org.webpki.mobile.android.proxy.keygen2;

import android.os.AsyncTask;

import android.widget.Button;
import android.widget.RelativeLayout;

import android.view.View;

import org.webpki.mobile.android.proxy.R;
import org.webpki.mobile.android.proxy.BaseProxyActivity;

import org.webpki.android.keygen2.CredentialDiscoveryRequestDecoder;
import org.webpki.android.keygen2.KeyCreationRequestDecoder;
import org.webpki.android.keygen2.PlatformNegotiationRequestDecoder;
import org.webpki.android.keygen2.ProvisioningFinalizationRequestDecoder;
import org.webpki.android.keygen2.ProvisioningInitializationRequestDecoder;

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
			keygen2_activity.getProtocolInvocationData();	
            keygen2_activity.addSchema(PlatformNegotiationRequestDecoder.class);
            keygen2_activity.addSchema(ProvisioningInitializationRequestDecoder.class);
            keygen2_activity.addSchema(KeyCreationRequestDecoder.class);
            keygen2_activity.addSchema(CredentialDiscoveryRequestDecoder.class);
            keygen2_activity.addSchema(ProvisioningFinalizationRequestDecoder.class);
            keygen2_activity.platform_request = (PlatformNegotiationRequestDecoder) keygen2_activity.parseXML(keygen2_activity.initial_request_data);
            return true;
		}
		catch (Exception e)
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
	                keygen2_activity.showHeavyWork (BaseProxyActivity.PROGRESS_LOOKUP);
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
