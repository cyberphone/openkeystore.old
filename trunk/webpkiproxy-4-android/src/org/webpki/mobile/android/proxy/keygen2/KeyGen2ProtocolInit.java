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
			View cancel = keygen2_activity.findViewById(R.id.cancelButton);
			RelativeLayout.LayoutParams cancel_layout =(RelativeLayout.LayoutParams)cancel.getLayoutParams();
			cancel_layout.addRule(RelativeLayout.ALIGN_PARENT_LEFT);
			cancel.setLayoutParams(cancel_layout);

			Button ok = (Button) keygen2_activity.findViewById(R.id.OKbutton);
			ok.setVisibility(View.VISIBLE);
			ok.setOnClickListener(new View.OnClickListener()
	        {
	            @Override
	            public void onClick(View v)
	            {
	    			Button ok = (Button) keygen2_activity.findViewById(R.id.OKbutton);
	    			ok.setVisibility(View.INVISIBLE);

	    			View cancel = keygen2_activity.findViewById(R.id.cancelButton);
	    			RelativeLayout.LayoutParams cancel_layout =(RelativeLayout.LayoutParams)cancel.getLayoutParams();
	    			cancel_layout.addRule(RelativeLayout.ALIGN_PARENT_LEFT, 0);
	    			cancel.setLayoutParams(cancel_layout);

	    			keygen2_activity.showHeavyWork (BaseProxyActivity.PROGRESS_LOOKUP);
	            	keygen2_activity.logOK("The user hit OK");
	            	new KeyGen2SessionCreation (keygen2_activity).execute();
	            }
	        });
		}
		else
		{
			keygen2_activity.showFailLog ();
		}
    }
}
