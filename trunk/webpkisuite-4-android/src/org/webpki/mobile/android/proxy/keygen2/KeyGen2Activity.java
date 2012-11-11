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

import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import org.webpki.mobile.android.proxy.R;
import org.webpki.mobile.android.proxy.BaseProxyActivity;

import org.webpki.android.keygen2.KeyCreationRequestDecoder;
import org.webpki.android.keygen2.PlatformNegotiationRequestDecoder;
import org.webpki.android.keygen2.ProvisioningInitializationRequestDecoder;

public class KeyGen2Activity extends BaseProxyActivity
{
	static final String KEYGEN2 = "KeyGen2";

	TextView text_view;

	PlatformNegotiationRequestDecoder platform_request;
	
	ProvisioningInitializationRequestDecoder prov_init_request;
	
	KeyCreationRequestDecoder key_creation_request;
	
	
	int provisioning_handle;
	
    @Override
    public void onCreate(Bundle savedInstanceState)
    {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_keygen2);
        text_view = (TextView)findViewById(R.id.win);

        // Setup the "Cancel" button
        ((Button) findViewById(R.id.cancelButton)).setOnClickListener(new View.OnClickListener()
        {
            @Override
            public void onClick(View v)
            {
            	finish();
            }
        });
        
        showHeavyWork (PROGRESS_INITIALIZING);

        // Start of keygen2
        new KeyGen2ProtocolInit (this).execute();
    }

	@Override
	public String getProtocolName() 
	{
		return KEYGEN2;
	}

}
