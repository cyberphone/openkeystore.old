package org.webpki.mobile.android.proxy;

import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import org.webpki.android.keygen2.PlatformNegotiationRequestDecoder;


public class KeyGen2Activity extends WebPKIActivity
{
	TextView text_view;

	PlatformNegotiationRequestDecoder platform_request;
	
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

}
