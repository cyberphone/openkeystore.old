package org.webpki.mobile.android.proxy;

import android.app.ProgressDialog;
import android.os.Bundle;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.TextView;

import org.webpki.android.keygen2.PlatformNegotiationRequestDecoder;

import org.webpki.android.xml.XMLSchemaCache;


public class KeyGen2Activity extends WebPKIActivity
{
	TextView text_view;

	PlatformNegotiationRequestDecoder platform_request;
	
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_keygen2);
        text_view = (TextView)findViewById(R.id.win);

        // Setup the "Cancel" button
        ((Button) findViewById(R.id.cancelButton)).setOnClickListener(new OnClickListener()
        {
            @Override
            public void onClick(View v)
            {
            	finish();
            }
        });
        
        showHeavyWork ();

        // Start of keygen2
        new KeyGen2ProtocolInit (this).execute();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.activity_key_gen2, menu);
        return true;
    }

    
}
