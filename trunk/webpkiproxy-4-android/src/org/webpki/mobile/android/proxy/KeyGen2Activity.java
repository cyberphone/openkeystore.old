package org.webpki.mobile.android.proxy;

import android.os.Bundle;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.TextView;

public class KeyGen2Activity extends WebPKIActivity
{
	TextView text_view;

	KeyGen2ProtocolRunner kg2_prot_run;
	
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_keygen2);
        text_view = (TextView)findViewById(R.id.win);

        // Start of keygen2
        kg2_prot_run = new KeyGen2ProtocolRunner (this);
        ((Button) findViewById(R.id.OKbutton)).setOnClickListener(new OnClickListener()
        {
            @Override
            public void onClick(View v)
            {
            	kg2_prot_run.execute();
            }
        });

        // Cancel
        ((Button) findViewById(R.id.cancelButton)).setOnClickListener(new OnClickListener()
        {
            @Override
            public void onClick(View v)
            {
            	finish();
            }
        });
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.activity_key_gen2, menu);
        return true;
    }

    
}
