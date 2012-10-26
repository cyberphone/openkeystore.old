package org.webpki.mobile.android.proxy;

import android.os.Bundle;
import android.webkit.WebView;
import android.app.Activity;
import android.content.Intent;

public class FailLoggerActivity extends Activity {

    public static final String LOG_MESSAGE = "log";

	@Override
    public void onCreate(Bundle savedInstanceState)
	{
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_fail_logger);
        WebView log_view = (WebView)findViewById (R.id.faledData);
        Intent intent = getIntent();
        StringBuffer log_message = new StringBuffer ("<html><body><pre>");
        for (char c : intent.getStringExtra(LOG_MESSAGE).toCharArray())
        {
   			if (c == '\n')
			{
   				log_message.append("%0A");
			}
			else
			{
				log_message.append(c);
			}
        }
        log_view.loadData(log_message.append("</pre></body></html>").toString(), "text/html", null);
    }
}
