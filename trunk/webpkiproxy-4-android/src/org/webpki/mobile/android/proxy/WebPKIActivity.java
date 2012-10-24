package org.webpki.mobile.android.proxy;

import java.io.IOException;

import java.net.URLDecoder;

import java.util.List;

import android.app.Activity;

import android.content.Intent;

import android.net.Uri;

/**
 * Class for taking care of "webpkiproxy://" XML protocol handlers
 */
public abstract class WebPKIActivity extends Activity 
{
	
	WebPKIInvocationData getWebPKIInvocationData () throws IOException
	{
		WebPKIInvocationData invocation_data = new WebPKIInvocationData ();
        Intent intent = getIntent ();
        Uri uri = intent.getData();
        if (uri == null)
        {
        	throw new IOException ("No URI");
        }
    	List<String> arg = uri.getQueryParameters("msg");
    	if (arg.isEmpty())
    	{
    		throw new IOException ("Missing \"msg\"");
    	}
    	invocation_data.xmldata = URLDecoder.decode(arg.get(0), "UTF-8").getBytes("UTF-8");
    	arg = uri.getQueryParameters("cookie");
    	if (!arg.isEmpty())
    	{
    		invocation_data.cookie = arg.get(0);
    	}
        return invocation_data;
	}
}
