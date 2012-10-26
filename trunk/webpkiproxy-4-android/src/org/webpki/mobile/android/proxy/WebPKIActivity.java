package org.webpki.mobile.android.proxy;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;

import java.net.URLDecoder;

import java.util.List;
import java.util.Vector;

import android.app.Activity;
import android.app.ProgressDialog;

import android.content.Intent;

import android.net.Uri;

import org.webpki.android.net.HTTPSWrapper;
import org.webpki.android.xml.XMLSchemaCache;

/**
 * Class for taking care of "webpkiproxy://" XML protocol handlers
 */
public abstract class WebPKIActivity extends Activity 
{
	static final String PROGRESS_INITIALIZING = "Initializing...";
	static final String PROGRESS_KEYGEN       = "Generating keys...";
	static final String PROGRESS_LOOKUP       = "Credential lookup...";
	static final String PROGRESS_DEPLOY_CERTS = "Receiving credentials...";
	static final String PROGRESS_FINAL        = "Finish message...";
	
	XMLSchemaCache schema_cache;
	
	ProgressDialog progress_display;
	
	StringBuffer logger = new StringBuffer ();
	
    HTTPSWrapper https_wrapper = new HTTPSWrapper ();
	
	Vector<String> cookies = new Vector<String> ();
	
	byte[] initial_request_data;

	public void showHeavyWork (String message)
	{
		progress_display = ProgressDialog.show(this, null, message);
	}

	public void noMoreWorkToDo ()
	{
		progress_display.dismiss();
	}

	public void updateWorkIndicator(String message)
	{
		progress_display.setMessage(message);
	}

	public void logOK (String message)
	{
		logger.append(message).append('\n');
	}

	public void addOptionalCookies () throws IOException
	{
		for (String cookie : cookies)
		{
			https_wrapper.setHeader("Cookie", cookie);
		}
	}

	public void logException (Exception e)
	{
    	ByteArrayOutputStream baos = new ByteArrayOutputStream ();
    	PrintWriter printer_writer = new PrintWriter (baos);
    	e.printStackTrace(printer_writer);
    	printer_writer.flush();
    	try 
    	{
    		logger.append("<font color=\"red\">").append(baos.toString("UTF-8")).append("</font>");
		} 
    	catch (IOException e1)
		{
		}
	}

	public void setOptionalCookie ()
	{
		
	}
	
	public void showFailLog() 
	{
        Intent intent = new Intent(this, FailLoggerActivity.class);
        intent.putExtra(FailLoggerActivity.LOG_MESSAGE, logger.toString());
        startActivity(intent);
        finish ();
	}
   
	public void getWebPKIInvocationData () throws IOException
	{
		schema_cache = new XMLSchemaCache ();
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
    	initial_request_data = URLDecoder.decode(arg.get(0), "UTF-8").getBytes("UTF-8");
    	arg = uri.getQueryParameters("cookie");
    	if (!arg.isEmpty())
    	{
    		cookies.add(arg.get(0));
    	}
        logOK ("Read Invocation, Cookie=" + (arg.isEmpty() ? "N/A" : cookies.elementAt(0)));
	}
}
