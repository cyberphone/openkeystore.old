package org.webpki.mobile.android.proxy;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;

import java.net.URLDecoder;

import java.security.Security;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Vector;

import android.app.Activity;
import android.app.ProgressDialog;

import android.content.Intent;

import android.net.Uri;
import android.util.Log;

import org.apache.http.HttpStatus;

import org.webpki.android.net.HTTPSWrapper;
import org.webpki.android.xml.XMLSchemaCache;
import org.webpki.android.xml.XMLObjectWrapper;
import org.webpki.mobile.android.sks.SKSImplementation;

import org.spongycastle.jce.provider.BouncyCastleProvider;

/**
 * Class for taking care of "webpkiproxy://" XML protocol handlers
 */
public abstract class BaseProxyActivity extends Activity 
{
	public static final String PROGRESS_INITIALIZING = "Initializing...";
	public static final String PROGRESS_SESSION      = "Creating session...";
	public static final String PROGRESS_KEYGEN       = "Generating keys...";
	public static final String PROGRESS_LOOKUP       = "Credential lookup...";
	public static final String PROGRESS_DEPLOY_CERTS = "Receiving credentials...";
	public static final String PROGRESS_FINAL        = "Finish message...";
	
	private XMLSchemaCache schema_cache;
	
	ProgressDialog progress_display;
	
	private StringBuffer logger = new StringBuffer ();
	
	private HTTPSWrapper https_wrapper = new HTTPSWrapper ();
	
	public SKSImplementation sks = new SKSImplementation ();
	
	private String redirect_url;
	
	Vector<String> cookies = new Vector<String> ();
	
	public byte[] initial_request_data;

	public void showHeavyWork (String message)
	{
		progress_display = ProgressDialog.show(this, null, message);
	}

	private void addOptionalCookies (String url) throws IOException
	{
		for (String cookie : cookies)
		{
			https_wrapper.setHeader("Cookie", cookie);
		}
	}
	
	public void launchBrowser (String url)
	{
      	Intent intent = new Intent(Intent.ACTION_VIEW).setData(Uri.parse(url));
        startActivity(intent);
        finish ();
	}

	public void postXMLData (String url, XMLObjectWrapper xml_object, boolean interrupt_expected) throws IOException, InterruptedProtocolException
	{
		logOK ("Writing \"" + xml_object.element() + "\" object to: " + url);
		addOptionalCookies (url);
		https_wrapper.makePostRequest(url, xml_object.writeXML());
		if (https_wrapper.getResponseCode() == HttpStatus.SC_MOVED_TEMPORARILY)
		{
			if ((redirect_url = https_wrapper.getHeaderValue("Location")) == null)
			{
				throw new IOException ("Malformed redirect");
			}
			if (!interrupt_expected)
			{
				Log.e(getProtocolName (), "Unexpected redirect");
				throw new InterruptedProtocolException ();
			}
		}
		else
		{
			 if (https_wrapper.getResponseCode() != HttpStatus.SC_OK)
			 {
				 throw new IOException (https_wrapper.getResponseMessage());
			 }
			 if (interrupt_expected)
			 {
				 throw new IOException ("Redirect expected");
			 }
		}
	}

	public String getRedirectURL ()
	{
		return redirect_url;
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

	public abstract String getProtocolName ();

	public void showFailLog() 
	{
        Intent intent = new Intent(this, FailLoggerActivity.class);
        intent.putExtra(FailLoggerActivity.LOG_MESSAGE, logger.toString());
        startActivity(intent);
        finish ();
	}

	public void addSchema (Class<? extends XMLObjectWrapper> wrapper_class) throws IOException
	{
		schema_cache.addWrapper(wrapper_class);
		logOK ("Added XML schema for: " + wrapper_class.getName());
	}
   
    public XMLObjectWrapper parseXML (byte[] xmldata) throws IOException
    {
    	XMLObjectWrapper xml_object = schema_cache.parse(xmldata);
    	logOK("Successfully read \"" + xml_object.element() + "\" object");
    	return xml_object;
    }

    public XMLObjectWrapper parseResponse () throws IOException
    {
    	return parseXML (https_wrapper.getData());
    }

    public X509Certificate getServerCertificate ()
    {
    	return https_wrapper.getServerCertificate();
    }

    public void getProtocolInvocationData () throws IOException
	{
    	logOK (getProtocolName () + " protocol run: " + new SimpleDateFormat ("yyyy-MM-dd' 'HH:mm:ss' UTC'").format (new Date ()));
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
        logOK ("Invocation read, Cookie: " + (arg.isEmpty() ? "N/A" : cookies.elementAt(0)));
		Security.insertProviderAt(new BouncyCastleProvider(), 1);
	}
}
