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
package org.webpki.mobile.android.proxy;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;

import java.security.Security;

import java.security.cert.X509Certificate;

import java.text.SimpleDateFormat;

import java.util.Date;
import java.util.List;
import java.util.Vector;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.ProgressDialog;

import android.content.Context;
import android.content.DialogInterface;
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
    //////////////////////
    // Progress messages
    //////////////////////
    public static final String PROGRESS_INITIALIZING = "Initializing...";
    public static final String PROGRESS_SESSION      = "Creating session...";
    public static final String PROGRESS_KEYGEN       = "Generating keys...";
    public static final String PROGRESS_LOOKUP       = "Credential lookup...";
    public static final String PROGRESS_DEPLOY_CERTS = "Receiving credentials...";
    public static final String PROGRESS_FINAL        = "Finish message...";

    public static final String CONTINUE_EXECUTION    = "CONTINUE_EXECUTION";  // Return constant to AsyncTasks
    
    private static final String PERSISTENCE_SKS      = "SKS";  // SKS persistence file

    private XMLSchemaCache schema_cache;

    ProgressDialog progress_display;

    private StringBuffer logger = new StringBuffer ();

    private HTTPSWrapper https_wrapper;

    public SKSImplementation sks;

    private String redirect_url;
    
    private String abort_url;
    
    private boolean user_aborted;

    Vector<String> cookies = new Vector<String> ();

    public byte[] initial_request_data;
    
    public abstract String getProtocolName ();
    
    public abstract void abortTearDown ();

    public void conditionalAbort (final String message)
      {
        final BaseProxyActivity instance = this;
        AlertDialog.Builder alert_dialog = new AlertDialog.Builder (this)
            .setMessage ("Do you want to abort the current enrollment process?")
            .setCancelable (false)
            .setPositiveButton ("Yes", new DialogInterface.OnClickListener ()
          {
            public void onClick (DialogInterface dialog, int id)
              {
                // The user decided that this is not what he/she wants...
                dialog.cancel ();
                user_aborted = true;
                abortTearDown ();
                if (abort_url == null)
                  {
                    instance.finish ();
                  }
                else
                  {
                    launchBrowser (abort_url);
                  }
              }
          });
        alert_dialog.setNegativeButton ("No", new DialogInterface.OnClickListener ()
          {
            public void onClick (DialogInterface dialog, int id)
              {
                // The user apparently changed his/her mind and wants to continue...
                dialog.cancel ();
                if (message != null && progress_display != null)
                  {
                    progress_display = null;
                    showHeavyWork (message);
                  }
              }
          });

        // Create and show alert dialog
        alert_dialog.create ().show ();
      }

    public void setAbortURL (String abort_url)
      {
        this.abort_url = abort_url;
      }

    public void showHeavyWork (final String message)
      {
        if (!user_aborted)
          {
            if (progress_display == null)
              {
                progress_display = new ProgressDialog (this);
                progress_display.setMessage (message);
                progress_display.setCanceledOnTouchOutside (false);
                progress_display.setCancelable (false);
                progress_display.setButton (DialogInterface.BUTTON_POSITIVE, "Cancel", new DialogInterface.OnClickListener ()
                  {
                    public void onClick (DialogInterface dialog, int which)
                      {
                        conditionalAbort (message);
                      }
                  });
                progress_display.show ();
              }
            else
              {
                progress_display.setMessage (message);
              }
          }
      }

    public void noMoreWorkToDo ()
      {
        if (progress_display != null)
          {
            progress_display.dismiss ();
            progress_display = null;
          }
      }

    private void addOptionalCookies (String url) throws IOException
      {
        for (String cookie : cookies)
          {
            https_wrapper.setHeader ("Cookie", cookie);
          }
      }

    public boolean userHasAborted ()
      {
        return user_aborted;
      }

    public void initSKS ()
      {
        try
          {
            sks = (SKSImplementation) new ObjectInputStream (openFileInput(PERSISTENCE_SKS)).readObject ();
          }
        catch (Exception e)
          {
            Log.e (getProtocolName (), "Couldn't read SKS");
            sks = new SKSImplementation ();
          }
      }

    public void closeProxy ()
      {
        if (sks != null)
          {
            try
              {
                ObjectOutputStream oos = new ObjectOutputStream (openFileOutput(PERSISTENCE_SKS, Context.MODE_PRIVATE));
                oos.writeObject (sks);
                oos.close ();
              }
            catch (Exception e)
              {
                Log.e (getProtocolName (), "Couldn't write SKS");
              }
          }
        finish ();
      }

    public void launchBrowser (String url)
      {
        noMoreWorkToDo ();
        Intent intent = new Intent (Intent.ACTION_VIEW).setData (Uri.parse (url));
        startActivity (intent);
        closeProxy ();
      }

    public void postXMLData (String url,
                             XMLObjectWrapper xml_object,
                             boolean interrupt_expected) throws IOException, InterruptedProtocolException
      {
        logOK ("Writing \"" + xml_object.element () + "\" object to: " + url);
        addOptionalCookies (url);
        https_wrapper.makePostRequest (url, xml_object.writeXML ());
        if (https_wrapper.getResponseCode () == HttpStatus.SC_MOVED_TEMPORARILY)
          {
            if ((redirect_url = https_wrapper.getHeaderValue ("Location")) == null)
              {
                throw new IOException ("Malformed redirect");
              }
            if (!interrupt_expected)
              {
                Log.e (getProtocolName (), "Unexpected redirect");
                throw new InterruptedProtocolException ();
              }
          }
        else
          {
            if (https_wrapper.getResponseCode () != HttpStatus.SC_OK)
              {
                throw new IOException (https_wrapper.getResponseMessage ());
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

    public void logOK (String message)
      {
        logger.append (message).append ('\n');
      }

    public void logException (Exception e)
      {
        ByteArrayOutputStream baos = new ByteArrayOutputStream ();
        PrintWriter printer_writer = new PrintWriter (baos);
        e.printStackTrace (printer_writer);
        printer_writer.flush ();
        try
          {
            logger.append ("<font color=\"red\">").append (baos.toString ("UTF-8")).append ("</font>");
          }
        catch (IOException e1)
          {
          }
      }

    public void showFailLog ()
      {
        noMoreWorkToDo ();
        Intent intent = new Intent (this, FailLoggerActivity.class);
        intent.putExtra (FailLoggerActivity.LOG_MESSAGE, logger.toString ());
        startActivity (intent);
        closeProxy ();
      }

    public void addSchema (Class<? extends XMLObjectWrapper> wrapper_class) throws IOException
      {
        schema_cache.addWrapper (wrapper_class);
        logOK ("Added XML schema for: " + wrapper_class.getName ());
      }

    public XMLObjectWrapper parseXML (byte[] xmldata) throws IOException
      {
        XMLObjectWrapper xml_object = schema_cache.parse (xmldata);
        logOK ("Successfully read \"" + xml_object.element () + "\" object");
        return xml_object;
      }

    public XMLObjectWrapper parseResponse () throws IOException
      {
        return parseXML (https_wrapper.getData ());
      }

    public X509Certificate getServerCertificate ()
      {
        return https_wrapper.getServerCertificate ();
      }
    
    public void getProtocolInvocationData () throws Exception
      {
        logOK (getProtocolName () + " protocol run: " + new SimpleDateFormat ("yyyy-MM-dd' 'HH:mm:ss").format (new Date ()));
        https_wrapper = new HTTPSWrapper ();
        initSKS ();
        schema_cache = new XMLSchemaCache ();
        Intent intent = getIntent ();
        Uri uri = intent.getData ();
        if (uri == null)
          {
            throw new IOException ("No URI");
          }
        List<String> arg = uri.getQueryParameters ("url");
        if (arg.isEmpty ())
          {
            throw new IOException ("Missing initialization \"url\"");
          }
        String init_url = arg.get (0);
        arg = uri.getQueryParameters ("cookie");
        if (!arg.isEmpty ())
          {
            cookies.add (arg.get (0));
          }
        logOK ("Invocation URL=" + init_url + ", Cookie: " + (arg.isEmpty () ? "N/A" : cookies.elementAt (0)));
        addOptionalCookies (init_url);
        https_wrapper.makeGetRequest (init_url);
        if (https_wrapper.getResponseCode () != HttpStatus.SC_OK)
          {
            throw new IOException (https_wrapper.getResponseMessage ());
          }
        initial_request_data = https_wrapper.getData ();
        Security.insertProviderAt (new BouncyCastleProvider (), 1);
      }

    public void showAlert (String message)
      {
        AlertDialog.Builder alert_dialog = new AlertDialog.Builder (this)
            .setMessage (message).setCancelable (false)
            .setPositiveButton ("OK", new DialogInterface.OnClickListener ()
          {
            public void onClick (DialogInterface dialog, int id)
              {
                // Close the dialog box and do nothing
                dialog.cancel ();
              }
          });

        // Create and show alert dialog
        alert_dialog.create ().show ();
      }
  }
