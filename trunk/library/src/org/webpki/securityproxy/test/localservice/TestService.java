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
package org.webpki.securityproxy.test.localservice;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

import java.util.Date;
import java.util.Properties;
import java.util.logging.Logger;

import org.webpki.securityproxy.ProxyClient;
import org.webpki.securityproxy.ProxyRequestHandler;
import org.webpki.securityproxy.ProxyRequestInterface;
import org.webpki.securityproxy.ProxyResponseWrapper;

/**
 * Test service using the security proxy system. 
 */
public class TestService implements ProxyRequestHandler
  {
    private static Logger logger = Logger.getLogger (TestService.class.getCanonicalName ());
    
    private static final String DEFAULT_PROPERTIES     = "securityproxy.properties";
    private static final String PROPERTY_PROXY_URL     = "securityproxy.url";
    private static final String PROPERTY_MAX_WORKERS   = "securityproxy.max-workers";
    private static final String PROPERTY_CYCLE_TIME    = "securityproxy.cycle-time";
    private static final String PROPERTY_RETRY_TIMEOUT = "securityproxy.retry-timeout";
    private static final String PROPERTY_DEBUG         = "securityproxy.debug";

    ProxyClient proxy_client = new ProxyClient (this);
    
    Properties properties;

    private String getPropertyStringUnconditional (String name) throws IOException
      {
        String value = properties.getProperty (name);
        if (value == null)
          {
            throw new IOException ("Property: " + name + " missing");
          }
        return value;
      }

    private String getPropertyString (String name) throws IOException
      {
        return getPropertyStringUnconditional (name);
      }

    private int getPropertyInt (String name) throws IOException
      {
        return Integer.parseInt (getPropertyStringUnconditional (name));
      }

    private boolean getPropertyBoolean (String name) throws IOException
      {
        String flag = getPropertyStringUnconditional (name);
        if (flag.equals ("true")) return true;
        if (flag.equals ("false")) return false;
        throw new IOException ("Boolean syntax error: " + name);
      }

    @Override
    public ProxyResponseWrapper handleProxyRequest (ProxyRequestInterface proxy_req_wrapper)
      {
        // TODO Auto-generated method stub
        return null;
      }

    public static void main (String[] args)
      {
        try
          {
            new TestService ().start (args.length == 0 ? null : new FileInputStream (args[0]));
          }
        catch (IOException e)
          {
            e.printStackTrace();
          }
      }

    private void start (InputStream is) throws IOException
      {
        ////////////////////////////////////////////////////////////////////////////////////////////
        // Property fetching
        ////////////////////////////////////////////////////////////////////////////////////////////
        if (is == null)
          {
            is = this.getClass ().getResourceAsStream ("/META-INF/" + DEFAULT_PROPERTIES);
          }
        properties = new Properties ();
        properties.load (is);
        StringBuffer s = new StringBuffer ();
        for (String key : properties.stringPropertyNames ())
          {
            if (s.length () > 0)
              {
                s.append (", ");
              }
            s.append (key).append ('=').append (properties.getProperty (key));
          }
        logger.info ("Properties: " + s.toString ());

        ////////////////////////////////////////////////////////////////////////////////////////////
        // Initialization
        ////////////////////////////////////////////////////////////////////////////////////////////
        proxy_client.initProxy (getPropertyString (PROPERTY_PROXY_URL),
                                getPropertyInt (PROPERTY_MAX_WORKERS),
                                getPropertyInt (PROPERTY_CYCLE_TIME),
                                getPropertyInt (PROPERTY_RETRY_TIMEOUT),
                                getPropertyBoolean (PROPERTY_DEBUG));

        ////////////////////////////////////////////////////////////////////////////////////////////
        // Main loop
        ////////////////////////////////////////////////////////////////////////////////////////////
        while (true)
          {
            try
              {
                Thread.sleep (200000L);
                logger.info ("Uploaded Data");
                proxy_client.addUploadObject (new MyUpload (new Date ().getTime ()));
              }
            catch (InterruptedException e)
              {
                return;
              }
          }
      }

  }