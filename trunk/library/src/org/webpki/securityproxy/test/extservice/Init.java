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
package org.webpki.securityproxy.test.extservice;

import java.util.Vector;
import java.util.logging.Logger;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

import org.webpki.securityproxy.ProxyServer;
import org.webpki.securityproxy.ProxyUploadHandler;
import org.webpki.securityproxy.ProxyUploadInterface;
import org.webpki.securityproxy.test.common.SampleUploadObject;


public class Init implements ServletContextListener, ProxyUploadHandler
  {
    private static Logger logger = Logger.getLogger (Init.class.getName ());
    
    static ProxyServer proxy_server;
    
    private static final int HISTORY = 20;

    static Vector<SampleUploadObject> uploads = new Vector<SampleUploadObject> ();

    @Override
    public void contextInitialized (ServletContextEvent event)
      {
        proxy_server = ProxyServer.getInstance ("testing-testing...");
        proxy_server.addUploadEventHandler (this);
      }

    @Override
    public void contextDestroyed (ServletContextEvent event)
      {
      }

    @Override
    public void handleUploadedData (ProxyUploadInterface upload_payload)
      {
        uploads.add (0, (SampleUploadObject) upload_payload);
        if (uploads.size () > HISTORY)
          {
            uploads.setSize (HISTORY);
          }
        logger.info ("Uploaded data reached service");
      }
  }