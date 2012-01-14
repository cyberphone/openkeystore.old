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

import java.io.IOException;

import java.util.Date;
import java.util.Vector;
import java.util.logging.Logger;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServlet;

import org.webpki.securityproxy.ProxyServer;
import org.webpki.securityproxy.UploadEventHandler;
import org.webpki.securityproxy.UploadPayloadObject;

import org.webpki.securityproxy.test.localservice.MyUpload;

/**
 * External security proxy service.
 * 
 * This is the external service.
 * 
 */
public class ExtService extends HttpServlet implements UploadEventHandler
  {
    private static final long serialVersionUID = 1L;

    private static final int HISTORY = 20;

    private static Logger logger = Logger.getLogger (ExtService.class.getName ());

    private ProxyServer proxy_server;
    
    private Vector<MyUpload> uploads = new Vector<MyUpload> ();

    @Override
    public void init (ServletConfig config) throws ServletException
      {
        super.init (config);
        proxy_server = ProxyServer.getInstance ("testing-testing...");
        proxy_server.addUploadEventHandler (this);
      }

    @Override
    public void destroy ()
      {
        proxy_server.deleteUploadEventHandler (this);
      }

    @Override
    public void handleUploadedData (UploadPayloadObject upload_payload)
      {
        uploads.add (0, (MyUpload) upload_payload);
        if (uploads.size () > HISTORY)
          {
            uploads.setSize (HISTORY);
          }
        logger.info ("Uploaded data reached service");
      }

    @Override
    public void doGet (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        response.setContentType ("text/html; charset=utf-8");
        response.setHeader ("Pragma", "No-Cache");
        response.setDateHeader ("EXPIRES", 0);
        StringBuffer s = new StringBuffer ("<html><head><meta http-equiv=\"refresh\" content=\"20\"></head><body>");
        if (proxy_server.isReady ())
          {
            s.append ("Last Proxy Upload: ");
            int l = uploads.size ();
            if (l == 0)
              {
                s.append ("UNKNOWN");
              }
            else
              {
                printElem (s, 0);
                for (int q = 1; q < l; q++)
                  {
                    s.append ("<br>Previous Proxy Upload: ");
                    printElem (s, q);
                  }
              }
          }
        else
          {
            s.append ("PROXY SERVER NOT READY"); 
          }
        response.getWriter ().print (s.append ("</body></html>").toString ());
      }

    private void printElem (StringBuffer s, int index)
      {
        s.append (new Date (uploads.elementAt (index).getTimeStamp ()).toString ());
      }

    @Override
    public void doPost (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        response.setContentType ("text/html; charset=utf-8");
        response.setHeader ("Pragma", "No-Cache");
        response.setDateHeader ("EXPIRES", 0);
        response.getWriter ().print ("<html><head><meta http-equiv=\"refresh\" content=\"20\"></head>" +
                                     "<body>hi</body></html>");
      }
  }
