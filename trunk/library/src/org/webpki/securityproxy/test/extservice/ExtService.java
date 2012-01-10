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

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServlet;

import org.webpki.securityproxy.UploadEventHandler;
import org.webpki.securityproxy.UploadPayloadObject;
import org.webpki.securityproxy.test.intextcommon.IntExtCommon;
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

    MyUpload my_upload;

    @Override
    public void init (ServletConfig config) throws ServletException
      {
        super.init (config);
        IntExtCommon.getProxy ().addUploadEventHandler (this);
      }

    @Override
    public void destroy ()
      {
        IntExtCommon.getProxy ().deleteUploadEventHandler (this);
      }

    @Override
    public void handleUploadedData (UploadPayloadObject upload_payload)
      {
        my_upload = (MyUpload) upload_payload;
      }

    @Override
    public void doGet (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        response.setContentType ("text/html; charset=utf-8");
        response.setHeader ("Pragma", "No-Cache");
        response.setDateHeader ("EXPIRES", 0);
        response.getWriter ().print ("<html><head><meta http-equiv=\"refresh\" content=\"60\"></head>" +
                                     "<body>Last Proxy Upload: " +
                                     (my_upload == null ? "UNKNOWN" : new Date (my_upload.last_time_stamp).toString ()) +
                                     "</body></html>");
      }

    @Override
    public void doPost (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        response.setContentType ("text/html; charset=utf-8");
        response.setHeader ("Pragma", "No-Cache");
        response.setDateHeader ("EXPIRES", 0);
        response.getWriter ().print ("<html><head><meta http-equiv=\"refresh\" content=\"60\"></head>" +
                                     "<body>Last Proxy Upload: " +
                                     (my_upload == null ? "UNKNOWN" : new Date (my_upload.last_time_stamp).toString ()) +
                                     "</body></html>");
      }
  }
