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
package org.webpki.securityproxy;

import java.io.IOException;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServlet;


/**
 * Proxy channel servlet.
 * 
 * This is the actual proxy channel servlet that forwards client proxy requests
 * into proxy server logic.   It is configured by an external "web.xml" file.
 * 
 */
public class ProxyChannelServlet extends HttpServlet
  {
    private static final long serialVersionUID = 1L;
    
    private static final String PROXY_INSTANCE_PROPERTY = "proxy-instance-name";
    
    private ProxyServer proxy_server;

    @Override
    public void init (ServletConfig config) throws ServletException
      {
        super.init (config);
        String name = config.getInitParameter (PROXY_INSTANCE_PROPERTY);
        if (name == null)
          {
            throw new ServletException ("Servlet property '" + PROXY_INSTANCE_PROPERTY + "' is undefined!");
          }
        proxy_server = ProxyServer.getInstance (name);
      }

    @Override
    public void doGet (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        throw new IOException ("Not allowed");
      }

    @Override
    public void doPost (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        proxy_server.processProxyCall (request, response);
      }
  }
