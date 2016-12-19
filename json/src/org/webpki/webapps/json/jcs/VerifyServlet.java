/*
 *  Copyright 2006-2014 WebPKI.org (http://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.webpki.webapps.json.jcs;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.util.ArrayUtil;
import org.webpki.util.Base64URL;

public class VerifyServlet extends HttpServlet
  {
    private static final long serialVersionUID = 1L;
    
    String signature;
    
    @Override
    public
    void init (ServletConfig config)
      {
        try
          {
            super.init (config);
            try
              {
                signature = new String (ArrayUtil.getByteArrayFromInputStream (config.getServletContext ().getResourceAsStream ("/signature.json")), "UTF-8");
              }
            catch (IOException e)
              {
                throw new RuntimeException (e);
              }
          }
        catch (ServletException e)
          {
            throw new RuntimeException (e);
          }
      }
    
    public void doGet (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        HTML.verifyPage (response, request, signature);
      }

    public void doPost (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        request.setCharacterEncoding ("UTF-8");
        String json = CreateServlet.getTextArea (request);
/*
        response.sendRedirect (ServletUtil.getContextURL (request) + 
                               "/request?" + RequestServlet.JCS_ARGUMENT + "=" + 
                               Base64URL.encode (json.getBytes ("UTF-8")));
*/
        RequestDispatcher rd = request.getRequestDispatcher ("request?" + RequestServlet.JCS_ARGUMENT + "=" + Base64URL.encode (json.getBytes ("UTF-8")));
        rd.forward (request, response); 
      }
  }
