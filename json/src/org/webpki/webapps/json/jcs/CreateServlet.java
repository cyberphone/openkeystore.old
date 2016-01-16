/*
 *  Copyright 2006-2014 WebPKI.org (http://webpki.org).
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
package org.webpki.webapps.json.jcs;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.json.JSONArrayReader;
import org.webpki.json.JSONArrayWriter;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONParser;

import org.webpki.util.Base64URL;

public class CreateServlet extends HttpServlet
  {
    private static final long serialVersionUID = 1L;
    
    static final String KEY_TYPE  = "keytype";
    static final String JOSE_FLAG = "jose";
    static final String ES6_FLAG  = "es6";
    
    public void doGet (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        HTML.createPage (response, request);
      }
    
    static public String getTextArea (HttpServletRequest request) throws IOException
      {
        String string = request.getParameter (RequestServlet.JCS_ARGUMENT);
        if (string == null)
          {
            throw new IOException ("Missing data for: " + RequestServlet.JCS_ARGUMENT);
          }
        StringBuffer s = new StringBuffer ();
        for (char c : string.toCharArray ())
          {
            if (c != '\r')
              {
                s.append (c);
              }
          }
        return s.toString ();
      }

    public void doPost (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        request.setCharacterEncoding ("UTF-8");
        String json_object = getTextArea (request);
        GenerateSignature.ACTION action = GenerateSignature.ACTION.EC;
        boolean es6 = new Boolean (request.getParameter (ES6_FLAG));
        String key_type = request.getParameter (KEY_TYPE);
        boolean jose = new Boolean (request.getParameter (JOSE_FLAG));
        for (GenerateSignature.ACTION a : GenerateSignature.ACTION.values ())
          {
            if (a.toString ().equals (key_type))
              {
                action = a;
                break;
              }
          }
        try
          {
            JSONObjectReader reader = JSONParser.parse (json_object);
            JSONObjectWriter writer = new JSONObjectWriter (reader);
            if (es6) 
              {
                writer = new JSONObjectWriter ();
                es6Normalize (reader, writer);
              }
            byte[] signed_json = new GenerateSignature (action, jose).sign (writer);
            RequestDispatcher rd = request.getRequestDispatcher ("request?" + RequestServlet.JCS_ARGUMENT + "=" + Base64URL.encode (signed_json));
            rd.forward (request, response); 
          }
        catch (IOException e)
          {
            HTML.errorPage (response,  e.getMessage ());
          }
      }

    void es6Normalize (JSONObjectReader reader, JSONObjectWriter writer) throws IOException
      {
        String[] properties = reader.getProperties ();
        boolean changes = false;
        do
          {
            changes = false;
            int i = properties.length;
            while (--i > 0)
              {
                if (getValue(properties[i - 1]) > getValue(properties[i]))
                  {
                    String save = properties[i - 1];
                    properties[i - 1] =  properties[i];
                    properties[i] = save;
                    changes = true;
                  }
              }
          }
        while (changes);
        for (String property : properties)
          {
            switch (reader.getPropertyType (property)) 
              {
                case NUMBER:
                  writer.setDouble (property, reader.getDouble (property));
                  break;
                case NULL:
                  writer.setNULL (property);
                  break;
                case BOOLEAN:
                  writer.setBoolean (property, reader.getBoolean (property));
                  break;
                case STRING:
                  writer.setString (property, reader.getString (property));
                  break;
                case ARRAY:
                  rewriteArray(reader.getArray (property), writer.setArray (property));
                  break;
                default:
                  es6Normalize(reader.getObject (property), writer.setObject (property));
              }
          }
      }

    void rewriteArray (JSONArrayReader arrayReader, JSONArrayWriter arrayWriter) throws IOException
      {
        while (arrayReader.hasMore ())
          {
            switch (arrayReader.getElementType ())
              {
                case NUMBER:
                  arrayWriter.setDouble (arrayReader.getDouble ());
                  break;
                case NULL:
                  arrayReader.scanAway ();
                  arrayWriter.setNULL ();
                  break;
                case BOOLEAN:
                  arrayWriter.setBoolean (arrayReader.getBoolean ());
                  break;
                case STRING:
                  arrayWriter.setString (arrayReader.getString ());
                  break;
                case ARRAY:
                  rewriteArray (arrayReader.getArray (), arrayWriter.setArray ());
                  break;
                default:
                  es6Normalize (arrayReader.getObject (), arrayWriter.setObject ());
              }
          }
      }

    long getValue (String property)
      {
        if (property.matches("\\d+"))
          {
            return Long.parseLong (property);
          }
        return Long.MAX_VALUE;
      }
  }
