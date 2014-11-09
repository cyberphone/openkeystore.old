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
package org.webpki.webapps.wcppsignaturedemo;

import java.io.IOException;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.crypto.KeyStoreVerifier;
import org.webpki.crypto.VerifierInterface;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;
import org.webpki.json.JSONX509Verifier;

public class SignedResultServlet extends HttpServlet implements BaseProperties
  {
    private static final long serialVersionUID = 1L;
    
    public void doPost (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        request.setCharacterEncoding ("UTF-8");
        String signature = request.getParameter ("signature");
        boolean error = false;
        if (signature == null)
          {
            signature = "Internal Error - Missing argument";
            error = true;
          }
        else
          {
            JSONObjectReader json = null;
            try
              {
                json = JSONParser.parse (signature);
                if (json.getObject (DOCUMENT_DATA_JSON).hasProperty (DOCUMENT_HASH_JSON))
                  {
                    JSONObjectReader document_hash = json.getObject (DOCUMENT_DATA_JSON).getObject (DOCUMENT_HASH_JSON);
                    document_hash.getBinary (VALUE_JSON);
                  }
                VerifierInterface verifier = new KeyStoreVerifier (SignatureDemoService.client_root);
                json.getSignature ().verify (new JSONX509Verifier (verifier));
                signature = new String (new JSONObjectWriter (json).serializeJSONObject (JSONOutputFormats.PRETTY_HTML), "UTF-8");
              }
            catch (IOException e)
              {
                signature = e.getMessage ();
                error = true;
              }
          }
        try
          {
            Thread.sleep (1000);
          }
        catch (InterruptedException e)
          {
          }
        HTML.signedResult (response, signature, error);
      }
  }
