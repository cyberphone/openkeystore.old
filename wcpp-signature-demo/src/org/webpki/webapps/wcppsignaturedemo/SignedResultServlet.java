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
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.CertificateUtil;
import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.KeyStoreVerifier;
import org.webpki.crypto.VerifierInterface;
import org.webpki.crypto.SignatureWrapper;
import org.webpki.json.JSONAlgorithmPreferences;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;
import org.webpki.json.JSONX509Verifier;
import org.webpki.tools.XML2HTMLPrinter;
import org.webpki.util.ArrayUtil;
import org.webpki.util.Base64;
import org.webpki.util.Base64URL;
import org.webpki.xml.XMLSchemaCache;
import org.webpki.xmldsig.SignedKeyInfoSpecifier;
import org.webpki.xmldsig.XMLVerifier;

public class SignedResultServlet extends HttpServlet implements BaseProperties
  {
    private static final long serialVersionUID = 1L;
    
    public void doPost (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        request.setCharacterEncoding ("UTF-8");
        String signature = request.getParameter ("signature");
        String signature_request = request.getParameter ("request");
        String title = "JCS is a nice JSON signature format";
        boolean error = false;
        try
          {
            if (signature == null)
              {
                throw new IOException ("Internal Error - Missing signature argument");
              }
            if (signature_request == null)
              {
                throw new IOException ("Internal Error - Missing request argument");
              }
            byte[] document = JSONParser.parse (signature_request).getObject (OBJECT_TO_SIGN_JSON).getBinary (DOCUMENT_JSON);
            if (signature.startsWith ("<?xml"))
              {
                title = "This signature must be &quot;flattened&quot; (=remove all whitespace between elements) to validate";
                XMLSchemaCache xml_schema_cache = new XMLSchemaCache ();
                xml_schema_cache.addWrapper (XMLSignatureResponse.class);
                XMLSignatureResponse xml_response = (XMLSignatureResponse) xml_schema_cache.parse (signature.getBytes ("UTF-8"));
                XMLVerifier verifier = new XMLVerifier (new KeyStoreVerifier (SignatureDemoService.client_root_kestore));
                verifier.setSignedKeyInfo (SignedKeyInfoSpecifier.REQUIRE_SIGNED_KEY_INFO);
                verifier.validateEnvelopedSignature (xml_response);
                signature = XML2HTMLPrinter.convert (signature);
              }
            else if (signature.contains ("{"))
              {
                JSONObjectReader json = JSONParser.parse (signature);
                if (json.getObject (DOCUMENT_DATA_JSON).hasProperty (DOCUMENT_HASH_JSON))
                  {
                    if (!ArrayUtil.compare (json.getObject (DOCUMENT_DATA_JSON).getObject (DOCUMENT_HASH_JSON).getBinary (VALUE_JSON),
                                            HashAlgorithms.SHA256.digest (document)))
                      {
                        throw new IOException ("Hash verification error");                  
                      }
                  }
                else if (!ArrayUtil.compare (json.getObject (DOCUMENT_DATA_JSON).getBinary (DOCUMENT_JSON), document))
                  {
                    throw new IOException ("Document verification error");                  
                  }
                VerifierInterface verifier = new KeyStoreVerifier (SignatureDemoService.client_root_kestore);
                json.getSignature (JSONAlgorithmPreferences.JOSE).verify (new JSONX509Verifier (verifier));
                signature = new String (new JSONObjectWriter (json).serializeJSONObject (JSONOutputFormats.PRETTY_HTML), "UTF-8");
              }
            else
              {
                title = "JWS signatures are ugly but safe :-)";
                JSONObjectReader header = JSONParser.parse (Base64URL.decode (signature.substring (0, signature.indexOf ('.'))));
                if (!header.getString ("alg").equals ("RS256"))
                  {
                    throw new IOException ("JWS algorithm error");
                  }
                X509Certificate cert = CertificateUtil.getCertificateFromBlob (new Base64().getBinaryFromBase64String (header.getArray ("x5c").getString ()));
                byte[] signed_data = signature.substring (0, signature.lastIndexOf ('.')).getBytes ("UTF-8");
                byte[] raw_signature = Base64URL.decode (signature.substring (signature.lastIndexOf ('.') + 1));
                if (!new SignatureWrapper (AsymSignatureAlgorithms.RSA_SHA256, cert.getPublicKey ())
                          .update (signed_data)
                          .verify (raw_signature))
                  {
                    throw new IOException ("Bad JWS signature");
                  }
                VerifierInterface verifier = new KeyStoreVerifier (SignatureDemoService.client_root_kestore);
                verifier.verifyCertificatePath (new X509Certificate[]{cert});
                JSONObjectReader payload = JSONParser.parse (Base64URL.decode (signature.substring (signature.indexOf ('.') + 1, signature.lastIndexOf ('.'))));
                signature = "<div align=\"center\" style=\"padding-bottom:10pt\"><b>Actual Response</b></div>" + signature +
                "<div align=\"center\" style=\"padding:20pt 0px 10pt 0px\"><b>Decoded Header</b></div>" + new String (new JSONObjectWriter (header).serializeJSONObject (JSONOutputFormats.PRETTY_HTML), "UTF-8") +
                "<div align=\"center\" style=\"padding:20pt 0px 10pt 0px\"><b>Decoded Payload</b></div>" + new String (new JSONObjectWriter (payload).serializeJSONObject (JSONOutputFormats.PRETTY_HTML), "UTF-8");
              }
            Thread.sleep (1000);
          }
        catch (IOException e)
          {
            signature = e.getMessage ();
            error = true;
          }
        catch (GeneralSecurityException e)
          {
             e.printStackTrace();
          }
        catch (InterruptedException e)
          {
             e.printStackTrace();
          }
        HTML.signedResult (response, signature, signature_request, error, title);
      }

    public void doGet (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        response.sendRedirect (SignatureDemoService.issuer_url);
      }
  }
