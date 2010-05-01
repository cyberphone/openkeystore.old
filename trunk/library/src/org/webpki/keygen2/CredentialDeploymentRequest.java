/*
 *  Copyright 2006-2010 WebPKI.org (http://webpki.org).
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
package org.webpki.keygen2;

import java.io.IOException;

import java.security.cert.X509Certificate;

import org.webpki.xml.XMLObjectWrapper;
import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMWriterHelper;

import org.webpki.xmldsig.XMLSignatureWrapper;

import org.webpki.crypto.CertificateUtil;

import static org.webpki.keygen2.KeyGen2Constants.*;


abstract class CredentialDeploymentRequest extends XMLObjectWrapper 
  {
    CredentialDeploymentRequest () {}


    static String[] getSortedAlgorithms (String[] algorithms) throws IOException
      {
        int i = 0;
        while (true)
          {
            if (i < (algorithms.length - 1))
              {
                if (algorithms[i].compareTo (algorithms[i + 1]) > 0)
                  {
                    String s = algorithms[i];
                    algorithms[i] = algorithms[i + 1];
                    algorithms[i + 1] = s;
                    i = 0;
                  }
                else
                  {
                    i++;
                  }
              }
            else
              {
                break;
              }
          }
        return algorithms;
      }


    static void checkCertificateOrder (X509Certificate[] eepath, X509Certificate[] capath) throws IOException
      {
        if (!eepath[0].equals (CertificateUtil.getSortedPath (new X509Certificate[]{eepath[0], capath[0]})[0]))
          {
            throw new IOException ("Certificate order error!");
          }
      }


    public void init () throws IOException
      {
        addWrapper (XMLSignatureWrapper.class);
        addSchema (KEYGEN2_SCHEMA_FILE);
      }


    protected boolean hasQualifiedElements ()
      {
        return true;
      }


    public String namespace ()
      {
        return KEYGEN2_NS;
      }

    
    public String element ()
      {
        return "CredentialDeploymentRequest";
      }


    protected void fromXML (DOMReaderHelper helper) throws IOException
      {
        throw new IOException ("Should have been implemented in derived class");
      }


    protected void toXML (DOMWriterHelper helper) throws IOException
      {
        throw new IOException ("Should have been implemented in derived class");
      }

  }
