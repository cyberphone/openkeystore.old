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
package org.webpki.crypto;

import java.io.IOException;

import java.security.GeneralSecurityException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public enum MacAlgorithms
  {
    HMAC_MD5    ("http://www.w3.org/2001/04/xmldsig-more#hmac-md5",    "HmacMD5",    false),
    HMAC_SHA1   ("http://www.w3.org/2000/09/xmldsig#hmac-sha1",        "HmacSHA1",   true),
    HMAC_SHA256 ("http://www.w3.org/2001/04/xmldsig-more#hmac-sha256", "HmacSHA256", true),
    HMAC_SHA384 ("http://www.w3.org/2001/04/xmldsig-more#hmac-sha384", "HmacSHA384", false),
    HMAC_SHA512 ("http://www.w3.org/2001/04/xmldsig-more#hmac-sha512", "HmacSHA512", false);

    private final String uri;       // As expressed in XML messages
    private final String jcename;   // As expressed for JCE
    private boolean sks_mandatory;  // If required in SKS

    private MacAlgorithms (String uri, String jcename, boolean sks_mandatory)
      {
        this.uri = uri;
        this.jcename = jcename;
        this.sks_mandatory = sks_mandatory;
      }


    public String getURI ()
      {
        return uri;
      }


    public String getJCEName ()
      {
        return jcename;
      }

    
    public boolean isMandatorySKSAlgorithm ()
      {
        return sks_mandatory;
      }


    public byte[] digest (byte[] key, byte[] data) throws IOException
      {
        try
          {
            Mac mac = Mac.getInstance (getJCEName ());
            mac.init (new SecretKeySpec (key, "RAW"));  // Note: any length is OK in HMAC
            return mac.doFinal (data);
          }
        catch (GeneralSecurityException gse)
          {
            IOException iox = new IOException ();
            iox.initCause (gse.getCause ());
            throw iox;
          }
      }


    public static boolean testAlgorithmURI (String uri)
      {
        for (MacAlgorithms alg : MacAlgorithms.values ())
          {
            if (uri.equals (alg.uri))
              {
                return true;
              }
          }
        return false;
      }


    public static MacAlgorithms getAlgorithmFromURI (String uri) throws IOException
      {
        for (MacAlgorithms alg : values ())
          {
            if (uri.equals (alg.uri))
              {
                return alg;
              }
          }
        throw new IOException ("Unknown algorithm: " + uri);
      }

  }
