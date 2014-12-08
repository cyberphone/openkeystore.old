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
package org.webpki.crypto;

import java.io.IOException;
import java.security.GeneralSecurityException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public enum MACAlgorithms implements SignatureAlgorithms
  {
    HMAC_SHA1   ("http://www.w3.org/2000/09/xmldsig#hmac-sha1",        null,    "HmacSHA1",   true),
    HMAC_SHA256 ("http://www.w3.org/2001/04/xmldsig-more#hmac-sha256", "HS256", "HmacSHA256", true),
    HMAC_SHA384 ("http://www.w3.org/2001/04/xmldsig-more#hmac-sha384", "HS384", "HmacSHA384", false),
    HMAC_SHA512 ("http://www.w3.org/2001/04/xmldsig-more#hmac-sha512", "HS512", "HmacSHA512", false);

    private final String sks_id;    // As (typically) expressed in protocols
    private final String josename;  // JOSE alternative
    private final String jcename;   // As expressed for JCE
    private boolean sks_mandatory;  // If required in SKS

    private MACAlgorithms (String sks_id, String josename, String jcename, boolean sks_mandatory)
      {
        this.sks_id = sks_id;
        this.josename = josename;
        this.jcename = jcename;
        this.sks_mandatory = sks_mandatory;
      }


    @Override
    public boolean isSymmetric ()
      {
        return true;
      }


    @Override
    public boolean isMandatorySKSAlgorithm ()
      {
        return sks_mandatory;
      }


    @Override
    public String getJCEName ()
      {
        return jcename;
      }


    @Override
    public String getURI ()
      {
        return sks_id;
      }


    @Override
    public String getOID ()
      {
        return null;
      }


    @Override
    public String getJOSEName ()
      {
        return josename;
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
            throw new IOException (gse);
          }
      }


    public static boolean testAlgorithmURI (String sks_id)
      {
        for (MACAlgorithms alg : MACAlgorithms.values ())
          {
            if (sks_id.equals (alg.sks_id))
              {
                return true;
              }
          }
        return false;
      }


    public static MACAlgorithms getAlgorithmFromID (String algorithm_id) throws IOException
      {
        for (MACAlgorithms alg : values ())
          {
            if (algorithm_id.equals (alg.sks_id) || algorithm_id.equals (alg.josename))
              {
                return alg;
              }
          }
        throw new IOException ("Unknown MAC algorithm: " + algorithm_id);
      }
  }
