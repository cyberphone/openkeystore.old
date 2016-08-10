/*
 *  Copyright 2006-2015 WebPKI.org (http://webpki.org).
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
    HMAC_SHA384 ("http://www.w3.org/2001/04/xmldsig-more#hmac-sha384", "HS384", "HmacSHA384", true),
    HMAC_SHA512 ("http://www.w3.org/2001/04/xmldsig-more#hmac-sha512", "HS512", "HmacSHA512", true);

    private final String sksname;   // As (typically) expressed in protocols
    private final String josename;  // JOSE alternative
    private final String jcename;   // As expressed for JCE
    private boolean sks_mandatory;  // If required in SKS

    private MACAlgorithms (String sksname, String josename, String jcename, boolean sks_mandatory)
      {
        this.sksname = sksname;
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
    public String getOID ()
      {
        return null;
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


    public static boolean testAlgorithmURI (String sksname)
      {
        for (MACAlgorithms alg : MACAlgorithms.values ())
          {
            if (sksname.equals (alg.sksname))
              {
                return true;
              }
          }
        return false;
      }


    public static MACAlgorithms getAlgorithmFromID (String algorithm_id, AlgorithmPreferences algorithmPreferences) throws IOException
      {
        for (MACAlgorithms alg : values ())
          {
            if (algorithm_id.equals (alg.sksname))
              {
                if (algorithmPreferences == AlgorithmPreferences.JOSE)
                  {
                    throw new IOException ("JOSE algorithm expected: " + algorithm_id);
                  }
                return alg;
              }
            if (algorithm_id.equals (alg.josename))
              {
                if (algorithmPreferences == AlgorithmPreferences.SKS)
                  {
                    throw new IOException ("SKS algorithm expected: " + algorithm_id);
                  }
                return alg;
              }
          }
        throw new IOException ("Unknown MAC algorithm: " + algorithm_id);
      }

    
    @Override
    public String getAlgorithmId (AlgorithmPreferences algorithmPreferences) throws IOException
      {
        if (josename == null)
          {
            if (algorithmPreferences == AlgorithmPreferences.JOSE)
              {
                throw new IOException("There is no JOSE algorithm for: " + toString ());
              }
            return sksname;
          }
        return algorithmPreferences == AlgorithmPreferences.SKS ? sksname : josename;
      }
  }
