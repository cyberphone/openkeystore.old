/*
 *  Copyright 2006-2013 WebPKI.org (http://webpki.org).
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


public enum AsymEncryptionAlgorithms implements EncryptionAlgorithms
  {
    RSA_PKCS_1_5           ("1.2.840.113549.1.1.1",
                            "http://xmlns.webpki.org/sks/algorithm#rsa.pkcs1_5",
                            "RSA/ECB/PKCS1Padding"),
    RSA_OAEP_SHA1_MGF1P    (null,
                            "http://xmlns.webpki.org/sks/algorithm#rsa.oaep.sha1.mgf1p",
                            "RSA/ECB/OAEPWithSHA1AndMGF1Padding"),
    RSA_OAEP_SHA256_MGF1P  (null,
                            "http://xmlns.webpki.org/sks/algorithm#rsa.oaep.sha256.mgf1p",
                            "RSA/ECB/OAEPWithSHA256AndMGF1Padding"),
    RSA_RAW                (null,
                            "http://xmlns.webpki.org/sks/algorithm#rsa.raw",
                            "RSA/ECB/NoPadding");

    private final String         oid;             // As expressed in OIDs
    private final String         uri;             // As expressed in XML
    private final String         jcename;         // As expressed for JCE

    private AsymEncryptionAlgorithms (String oid, String uri, String jcename)
      {
        this.oid = oid;
        this.uri = uri;
        this.jcename = jcename;
      }


    @Override
    public boolean isSymmetric ()
      {
        return false;
      }


    @Override
    public boolean isMandatorySKSAlgorithm ()
      {
        return true;
      }


    @Override
    public String getJCEName ()
      {
        return jcename;
      }


    @Override
    public String getURI ()
      {
        return uri;
      }


    @Override
    public String getOID ()
      {
        return oid;
      }


    public static AsymEncryptionAlgorithms getAlgorithmFromOID (String oid) throws IOException
      {
        for (AsymEncryptionAlgorithms alg : values ())
          {
            if (oid.equals (alg.oid))
              {
                return alg;
              }
          }
        throw new IOException ("Unknown algorithm: " + oid);
      }


    public static AsymEncryptionAlgorithms getAlgorithmFromURI (String uri) throws IOException
      {
        for (AsymEncryptionAlgorithms alg : values ())
          {
            if (uri.equals (alg.uri))
              {
                return alg;
              }
          }
        throw new IOException ("Unknown algorithm: " + uri);
      }
  }
