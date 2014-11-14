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

public enum ExtendedKeyUsages
  {
    SERVER_AUTH             ("1.3.6.1.5.5.7.3.1", "serverAuth"),
    CLIENT_AUTH             ("1.3.6.1.5.5.7.3.2", "clientAuth"),
    CODE_SIGNING            ("1.3.6.1.5.5.7.3.3", "codeSigning"),
    EMAIL_PROTECTION        ("1.3.6.1.5.5.7.3.4", "emailProtection"),
    TIME_STAMPING           ("1.3.6.1.5.5.7.3.8", "timeStamping"),
    OCSP_SIGNING            ("1.3.6.1.5.5.7.3.9", "OCSPSigning");

    private final String oid;
    private final String x509_name;

    private ExtendedKeyUsages (String oid, String x509_name)
      {
        this.oid = oid;
        this.x509_name = x509_name;
      }


    public String getOID ()
      {
        return oid;
      }
  

    public static ExtendedKeyUsages getExtendedKeyUsage (String oid) throws IOException
      {
        for (ExtendedKeyUsages eku : ExtendedKeyUsages.values ())
          {
            if (oid.equals (eku.oid))
              {
                return eku;
              }
          }
        throw new IOException ("Unknown EKU: " + oid);
      }

    public static String getOptionallyTranslatedEKU (String oid) throws IOException
      {
        for (ExtendedKeyUsages eku : ExtendedKeyUsages.values ())
          {
            if (oid.equals (eku.oid))
              {
                return eku.x509_name;
              }
          }
        return oid;
      }


    public Object getX509Name ()
      {
         return x509_name;
      }
  }
