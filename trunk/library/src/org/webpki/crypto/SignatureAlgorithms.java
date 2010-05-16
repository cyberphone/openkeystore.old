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
package org.webpki.crypto;

import java.io.IOException;


public enum SignatureAlgorithms
  {
    RSA_SHA1     ("1.2.840.113549.1.1.5",  "http://www.w3.org/2000/09/xmldsig#rsa-sha1",          "SHA1withRSA",     HashAlgorithms.SHA1),
    RSA_SHA256   ("1.2.840.113549.1.1.11", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",   "SHA256withRSA",   HashAlgorithms.SHA256),
    RSA_SHA384   ("1.2.840.113549.1.1.12", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",   "SHA384withRSA",   HashAlgorithms.SHA384),
    RSA_SHA512   ("1.2.840.113549.1.1.13", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",   "SHA512withRSA",   HashAlgorithms.SHA512),
    ECDSA_SHA1   ("1.2.840.10045.1",       "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1",   "SHA1withECDSA",   HashAlgorithms.SHA1),
    ECDSA_SHA256 ("1.2.840.10045.4.3.2",   "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", "SHA256withECDSA", HashAlgorithms.SHA256),
    ECDSA_SHA384 ("1.2.840.10045.4.3.3",   "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384", "SHA384withECDSA", HashAlgorithms.SHA384),
    ECDSA_SHA512 ("1.2.840.10045.4.3.4",   "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512", "SHA512withECDSA", HashAlgorithms.SHA512);

    private final String oid;       // As expressed in OIDs
    private final String uri;       // As expressed in XML messages
    private final String jcename;   // As expressed for JCE
    private final HashAlgorithms digest_alg;

    private SignatureAlgorithms (String oid, String uri, String jcename, HashAlgorithms digest_alg)
      {
        this.oid = oid;
        this.uri = uri;
        this.jcename = jcename;
        this.digest_alg = digest_alg;
      }


    public String getOID ()
      {
        return oid;
      }


    public String getURI ()
      {
        return uri;
      }


    public String getJCEName ()
      {
        return jcename;
      }


    public HashAlgorithms getDigestAlgorithm ()
      {
        return digest_alg;
      }


    public static boolean testAlgorithmURI (String uri)
      {
        for (SignatureAlgorithms alg : values ())
          {
            if (uri.equals (alg.uri))
              {
                return true;
              }
          }
        return false;
      }


    public static SignatureAlgorithms getAlgorithmFromURI (String uri) throws IOException
      {
        for (SignatureAlgorithms alg : SignatureAlgorithms.values ())
          {
            if (uri.equals (alg.uri))
              {
                return alg;
              }
          }
        throw new IOException ("Unknown algorithm: " + uri);
      }

  }
