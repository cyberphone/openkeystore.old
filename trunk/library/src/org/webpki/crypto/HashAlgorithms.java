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

import java.security.MessageDigest;
import java.security.GeneralSecurityException;


public enum HashAlgorithms
  {
    SHA1   ("http://www.w3.org/2000/09/xmldsig#sha1",        "1.3.14.3.2.26",          "SHA-1"),
    SHA256 ("http://www.w3.org/2001/04/xmlenc#sha256",       "2.16.840.1.101.3.4.2.1", "SHA-256"),
    SHA384 ("http://www.w3.org/2001/04/xmldsig-more#sha384", "2.16.840.1.101.3.4.2.2", "SHA-384"),
    SHA512 ("http://www.w3.org/2001/04/xmlenc#sha512",       "2.16.840.1.101.3.4.2.3", "SHA-512");

    private final String uri;       // As expressed in XML messages
    private final String oid;       // As expressed in ASN.1 messages
    private final String jcename;   // As expressed for JCE

    private HashAlgorithms (String uri, String oid, String jcename)
      {
        this.uri = uri;
        this.oid = oid;
        this.jcename = jcename;
      }


    public String getURI ()
      {
        return uri;
      }


    public String getOID ()
      {
        return oid;
      }


    public String getJCEName ()
      {
        return jcename;
      }

    
    public static boolean testAlgorithmURI (String uri)
      {
        for (HashAlgorithms alg : HashAlgorithms.values ())
          {
            if (uri.equals (alg.uri))
              {
                return true;
              }
          }
        return false;
      }


    public byte[] digest (byte[] data) throws IOException
      {
        try
          {
            return MessageDigest.getInstance (getJCEName ()).digest (data);
          }
        catch (GeneralSecurityException gse)
          {
            IOException iox = new IOException ();
            iox.initCause (gse.getCause ());
            throw iox;
          }
      }


    public static HashAlgorithms getAlgorithmFromURI (String uri) throws IOException
      {
        for (HashAlgorithms alg : values ())
          {
            if (uri.equals (alg.uri))
              {
                return alg;
              }
          }
        throw new IOException ("Unknown algorithm: " + uri);
      }


    public static HashAlgorithms getAlgorithmFromOID (String oid) throws IOException
      {
        for (HashAlgorithms alg : values ())
          {
            if (oid.equals (alg.oid))
              {
                return alg;
              }
          }
        throw new IOException ("Unknown algorithm: " + oid);
      }

  }
