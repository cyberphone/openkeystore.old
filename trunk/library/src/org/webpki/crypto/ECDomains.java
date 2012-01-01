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

import java.security.interfaces.ECPublicKey;

import org.webpki.asn1.DerDecoder;
import org.webpki.asn1.ParseUtil;


public enum ECDomains
  {
    B_163   ("1.3.132.0.15",        "B-163",     163, SignatureAlgorithms.ECDSA_SHA1),
    B_233   ("1.3.132.0.27",        "B-233",     233, SignatureAlgorithms.ECDSA_SHA256),
    B_283   ("1.3.132.0.17",        "B-283",     283, SignatureAlgorithms.ECDSA_SHA384),
    P_192   ("1.2.840.10045.3.1.1", "secp192r1", 192, SignatureAlgorithms.ECDSA_SHA256),
    P_256   ("1.2.840.10045.3.1.7", "secp256r1", 256, SignatureAlgorithms.ECDSA_SHA256),
    P_384   ("1.3.132.0.34",        "secp384r1", 384, SignatureAlgorithms.ECDSA_SHA384);

    private final String oid;       // As expressed in ASN.1 messages
    private final String jcename;   // As expressed for JCE
    private final int length_in_bits;
    private final SignatureAlgorithms pref_alg;

    private ECDomains (String oid, String jcename, int length_in_bits, SignatureAlgorithms pref_alg)
      {
        this.oid = oid;
        this.jcename = jcename;
        this.length_in_bits = length_in_bits;
        this.pref_alg = pref_alg;
      }


    public String getOID ()
      {
        return oid;
      }

    
    public String getURI ()
      {
        return "urn:oid:" + getOID ();
      }


    public String getJCEName ()
      {
        return jcename;
      }


    public int getPublicKeySizeInBits ()
      {
        return length_in_bits;
      }
 

    public SignatureAlgorithms getRecommendedSignatureAlgorithm ()
      {
        return pref_alg;
      }
 

    public static ECDomains getECDomainFromOID (String oid) throws IOException
      {
        for (ECDomains alg : values ())
          {
            if (oid.equals (alg.oid))
              {
                return alg;
              }
          }
        throw new IOException ("Unknown domain: " + oid);
      }


    public static ECDomains getECDomain (ECPublicKey public_key) throws IOException
      {
        return getECDomainFromOID (ParseUtil.oid (
                                      ParseUtil.sequence (
                                         ParseUtil.sequence (
                                            DerDecoder.decode (public_key.getEncoded ()), 2).get(0), 2).get (1)).oid ());
      }


    public static SignatureAlgorithms getRecommendedSignatureAlgorithm (ECPublicKey public_key) throws IOException
      {
        return getECDomain (public_key).getRecommendedSignatureAlgorithm ();
      }

  }
