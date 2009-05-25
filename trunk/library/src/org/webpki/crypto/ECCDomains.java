package org.webpki.crypto;

import java.io.IOException;

import java.security.interfaces.ECPublicKey;

import org.webpki.asn1.DerDecoder;
import org.webpki.asn1.ParseUtil;


public enum ECCDomains
  {
    B_163   ("1.3.132.0.15",        "B-163", 163, SignatureAlgorithms.ECDSA_SHA1),
    B_233   ("1.3.132.0.27",        "B-233", 233, SignatureAlgorithms.ECDSA_SHA256),
    B_283   ("1.3.132.0.17",        "B-283", 283, SignatureAlgorithms.ECDSA_SHA384),
    P_192   ("1.2.840.10045.3.1.1", "P-192", 192, SignatureAlgorithms.ECDSA_SHA256),
    P_256   ("1.2.840.10045.3.1.7", "P-256", 256, SignatureAlgorithms.ECDSA_SHA256),
    P_384   ("1.3.132.0.34",        "P-384", 384, SignatureAlgorithms.ECDSA_SHA384);

    private final String oid;       // As expressed in ASN.1 messages
    private final String jcename;   // As expressed for JCE
    private final int length_in_bits;
    private final SignatureAlgorithms pref_alg;

    private ECCDomains (String oid, String jcename, int length_in_bits, SignatureAlgorithms pref_alg)
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
 

    public static ECCDomains getECCDomainFromOID (String oid) throws IOException
      {
        for (ECCDomains alg : values ())
          {
            if (oid.equals (alg.oid))
              {
                return alg;
              }
          }
        throw new IOException ("Unknown domain: " + oid);
      }


    public static ECCDomains getECCDomain (ECPublicKey public_key) throws IOException
      {
        return getECCDomainFromOID (ParseUtil.oid (
                                      ParseUtil.sequence (
                                         ParseUtil.sequence (
                                            DerDecoder.decode (public_key.getEncoded ()), 2).get(0), 2).get (1)).oid ());
      }


    public static SignatureAlgorithms getRecommendedSignatureAlgorithm (ECPublicKey public_key) throws IOException
      {
        return getECCDomain (public_key).getRecommendedSignatureAlgorithm ();
      }

  }
