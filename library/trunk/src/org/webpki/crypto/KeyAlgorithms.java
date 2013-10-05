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
import java.math.BigInteger;

import java.security.PublicKey;

import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import java.security.spec.ECFieldF2m;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

import org.bouncycastle.jce.spec.ECNamedCurveSpec;

public enum KeyAlgorithms implements SKSAlgorithms
  {
    RSA1024     ("http://xmlns.webpki.org/sks/algorithm#rsa1024",
                 "RSA",
                 1024,
                 AsymSignatureAlgorithms.RSA_SHA1,
                 false,
                 true,
                 null,
                 null,
                 null,
                 null,
                 null,
                 null,
                 null,
                 0,
                 false),

    RSA2048     ("http://xmlns.webpki.org/sks/algorithm#rsa2048",
                 "RSA",
                 2048,
                 AsymSignatureAlgorithms.RSA_SHA256,
                 false,
                 true,
                 null,
                 null,
                 null,
                 null,
                 null,
                 null,
                 null,
                 0,
                 false),

    RSA3072     ("http://xmlns.webpki.org/sks/algorithm#rsa3072",
                 "RSA",
                 3072,
                 AsymSignatureAlgorithms.RSA_SHA512,
                 false,
                 false,
                 null,
                 null,
                 null,
                 null,
                 null,
                 null,
                 null,
                 0,
                 false),

    RSA4096     ("http://xmlns.webpki.org/sks/algorithm#rsa4096",
                 "RSA",
                 4096,
                 AsymSignatureAlgorithms.RSA_SHA512,
                 false,
                 false,
                 null,
                 null,
                 null,
                 null,
                 null,
                 null,
                 null,
                 0,
                 false),

    RSA1024_EXP ("http://xmlns.webpki.org/sks/algorithm#rsa1024.exp",
                 "RSA",
                 1024,
                 AsymSignatureAlgorithms.RSA_SHA1,
                 true,
                 false,
                 null,
                 null,
                 null,
                 null,
                 null,
                 null,
                 null,
                 0,
                 false),

    RSA2048_EXP ("http://xmlns.webpki.org/sks/algorithm#rsa2048.exp",
                 "RSA",
                 2048,
                 AsymSignatureAlgorithms.RSA_SHA256,
                 true,
                 false,
                 null,
                 null,
                 null,
                 null,
                 null,
                 null,
                 null,
                 0,
                 false),

    RSA3072_EXP ("http://xmlns.webpki.org/sks/algorithm#rsa3072.exp",
                 "RSA",
                 3072,
                 AsymSignatureAlgorithms.RSA_SHA512,
                 true,
                 false,
                 null,
                 null,
                 null,
                 null,
                 null,
                 null,
                 null,
                 0,
                 false),

    RSA4096_EXP ("http://xmlns.webpki.org/sks/algorithm#rsa4096.exp",
                 "RSA",
                 4096,
                 AsymSignatureAlgorithms.RSA_SHA512,
                 true,
                 false,
                 null,
                 null,
                 null,
                 null,
                 null,
                 null,
                 null,
                 0,
                 false),

    B_163       ("http://xmlns.webpki.org/sks/algorithm#ec.b163",
                 "sect163r2",
                 163,
                 AsymSignatureAlgorithms.ECDSA_SHA256,
                 false,
                 false,
                 "1.3.132.0.15",
                 "0800000000000000000000000000000000000000C9",
                 "000000000000000000000000000000000000000001",
                 "020A601907B8C953CA1481EB10512F78744A3205FD",
                 "03F0EBA16286A2D57EA0991168D4994637E8343E36",
                 "00D51FBC6C71A0094FA2CDD545B11C5C0C797324F1",
                 "040000000000000000000292FE77E70C12A4234C33",
                 2,
                 true),

    B_233       ("http://xmlns.webpki.org/sks/algorithm#ec.b233",
                 "sect233r1",
                 233,
                 AsymSignatureAlgorithms.ECDSA_SHA512,
                 false,
                 false,
                 "1.3.132.0.27",
                 "020000000000000000000000000000000000000004000000000000000001",
                 "000000000000000000000000000000000000000000000000000000000001",
                 "0066647EDE6C332C7F8C0923BB58213B333B20E9CE4281FE115F7D8F90AD",
                 "00FAC9DFCBAC8313BB2139F1BB755FEF65BC391F8B36F8F8EB7371FD558B",
                 "01006A08A41903350678E58528BEBF8A0BEFF867A7CA36716F7E01F81052",
                 "01000000000000000000000000000013E974E72F8A6922031D2603CFE0D7",
                 2,
                 true),

    B_283       ("http://xmlns.webpki.org/sks/algorithm#ec.b283",
                 "sect283r1",
                 283,
                 AsymSignatureAlgorithms.ECDSA_SHA512,
                 false,
                 false,
                 "1.3.132.0.17",
                 "0800000000000000000000000000000000000000000000000000000000000000000010A1",
                 "000000000000000000000000000000000000000000000000000000000000000000000001",
                 "027B680AC8B8596DA5A4AF8A19A0303FCA97FD7645309FA2A581485AF6263E313B79A2F5",
                 "05F939258DB7DD90E1934F8C70B0DFEC2EED25B8557EAC9C80E2E198F8CDBECD86B12053",
                 "03676854FE24141CB98FE6D4B20D02B4516FF702350EDDB0826779C813F0DF45BE8112F4",
                 "03FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEF90399660FC938A90165B042A7CEFADB307",
                 2,
                 true),

    P_192       ("http://xmlns.webpki.org/sks/algorithm#ec.p192",
                 "secp192r1",
                 192,
                 AsymSignatureAlgorithms.ECDSA_SHA256,
                 false,
                 false,
                 "1.2.840.10045.3.1.1",
                 "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF",
                 "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC",
                 "64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1",
                 "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",
                 "07192B95FFC8DA78631011ED6B24CDD573F977A11E794811",
                 "FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831",
                 1,
                 false),

    P_256       ("http://xmlns.webpki.org/sks/algorithm#ec.p256",
                 "secp256r1",
                 256,
                 AsymSignatureAlgorithms.ECDSA_SHA256,
                 false,
                 true,
                 "1.2.840.10045.3.1.7",
                 "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
                 "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
                 "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
                 "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
                 "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
                 "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
                 1,
                 false),

    P_384       ("http://xmlns.webpki.org/sks/algorithm#ec.p384",
                 "secp384r1",
                 384,
                 AsymSignatureAlgorithms.ECDSA_SHA512,
                 false,
                 false,
                 "1.3.132.0.34",
                 "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
                 "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC",
                 "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",
                 "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
                 "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
                 "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",
                 1,
                 false),

    P_521       ("http://xmlns.webpki.org/sks/algorithm#ec.p521",
                 "secp521r1",
                 521,
                 AsymSignatureAlgorithms.ECDSA_SHA512,
                 false,
                 false,
                 "1.3.132.0.35",
                 "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                 "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC",
                 "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",
                 "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
                 "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
                 "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
                 1,
                 false);


    private final String uri;                        // As expressed in XML and JSON
    private final String jcename;                    // As expressed for JCE
    private final int length_in_bits;
    private final AsymSignatureAlgorithms pref_alg;  // A sort of a "guide"
    private final boolean has_parameters;            // Parameter value required?
    private final boolean sks_mandatory;             // If required in SKS
    private final String ec_domain_oid;              // EC domain as expressed in ASN.1 messages, null for RSA
    private EllipticCurve elliptic_curve;            // EC
    private final BigInteger x;                      // EC 
    private final BigInteger y;                      // EC 
    private final BigInteger n;                      // EC
    private final int h;                             // EC


    private KeyAlgorithms (String uri,
                           String jcename,
                           int length_in_bits,
                           AsymSignatureAlgorithms pref_alg,
                           boolean has_parameters,
                           boolean sks_mandatory,
                           String ec_domain_oid,
                           String field,
                           String a,
                           String b,
                           String x, 
                           String y, 
                           String n,
                           int h,
                           boolean f2m)
      {
        this.uri = uri;
        this.jcename = jcename;
        this.length_in_bits = length_in_bits;
        this.pref_alg = pref_alg;
        this.has_parameters = has_parameters;
        this.sks_mandatory = sks_mandatory;
        this.ec_domain_oid = ec_domain_oid;
        this.elliptic_curve = field == null ?
            null 
                                            :
            new EllipticCurve (f2m ? new ECFieldF2m (length_in_bits, new BigInteger (field, 16)) : new ECFieldFp (new BigInteger (field, 16)),
                               new BigInteger (a, 16), new BigInteger (b, 16));
        this.x = x == null ? null : new BigInteger (x, 16);
        this.y = y == null ? null : new BigInteger (y, 16);
        this.n = n == null ? null : new BigInteger (n, 16);
        this.h = h;
      }


    @Override
    public boolean isSymmetric ()
      {
        return false;
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
        return uri;
      }


    @Override
    public String getOID ()
      {
        return null;
      }

    
    public String getECDomainOID ()
      {
        return ec_domain_oid;
      }

    
    public boolean isECKey ()
      {
        return ec_domain_oid != null;
      }

    
    public boolean isRSAKey ()
      {
        return ec_domain_oid == null;
      }


    public int getPublicKeySizeInBits ()
      {
        return length_in_bits;
      }
 

    public AsymSignatureAlgorithms getRecommendedSignatureAlgorithm ()
      {
        return pref_alg;
      }


    public boolean hasParameters ()
      {
        return has_parameters;
      }

    public EllipticCurve getEllipticCurve ()
      {
        return elliptic_curve;
      }

    public ECParameterSpec getECParameterSpec ()
      {
        return new ECNamedCurveSpec (jcename, elliptic_curve, new ECPoint (x, y), n, BigInteger.valueOf (h));
      }
 

    public static KeyAlgorithms getKeyAlgorithm (PublicKey public_key, Boolean key_parameters) throws IOException
      {
        if (public_key instanceof ECPublicKey)
          {
            EllipticCurve ec_curve = ((ECPublicKey) public_key).getParams ().getCurve ();
            for (KeyAlgorithms alg : values ())
              {
                if (alg.isECKey () && alg.elliptic_curve.equals (ec_curve))
                  {
                    return alg;
                  }
              }
            throw new IOException ("Unknown EC curve: " + ec_curve.toString ());
          }
        byte[] modblob = ((RSAPublicKey)public_key).getModulus ().toByteArray ();
        int length_in_bits = (modblob[0] == 0 ? modblob.length - 1 : modblob.length) * 8;
        for (KeyAlgorithms alg : values ())
          {
            if (alg.ec_domain_oid == null && length_in_bits == alg.length_in_bits && 
                (key_parameters == null || alg.has_parameters == key_parameters))
              {
                return alg;
              }
          }
        throw new IOException ("Unsupported RSA key size: " + length_in_bits);
      }


    public static KeyAlgorithms getKeyAlgorithm (PublicKey public_key) throws IOException
      {
        return getKeyAlgorithm (public_key, null);
      }


    public static KeyAlgorithms getKeyAlgorithmFromURI (String uri) throws IOException
      {
        for (KeyAlgorithms alg : values ())
          {
            if (uri.equals (alg.uri))
              {
                return alg;
              }
          }
        throw new IOException ("Unknown algorithm: " + uri);
      }
  }
