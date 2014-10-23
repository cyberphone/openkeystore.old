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
package org.webpki.webapps.wcppdemo;

import java.io.IOException;
import java.io.Serializable;

import java.math.BigInteger;

import java.security.Key;

import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;

import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

import org.webpki.crypto.KeyAlgorithms;

import org.webpki.util.ArrayUtil;
import org.webpki.util.Base64URL;

public class JWK implements Serializable
  {
    private static final long serialVersionUID = 1L;

    String jwk;
    
    String key_type = "RSA";
    
    byte[] encoded;

    public JWK (Key key) throws IOException
      {
        StringBuffer s = new StringBuffer ("{kty:");
        if (key instanceof RSAKey)
          {
            s.append ("'RSA',alg:");
            if (key instanceof RSAPublicKey)
              {
                RSAPublicKey rsa_public_key = (RSAPublicKey) key;
                s.append (getCryptoBinary (rsa_public_key.getModulus (), "'RSA-OAEP-256',n"))
                 .append (getCryptoBinary (rsa_public_key.getPublicExponent (), ",e"));
              }
            else
              {
                RSAPrivateCrtKey rsa_priv_crt = (RSAPrivateCrtKey) key;
                s.append (getCryptoBinary (rsa_priv_crt.getModulus (), "'RS256',n"))
                 .append (getCryptoBinary (rsa_priv_crt.getPublicExponent (), ",e"))
                 .append (getCryptoBinary (rsa_priv_crt.getPrivateExponent (), ",d"))
                 .append (getCryptoBinary (rsa_priv_crt.getPrimeP (), ",p"))
                 .append (getCryptoBinary (rsa_priv_crt.getPrimeQ (), ",q"))
                 .append (getCryptoBinary (rsa_priv_crt.getPrimeExponentP (), ",dp"))
                 .append (getCryptoBinary (rsa_priv_crt.getPrimeExponentQ (), ",dq"))
                 .append (getCryptoBinary (rsa_priv_crt.getCrtCoefficient (), ",qi"));
              }
          }
        else
          {
            key_type = "EC";
            processECPublicKey (s, key);
          }
        jwk = s.append ('}').toString ();
        encoded = key.getEncoded ();
      }
    
    public JWK (ECPublicKey public_key, ECPrivateKey private_key) throws IOException
      {
        this (public_key);
        StringBuffer s = new StringBuffer (jwk.substring (0, jwk.length () - 1));
        addCoordinate (s, KeyAlgorithms.getKeyAlgorithm (public_key), "d", private_key.getS ());
        jwk = s.append ('}').toString ();
      }

    private void processECPublicKey (StringBuffer s, Key key) throws IOException
      {
        ECPoint ec_point = ((ECPublicKey)key).getW ();
        s.append ("'EC',crv:'");
        EllipticCurve curve = ((ECKey) key).getParams ().getCurve ();
        for (KeyAlgorithms key_alg : KeyAlgorithms.values ())
          {
            if (key_alg.isECKey () && key_alg.getECParameterSpec ().getCurve ().equals (curve))
              {
                switch (key_alg)
                  {
                    case NIST_P_256:
                    case NIST_P_384:
                    case NIST_P_521:
                      s.append ("P-")
                       .append (key_alg.toString ().substring (7))
                       .append ('\'');
                      break;
                    default:
                      throw new IOException ("Unsupported: " + key_alg);
                  }
                addCoordinate (s, key_alg, "x", ec_point.getAffineX ());
                addCoordinate (s, key_alg, "y", ec_point.getAffineY ());
                return;
             }
          }
        throw new IOException ("No suitable EC curve");
      }

    private void addCoordinate (StringBuffer s, KeyAlgorithms ec, String name, BigInteger value) throws IOException
      {
        s.append (',');
        byte[] fixed_binary = value.toByteArray ();
        if (fixed_binary.length > (ec.getPublicKeySizeInBits () + 7) / 8)
          {
            if (fixed_binary[0] != 0)
              {
                throw new IOException ("Unexpected EC \"" + name + "\" value");
              }
            s.append (getCryptoBinary (value, name));
          }
        else
          {
            while (fixed_binary.length < (ec.getPublicKeySizeInBits () + 7) / 8)
              {
                fixed_binary = ArrayUtil.add (new byte[]{0}, fixed_binary);
              }
            s.append (name)
             .append (":'")
             .append (Base64URL.encode (fixed_binary))
             .append ('\'');
          }
      }

    private String getCryptoBinary (BigInteger value, String name)
      {
        byte[] crypto_binary = value.toByteArray ();
        if (crypto_binary[0] == 0x00)
          {
            byte[] wo_zero = new byte[crypto_binary.length - 1];
            System.arraycopy (crypto_binary, 1, wo_zero, 0, wo_zero.length);
            crypto_binary = wo_zero;
          }
        return name + ":'" + Base64URL.encode (crypto_binary) + "'";
      }
    
    public String getJWK ()
      {
        return jwk;
      }

    public String getKeyType ()
      {
        return key_type;
      }

    public byte[] getEncoded ()
      {
        return encoded;
      }
  }
