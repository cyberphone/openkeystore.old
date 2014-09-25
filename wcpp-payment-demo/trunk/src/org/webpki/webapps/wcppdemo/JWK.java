package org.webpki.webapps.wcppdemo;

import java.io.IOException;

import java.math.BigInteger;

import java.security.Key;

import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;

import org.webpki.util.Base64URL;

public class JWK
  {
    String jwk;
    
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
            throw new IOException ("NOT IMPLEMENTED");
         //   s.append ("'EC',");
          }
        jwk = s.append ('}').toString ();
        encoded = key.getEncoded ();
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

    public byte[] getEncoded ()
      {
        return encoded;
      }
  }
