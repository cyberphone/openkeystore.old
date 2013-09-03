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
package org.webpki.json.test;

import java.io.IOException;

import java.math.BigInteger;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;

import java.security.cert.X509Certificate;
import java.security.spec.ECFieldF2m;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.RSAPublicKeySpec;

import java.util.Vector;

import org.webpki.crypto.CertificateUtil;
import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.MACAlgorithms;
import org.webpki.crypto.KeyAlgorithms;
import org.webpki.util.ArrayUtil;

import org.bouncycastle.jce.ECNamedCurveTable;

import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;

/**
 * Decoder for JSON signatures.
 */
public class ECDump
  {
    static int field_size;
    static StringBuffer s = new StringBuffer ();

    
    static String SPACES = "                 ";
    static String COMMA_SPACE = ",\n" + SPACES;

    public static void main (String[] argc)
      {
        try
          {
            for (KeyAlgorithms named_curve : KeyAlgorithms.values ())
              {
                s.append ("    ")
                 .append (named_curve.toString ());
                while (s.length () < SPACES.length () - 1)
                  {
                    s.append (' ');
                  }
                s.append ('(');
                if (named_curve.getECDomainOID () == null)
                  {
                    s.append ("null");
                  }
                else
                  {
                    s.append ('\"')
                     .append (named_curve.getECDomainOID ())
                     .append ('\"');
                  }
                s.append (COMMA_SPACE + '\"')
                 .append (named_curve.getURI ())
                 .append ('\"' + COMMA_SPACE + '\"')
                 .append (named_curve.getJCEName ())
                 .append ('\"' + COMMA_SPACE)
                 .append (named_curve.getPublicKeySizeInBits ())
                 .append (COMMA_SPACE)
                 .append ("AsymSignatureAlgorithms.")
                 .append (named_curve.getRecommendedSignatureAlgorithm ().toString ())
                 .append (COMMA_SPACE)
                 .append (named_curve.hasParameters ())
                 .append (COMMA_SPACE)
                 .append (named_curve.isMandatorySKSAlgorithm ());
                 
                
                if (named_curve.getECDomainOID () == null)
                  {
                    nullArg (s);
                    nullArg (s);
                    nullArg (s);
                    nullArg (s);
                    nullArg (s);
                    nullArg (s);
                    s.append (COMMA_SPACE)
                     .append (0)
                     .append (COMMA_SPACE + "false");
                  }
                else
                  {
                    ECNamedCurveParameterSpec curve_params = ECNamedCurveTable.getParameterSpec (named_curve.getJCEName ());
                    if (curve_params == null)
                      {
                        throw new IOException ("Provider doesn't support: " + named_curve.getURI ());
                      }
/*
    P_192       ("1.2.840.10045.3.1.1",
                 "http://xmlns.webpki.org/sks/algorithm#ec.p192",
                 "secp192r1",
                 192,
                 AsymSignatureAlgorithms.ECDSA_SHA256,
                 false,
                 false),
*/
                    ECParameterSpec ec_params = new ECNamedCurveSpec (named_curve.getJCEName (), curve_params.getCurve (), curve_params.getG (), curve_params.getN ());
                    field_size = ec_params.getCurve ().getField ().getFieldSize ();
                    hex (ec_params.getCurve ().getField () instanceof ECFieldF2m ? ((ECFieldF2m) ec_params.getCurve ().getField ()).getReductionPolynomial () : ((ECFieldFp) ec_params.getCurve ().getField ()).getP ());
                    hex (ec_params.getCurve ().getA ());
                    hex (ec_params.getCurve ().getB ());
                    hex (ec_params.getGenerator ().getAffineX ());
                    hex (ec_params.getGenerator ().getAffineY ());
                    hex (ec_params.getOrder ());
                    s.append (COMMA_SPACE)
                     .append (ec_params.getCofactor ())
                     .append (COMMA_SPACE)
                     .append (ec_params.getCurve ().getField () instanceof ECFieldF2m);
  //                  System.out.println (s.toString ()  + field + a + b + x + y + order + cofactor + ",\n");

                    /*
                    System.out.println ("curve=" + named_curve + "\ngen_x=" + ec_params.getGenerator ().getAffineX ().toString (16) + "\ngen_y=" + ec_params.getGenerator ().getAffineY ().toString (16) + "\ncurve_a=" + ec_params.getCurve ().getA ().toString (16) + "\ncurve_b=" + ec_params.getCurve ().getB ().toString (16) + "\ncurve_fieldSize=" + ec_params.getCurve ().getField ().getFieldSize ());
                    if (ec_params.getCurve ().getField () instanceof ECFieldF2m)
                      {
                        System.out.print ("curve_F2M=" + ((ECFieldF2m) ec_params.getCurve ().getField ()).getM () + "\ncurve_F2MRP=" + ((ECFieldF2m) ec_params.getCurve ().getField ()).getReductionPolynomial ().toString (16));
                      }
                    else
                      {
                        System.out.print ("curve_FP=" + ((ECFieldFp) ec_params.getCurve ().getField ()).getP ().toString (16));
                      }
                    System.out.println ("\norder=" + ec_params.getOrder ().toString (16) + "\ncofactor=" + ec_params.getCofactor ());
                    ec_params = new ECParameterSpec (new EllipticCurve (ec_params.getCurve ().getField () instanceof ECFieldF2m ? new ECFieldF2m (((ECFieldF2m) ec_params.getCurve ().getField ()).getM ()) : new ECFieldFp (((ECFieldFp) ec_params.getCurve ().getField ()).getP ()), ec_params.getCurve ().getA (), ec_params.getCurve ().getB ()), new ECPoint (ec_params.getGenerator ().getAffineX (), ec_params.getGenerator ().getAffineY ()), ec_params.getOrder (), ec_params.getCofactor ());
                    */
                  }
                
                s.append ("),\n\n");
              }
            ArrayUtil.writeFile (argc[0], s.toString ().getBytes ("UTF-8"));
          }
        catch (Exception e)
          {
            System.out.println (e.getMessage ());
          }
      }

    private static void nullArg (StringBuffer s)
      {
        s.append (COMMA_SPACE + "null");
      }

    private static void hex (BigInteger v)
      {
        String ret = v.toString (16).toUpperCase ();
        int n = field_size;
        if ((n & 1) == 1)
          {
            n += 4;
          }
        s.append (COMMA_SPACE + "\"");
        while (ret.length () * 4 < n)
          {
            ret = '0' + ret;
          }
        s.append (ret).append ('\"');
      }

  }
