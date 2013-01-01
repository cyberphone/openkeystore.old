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
package org.webpki.crypto.test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;

import java.security.spec.ECGenParameterSpec;

import javax.crypto.KeyAgreement;

import org.webpki.crypto.KeyAlgorithms;

public class ECKeyExperiments
  {

    // Just to verify that NIST curves are identical for ECDH and ECDSA

    private ECKeyExperiments ()
      {
      }
    
    private static KeyPair gen (KeyAlgorithms key_alg) throws Exception
      {
        KeyPairGenerator generator = KeyPairGenerator.getInstance ("EC");
        ECGenParameterSpec eccgen = new ECGenParameterSpec (key_alg.getJCEName ());
        generator.initialize(eccgen, new SecureRandom());
        return generator.generateKeyPair();
      }

    static byte[] data = new byte[]{4, 5, 6, 7, 8, 0};
    
    static String ECC_SIGNATURE = "SHA256withECDSA";
    
    
    private static void signverify (KeyPair kp) throws Exception
      {
        Signature signer = Signature.getInstance (ECC_SIGNATURE);
        signer.initSign (kp.getPrivate ());
        signer.update (data);
        byte[] signature = signer.sign ();

        Signature verifier = Signature.getInstance (ECC_SIGNATURE);
        verifier.initVerify (kp.getPublic ());
        verifier.update (data);

        if (!verifier.verify (signature))
          {
            throw new RuntimeException ("Bad sign");
          }
     
      }
    
    private static void execute (KeyAlgorithms key_alg) throws Exception
      {
        KeyPair kp1 = gen (key_alg);
        KeyPair kp2 = gen (key_alg);
        KeyAgreement ka1 = KeyAgreement.getInstance("ECDH");

        ka1.init(kp1.getPrivate());

        KeyAgreement ka2 = KeyAgreement.getInstance("ECDH");

        ka2.init(kp2.getPrivate());

        ka1.doPhase(kp2.getPublic(), true);
        ka2.doPhase(kp1.getPublic(), true);

        BigInteger  k1 = new BigInteger(ka1.generateSecret());
        BigInteger  k2 = new BigInteger(ka2.generateSecret());

        if (!k1.equals(k2))
        {
            throw new RuntimeException (key_alg + " 2-way test failed");
        }
        System.out.println ("ECDH Worked");
        signverify (kp1);
        signverify (kp2);
        System.out.println ("ECDSA Worked");
      }

    public static void main (String[] argv) throws Exception
      {
        try
          {
            Class<?> clazz = Class.forName ("org.bouncycastle.jce.provider.BouncyCastleProvider");
            Security.insertProviderAt ((Provider) clazz.newInstance (), 1);
          }
        catch (Exception e)
          {
            System.out.println ("BC not found");
          }
        for (KeyAlgorithms key_alg : KeyAlgorithms.values ())
          {
            if (key_alg.isECKey ())
              {
                execute (key_alg);
              }
          }
       }

  }
