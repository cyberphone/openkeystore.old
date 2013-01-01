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

import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import java.security.interfaces.ECPublicKey;

import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;

import org.webpki.asn1.DerDecoder;
import org.webpki.asn1.ParseUtil;
import org.webpki.asn1.BaseASN1Object;
import org.webpki.asn1.ASN1Sequence;
import org.webpki.asn1.ASN1ObjectID;
import org.webpki.asn1.ASN1BitString;
import org.webpki.crypto.KeyAlgorithms;

public class ECDSATest
  {


    private ECDSATest ()
      {
      }
    
    static void execute (KeyAlgorithms key_alg) throws Exception
      {
        KeyPairGenerator generator = KeyPairGenerator.getInstance ("EC");
        ECGenParameterSpec eccgen = new ECGenParameterSpec (key_alg.getJCEName ());
        generator.initialize(eccgen);
        KeyPair keypair = generator.generateKeyPair();
System.out.println ("ALG=" + ((ECPublicKey)keypair.getPublic ()).getAlgorithm () +
" FMT=" + ((ECPublicKey)keypair.getPublic ()).getFormat ());
        BaseASN1Object subjectPublicKeyInfo = DerDecoder.decode (keypair.getPublic ().getEncoded ());
        ASN1Sequence seqo = ParseUtil.sequence(subjectPublicKeyInfo, 2);
String oid = ParseUtil.oid (ParseUtil.sequence(seqo.get(0), 2).get(1)).oid();
byte[] pub = ParseUtil.bitstring(seqo.get(1));
byte[] crepk = new ASN1Sequence (new BaseASN1Object[] {
    new ASN1Sequence (new BaseASN1Object[] {new ASN1ObjectID ("1.2.840.10045.2.1"),
        new ASN1ObjectID (oid)
       }),
new ASN1BitString (pub)
   }).encode ();
PublicKey rpk = KeyFactory.getInstance ("EC").generatePublic (new X509EncodedKeySpec (crepk));

        Signature signer = Signature.getInstance ("SHA256WithECDSA");
        signer.initSign (keypair.getPrivate ());
        byte[] data = "Hej".getBytes ("UTF-8");
        signer.update (data);
        byte[] result = signer.sign ();

        Signature verifier = Signature.getInstance ("SHA256WithECDSA");
        verifier.initVerify (keypair.getPublic ());
        verifier.update (data);
        System.out.println ("Signature OK=" + verifier.verify (result));

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
