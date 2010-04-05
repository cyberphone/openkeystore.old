package org.webpki.crypto.test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import java.security.spec.ECGenParameterSpec;

import org.webpki.util.Base64;

public class GenECKey
  {


    private GenECKey ()
      {
      }

    public static void main (String[] argv) throws Exception
      {
        KeyPairGenerator generator = KeyPairGenerator.getInstance ("EC");
        ECGenParameterSpec eccgen = new ECGenParameterSpec ("P-256");
        generator.initialize(eccgen);
        KeyPair keypair = generator.generateKeyPair();
        System.out.println ("Public Key\n" + 
                             new Base64 (true).getBase64StringFromBinary (keypair.getPublic ().getEncoded ()) +
                             "\n\nPrivate Key\n" +
                             new Base64 (true).getBase64StringFromBinary (keypair.getPrivate ().getEncoded ()));
      }

  }
