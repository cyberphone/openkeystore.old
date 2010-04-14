package org.webpki.keygen2.test;

import java.security.Security;

import org.webpki.util.ArrayUtil;

import org.webpki.xml.XMLSchemaCache;

import org.webpki.crypto.JKSCAVerifier;

import org.webpki.keygen2.KeyInitializationResponseDecoder;

public class keyinitres_dec
  {

    private static void show ()
      {
        System.out.println ("keyinitres_dec in_file\n");
        System.exit (3);
      }


    public static void main (String args[]) throws Exception
      {
        if (args.length < 1) show ();
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        XMLSchemaCache cache = new XMLSchemaCache ();
        cache.addWrapper (KeyInitializationResponseDecoder.class);
        KeyInitializationResponseDecoder kgrd = (KeyInitializationResponseDecoder)cache.parse (ArrayUtil.readFile (args[0]));
        for (KeyInitializationResponseDecoder.GeneratedPublicKey k : kgrd.getGeneratedPublicKeys ())
          {
            System.out.println ("ID=" + k.getID () + " PublicKey=" + k.getPublicKey ());
          }
/*
        if (kgrd.hasEndorsementKeySignature ())
          {
            JKSCAVerifier verifier = new JKSCAVerifier (TPMKeyStore.getCAKeyStore ());
            verifier.setTrustedRequired (false);

  //          kgrd.verifyEndorsementKeySignature (verifier, false, KeyGen2KeyUsage.AUTHENTICATION);
            System.out.println ("\nTPM SIGNATURE VERIFIED\n" + verifier.getSignerCertificateInfo ().toString ());
          }
*/
      }
  }
