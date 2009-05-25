package org.webpki.keygen2.test;

import org.webpki.util.ArrayUtil;

import org.webpki.xml.XMLSchemaCache;

import org.webpki.crypto.JKSCAVerifier;

import org.webpki.keygen2.KeyOperationResponseDecoder;

public class keyopres_dec
  {

    private static void show ()
      {
        System.out.println ("keyopres_dec in_file\n");
        System.exit (3);
      }


    public static void main (String args[]) throws Exception
      {
        if (args.length < 1) show ();
        XMLSchemaCache cache = new XMLSchemaCache ();
        cache.addWrapper (KeyOperationResponseDecoder.class);
        KeyOperationResponseDecoder kgrd = (KeyOperationResponseDecoder)cache.parse (ArrayUtil.readFile (args[0]));
        for (KeyOperationResponseDecoder.GeneratedPublicKey k : kgrd.getGeneratedPublicKeys ())
          {
            System.out.println ("ID=" + k.getID () + " PublicKey=" + k.getPublicKey ());
          }
        if (kgrd.hasEndorsementKeySignature ())
          {
            JKSCAVerifier verifier = new JKSCAVerifier (TPMKeyStore.getCAKeyStore ());
            verifier.setTrustedRequired (false);

  //          kgrd.verifyEndorsementKeySignature (verifier, false, KeyGen2KeyUsage.AUTHENTICATION);
            System.out.println ("\nTPM SIGNATURE VERIFIED\n" + verifier.getSignerCertificateInfo ().toString ());
          }
      }
  }
