package org.webpki.keygen2.test;

import java.security.Security;

import org.webpki.util.ArrayUtil;

import org.webpki.xml.XMLSchemaCache;

import org.webpki.crypto.JKSCAVerifier;

import org.webpki.keygen2.IssuerCredentialStore;
import org.webpki.keygen2.KeyInitializationRequestEncoder;
import org.webpki.keygen2.KeyInitializationResponseDecoder;
import org.webpki.keygen2.KeyInitializationResponseEncoder;

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
        KeyInitializationRequestEncoder kgre = null;
        IssuerCredentialStore ics = null;
        kgrd.validateAndPopulate (kgre, null);
        for (IssuerCredentialStore.KeyProperties k : ics.getKeyProperties ())
          {
            System.out.println ("ID=" + k.getID () + " PublicKey=" + k.getPublicKey () +
                (k.getEncryptedPrivateKey () == null ? "" : "\n PRIVATE KEY"));
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
