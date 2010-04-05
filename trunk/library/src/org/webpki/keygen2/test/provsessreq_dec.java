package org.webpki.keygen2.test;

import org.webpki.util.ArrayUtil;

import org.webpki.xml.XMLSchemaCache;

import org.webpki.crypto.test.DemoKeyStore;
import org.webpki.crypto.test.ECKeys;

import org.webpki.crypto.JKSCAVerifier;

import org.webpki.keygen2.ProvisioningSessionRequestDecoder;

public class provsessreq_dec
  {
    
    private static void show ()
      {
        System.out.println ("keyopreq_dec in_file\n");
        System.exit (3);
      }


    public static void main (String args[]) throws Exception
      {
        if (args.length < 1) show ();
        XMLSchemaCache cache = new XMLSchemaCache ();
        cache.addWrapper (ProvisioningSessionRequestDecoder.class);
        ProvisioningSessionRequestDecoder kgrd = (ProvisioningSessionRequestDecoder)cache.parse (ArrayUtil.readFile (args[0]));
        if (!kgrd.getServerEphemeralKey ().equals (ECKeys.PUBLIC_KEY1))
          {
            System.out.println ("Not same EC");
          }

        if (kgrd.isSigned ())
          {
            JKSCAVerifier verifier = new JKSCAVerifier (DemoKeyStore.getCAKeyStore ());
            verifier.setTrustedRequired (false);
            kgrd.verifySignature (verifier);
            System.out.println ("\nSIGNATURE\n" + verifier.getSignerCertificateInfo ().toString () + "\nSIGNATURE");
          }

      }
  }
