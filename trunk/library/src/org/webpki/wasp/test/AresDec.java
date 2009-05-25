package org.webpki.wasp.test;

import org.webpki.util.ArrayUtil;

import org.webpki.xml.XMLSchemaCache;

import org.webpki.crypto.JKSCAVerifier;
import org.webpki.crypto.test.DemoKeyStore;

import org.webpki.wasp.AuthenticationResponseDecoder;



public class AresDec
  {

    private static void show ()
      {
        System.out.println ("AresDec inputfile\n");
        System.exit (3);
      }

    static AuthenticationResponseDecoder test (String in_file) throws Exception
      {
        byte[] data = ArrayUtil.readFile (in_file);
        XMLSchemaCache schema_cache = new XMLSchemaCache ();
        schema_cache.addWrapper (AuthenticationResponseDecoder.class);

        AuthenticationResponseDecoder ares = (AuthenticationResponseDecoder) schema_cache.parse (data);

        JKSCAVerifier verifier = new JKSCAVerifier (DemoKeyStore.getCAKeyStore ());
        verifier.setTrustedRequired (false);

        ares.verifySignature (verifier);

        System.out.println ("\nUSER AUTHENTICATION VERIFIED\n" + verifier.getSignerCertificateInfo ().toString ());
        return ares;
      }


    public static void main (String args[]) throws Exception
      {
        if (args.length != 1) show ();
        test (args[0]);
      }
  }
