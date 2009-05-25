package org.webpki.infocard.test;

import org.webpki.util.ArrayUtil;

import org.webpki.crypto.test.DemoKeyStore;

import org.webpki.crypto.JKSCAVerifier;

import org.webpki.infocard.InfoCardReader;

public class readcard
  {

    private static void show ()
      {
        System.out.println ("readcard in_file\n");
        System.exit (3);
      }

    public static void main (String args[]) throws Exception
      {
        if (args.length < 1) show ();
        JKSCAVerifier verifier = new JKSCAVerifier (DemoKeyStore.getCAKeyStore ());
        verifier.setTrustedRequired (false);
        new InfoCardReader (ArrayUtil.readFile (args[0]), verifier);

      }
  }
