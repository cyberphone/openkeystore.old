package org.webpki.sks.test;

import java.security.SecureRandom;

import org.webpki.util.Base64;
import org.webpki.util.DebugFormatter;

public class Random
  {
    public static void main (String[] argc)
      {
        if (argc.length != 2 || !(argc[1].equals ("hex") || argc[1].equals ("b64")))
          {
            System.out.println ("nr-of-bytes {hex|b64}");
            System.exit (3);
          }
        int n = Integer.parseInt (argc[0]);
        byte[] rnd = new byte[n];
        new SecureRandom ().nextBytes (rnd);
        if (argc[1].equals ("hex"))
          {
            System.out.println (DebugFormatter.getHexString (rnd));
          }
        else
          {
            System.out.println (new Base64 ().getBase64StringFromBinary (rnd));
          }
      }
  }
