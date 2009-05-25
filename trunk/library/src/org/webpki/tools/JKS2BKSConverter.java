package org.webpki.tools;

import java.io.FileInputStream;
import java.io.FileOutputStream;

import java.util.Enumeration;

import java.security.KeyStore;
import java.security.Key;

import java.security.cert.Certificate;


public class JKS2BKSConverter
  {

    public static void main (String argv[]) throws Exception
      {
        if (argv.length != 4)
          {
            System.out.println (JKS2BKSConverter.class.getName () + "  jksfile  bksfile/-same  storepass  keypass");
            System.exit (3);
          }
        KeyStore jks = KeyStore.getInstance ("JKS");
        jks.load (new FileInputStream (argv[0]), argv[2].toCharArray ());
        KeyStore bks = KeyStore.getInstance ("BKS");
        bks.load (null, null);
        Enumeration<String> aliases = jks.aliases ();
        while (aliases.hasMoreElements ())
          {
            String alias = aliases.nextElement ();
            if (jks.isKeyEntry (alias))
              {
                Certificate[] chain = jks.getCertificateChain (alias);
                Key key = jks.getKey (alias, argv[3].toCharArray ());
                bks.setKeyEntry (alias, key, argv[3].toCharArray (), chain);
              }
            else if (jks.isCertificateEntry (alias))
              {
                Certificate certificate = jks.getCertificate (alias);
                bks.setCertificateEntry (alias, certificate);
              }
            else
              {
                throw new Exception ("Bad KS");
              }
          }
        bks.store (new FileOutputStream (argv[1].equals ("-same") ? argv[0] : argv[1]), argv[2].toCharArray ());
      }

  }
