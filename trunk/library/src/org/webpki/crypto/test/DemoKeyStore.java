package org.webpki.crypto.test;

import java.io.IOException;
import java.security.KeyStore;
import java.security.GeneralSecurityException;


public class DemoKeyStore
  {

    public static String getSignerPassword ()
      {
        return "testing";
      }

    private DemoKeyStore ()
      {
      }

    public static KeyStore getMarionKeyStore () throws IOException
      {
        return new DemoKeyStore ().getKeyStore ("marion.ks");
      }

    public static KeyStore getExampleDotComKeyStore () throws IOException
      {
        return new DemoKeyStore ().getKeyStore ("example.ks");
      }

    public static KeyStore getMybankDotComKeyStore () throws IOException
      {
        return new DemoKeyStore ().getKeyStore ("mybank.ks");
      }

    public static KeyStore getCAKeyStore () throws IOException
      {
        return new DemoKeyStore ().getKeyStore ("root.ks");
      }

    public static KeyStore getSubCAKeyStore () throws IOException
      {
        return new DemoKeyStore ().getKeyStore ("subca.ks");
      }

    private KeyStore getKeyStore (String name) throws IOException
      {
        try
          {
            KeyStore ks = KeyStore.getInstance ("JKS");
            ks.load (getClass().getResourceAsStream (name), getSignerPassword ().toCharArray());
            return ks;
          }
        catch (GeneralSecurityException e)
          {
            throw new IOException (e.getMessage ());
          }
      }

  }
