package org.webpki.keygen2.test;

import java.io.IOException;
import java.security.KeyStore;
import java.security.GeneralSecurityException;


public class TPMKeyStore
  {

    public static String getSignerPassword ()
      {
        return "thetpm";
      }

    private TPMKeyStore ()
      {
      }

    public static KeyStore getTPMKeyStore () throws IOException
      {
        return new TPMKeyStore ().getKeyStore ("tpmcert.ks");
      }

    public static KeyStore getCAKeyStore () throws IOException
      {
        return new TPMKeyStore ().getKeyStore ("tpmroot.ks");
      }

    private KeyStore getKeyStore (String name) throws IOException
      {
        try
          {
            KeyStore ks = KeyStore.getInstance ("JKS");
            ks.load (getClass().getResourceAsStream (name), "testing".toCharArray());
            return ks;
          }
        catch (GeneralSecurityException e)
          {
            throw new IOException (e.getMessage ());
          }
      }

  }
