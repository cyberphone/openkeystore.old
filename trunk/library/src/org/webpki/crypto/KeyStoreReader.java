package org.webpki.crypto;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;

import org.webpki.util.ArrayUtil;

public abstract class KeyStoreReader
  {
    public static KeyStore loadKeyStore (String keystore_file_name, String password) throws IOException
      {
        try
          {
            byte[] buffer = ArrayUtil.readFile (keystore_file_name);
            // JKS magic number + version (2)
            byte[] jks = {(byte)0xfe, (byte)0xed, (byte)0xfe, (byte)0xed, 0, 0, 0, 2};
            String type = "JKS";
            for (int i = 0; i < 8; i++)
              {
                if (buffer[i] != jks[i])
                  {
                    type = "PKCS12";
                    break;
                  }
              }
            KeyStore ks = KeyStore.getInstance (type);
            ks.load (new ByteArrayInputStream (buffer), password.toCharArray ());
            return ks;
          }
        catch (GeneralSecurityException gse)
          {
            throw new IOException (gse);
          }
      }
  }
