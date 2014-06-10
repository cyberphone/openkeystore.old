/*
 *  Copyright 2006-2014 WebPKI.org (http://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.webpki.crypto;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;

import org.webpki.util.ArrayUtil;

public class KeyStoreReader
  {
    private KeyStoreReader () {} // No instantiation

    public static KeyStore loadKeyStore (String keystore_file_name, String password) throws IOException
      {
        try
          {
            byte[] buffer = ArrayUtil.readFile (keystore_file_name);
            byte[] jks = {0, 0, 0, 1, 0, 0, 0, 20}; // BKS: (int)VERSION + (int)SALT_LENGTH
            String type = "BKS";
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
