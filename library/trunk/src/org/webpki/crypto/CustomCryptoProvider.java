/*
 *  Copyright 2006-2013 WebPKI.org (http://webpki.org).
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

import java.security.Provider;
import java.security.Security;

import java.util.logging.Logger;

/**
 * Bouncycastle loader
 */
public class CustomCryptoProvider
  {
    private static Logger logger = Logger.getLogger (CustomCryptoProvider.class.getCanonicalName ());
    
    private CustomCryptoProvider () {};

    static boolean bc_flag;
    static
      {
        try
          {
            @SuppressWarnings("rawtypes")
            Class bc = Class.forName ("org.bouncycastle.jce.provider.BouncyCastleProvider");
            try
              {
                Security.insertProviderAt ((Provider) bc.newInstance (), 1);
                bc_flag = true;
                logger.info ("BouncyCastle found and loaded as the first provider");
              }
            catch (Exception e)
              {
                new RuntimeException (e);
              }
          }
        catch (Exception e)
          {
            logger.info ("BouncyCastle NOT found");
          }
      }

    public static boolean conditionalLoad ()
      {
        return bc_flag;
      }

    public static void forcedLoad ()
      {
        if (!bc_flag)
          {
            throw new RuntimeException ("BC missing!");
          }
      }
  }