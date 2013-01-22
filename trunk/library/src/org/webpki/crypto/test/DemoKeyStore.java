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

    public static KeyStore getECDSAStore () throws IOException
      {
        return new DemoKeyStore ().getKeyStore ("ecdsa.jks");
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
