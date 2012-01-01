/*
 *  Copyright 2006-2012 WebPKI.org (http://webpki.org).
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

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import java.security.spec.ECGenParameterSpec;

import org.webpki.util.Base64;

public class GenECKey
  {


    private GenECKey ()
      {
      }

    public static void main (String[] argv) throws Exception
      {
        KeyPairGenerator generator = KeyPairGenerator.getInstance ("EC");
        ECGenParameterSpec eccgen = new ECGenParameterSpec ("P-256");
        generator.initialize(eccgen);
        KeyPair keypair = generator.generateKeyPair();
        System.out.println ("Public Key\n" + 
                             new Base64 (true).getBase64StringFromBinary (keypair.getPublic ().getEncoded ()) +
                             "\n\nPrivate Key\n" +
                             new Base64 (true).getBase64StringFromBinary (keypair.getPrivate ().getEncoded ()));
      }

  }
