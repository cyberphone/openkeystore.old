/*
 *  Copyright 2006-2011 WebPKI.org (http://webpki.org).
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
package org.webpki.sks.test;

import java.io.FileInputStream;
import java.io.IOException;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import java.util.Enumeration;
import java.util.Vector;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.webpki.sks.AppUsage;
import org.webpki.sks.PassphraseFormat;
import org.webpki.sks.SecureKeyStore;

public class PKCS12Import
  {
    public static void main (String[] argc) throws Exception
      {
        if (argc.length != 3)
          {
            System.out.println ("\nUsage: " + PKCS12Import.class.getCanonicalName () + 
                                " file password pin-or-zero-length-arg");
            System.exit (-3);
          }
        char[] password = argc[1].toCharArray ();
        Security.insertProviderAt (new BouncyCastleProvider(), 1);
        KeyStore ks = KeyStore.getInstance ("PKCS12");
        ks.load (new FileInputStream (argc[0]), password);
        Vector<X509Certificate> cert_path = new Vector<X509Certificate> ();
        PrivateKey private_key = null;
        Enumeration<String> aliases = ks.aliases ();
        while (aliases.hasMoreElements ())
          {
            String alias = aliases.nextElement ();
            if (ks.isKeyEntry (alias))
              {
                private_key = (PrivateKey) ks.getKey (alias, password);
                for (Certificate cert : ks.getCertificateChain (alias))
                  {
                    cert_path.add ((X509Certificate) cert);
                  }
                break;
              }
          }
        if (private_key == null)
          {
            throw new IOException ("No private key!");
          }
        SecureKeyStore sks = (SecureKeyStore) Class.forName (System.getProperty ("sks.client")).newInstance ();
        boolean reference_implementation = sks instanceof SKSReferenceImplementation;
        Device device = new Device (sks);
        ProvSess sess = new ProvSess (device);
        PINPol pin_policy = null;
        String pin = argc[2].trim ();
        if (pin.length () > 0)
          {
            pin_policy = sess.createPINPolicy ("PIN",
                                               PassphraseFormat.STRING,
                                               1 /* min_length */, 
                                               50 /* max_length */,
                                               (short) 3 /* retry_limit*/, 
                                               null /* puk_policy */);            
          }
        else
          {
            pin = null;
          }
        GenKey key = sess.createECKey ("Key",
                                       pin /* pin_value */,
                                       pin_policy /* pin_policy */,
                                       AppUsage.AUTHENTICATION);
        key.setCertificate (cert_path.toArray (new X509Certificate[0]));
        key.restorePrivateKey (private_key);
        sess.closeSession ();
      }
  }
