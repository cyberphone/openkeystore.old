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
package org.webpki.mobile.android.sks;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import java.math.BigInteger;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

import java.security.spec.ECGenParameterSpec;

import java.util.Date;

import org.spongycastle.jce.X509Principal;
import org.spongycastle.jce.provider.BouncyCastleProvider;

import org.spongycastle.x509.X509V3CertificateGenerator;

import android.content.Context;

import android.provider.Settings;
import android.util.Log;

@SuppressWarnings("deprecation")
public abstract class SKSStore
  {
    private static final String PERSISTENCE_SKS      = "SKS";  // SKS persistence file
    
    private static SKSImplementation sks;

    public static SKSImplementation createSKS (String caller_for_log, Context caller, boolean save_if_new)
      {
        if (sks == null)
          {
            try
              {
                Security.insertProviderAt (new BouncyCastleProvider (), 1);
                sks = (SKSImplementation) new ObjectInputStream (caller.openFileInput(PERSISTENCE_SKS)).readObject ();
              }
            catch (Exception e)
              {
                Log.i (caller_for_log, "No SKS found, recreating it");
                try
                  {
                    KeyPairGenerator generator = KeyPairGenerator.getInstance ("EC");
                    ECGenParameterSpec eccgen = new ECGenParameterSpec ("secp256r1");
                    generator.initialize (eccgen, new SecureRandom ());
                    KeyPair kp = generator.generateKeyPair ();
                    X509V3CertificateGenerator cert_gen = new X509V3CertificateGenerator();
                    byte[] serial = new byte[8];
                    new SecureRandom ().nextBytes (serial);
                    cert_gen.setSerialNumber (new BigInteger (1, serial));
                    String android_id = Settings.Secure.getString(caller.getContentResolver(), Settings.Secure.ANDROID_ID);
                    X509Principal x509_name = new X509Principal ("serialNumber=" + (android_id == null ? "N/A" : android_id) +
                                                                 ",CN=Android SKS"); 
                    cert_gen.setIssuerDN (x509_name);  
                    cert_gen.setNotBefore (new Date(System.currentTimeMillis() - 1000L * 60 * 10));  // EJBCA also uses 10 minutes predating...
                    cert_gen.setNotAfter (new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 365 * 25)));  
                    cert_gen.setSubjectDN (x509_name);  
                    cert_gen.setPublicKey (kp.getPublic ());  
                    cert_gen.setSignatureAlgorithm ("SHA256withECDSA");   
                    sks = new SKSImplementation (cert_gen.generateX509Certificate (kp.getPrivate ()), kp.getPrivate ());
                    if (save_if_new)
                      {
                        serializeSKS (caller_for_log, caller);
                      }
                  }
                catch (Exception e2)
                  {
                    Log.e (caller_for_log, e2.getMessage ());
                   }
              }
          }
        return sks;
      }
    
    public static void serializeSKS (String caller_for_log, Context caller)
      {
        if (sks != null)
          {
            try
              {
                ObjectOutputStream oos = new ObjectOutputStream (caller.openFileOutput(PERSISTENCE_SKS, Context.MODE_PRIVATE));
                oos.writeObject (sks);
                oos.close ();
              }
            catch (Exception e)
              {
                Log.e (caller_for_log, "Couldn't write SKS");
              }
          }
      }
  }
