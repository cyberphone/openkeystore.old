/*
 *  Copyright 2006-2010 WebPKI.org (http://webpki.org).
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

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;

import java.math.BigInteger;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.Test;
import org.junit.BeforeClass;
import static org.junit.Assert.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.webpki.asn1.cert.DistinguishedName;

import org.webpki.ca.CA;
import org.webpki.ca.CertSpec;

import org.webpki.crypto.AsymKeySignerInterface;
import org.webpki.crypto.CertificateUtil;
import org.webpki.crypto.ECDomains;
import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.KeyUsageBits;
import org.webpki.crypto.MacAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.crypto.SymKeySignerInterface;

import org.webpki.crypto.test.DemoKeyStore;

import org.webpki.keygen2.CryptoConstants;
import org.webpki.keygen2.InputMethod;
import org.webpki.keygen2.KeyGen2URIs;
import org.webpki.keygen2.KeyUsage;
import org.webpki.keygen2.PINGrouping;
import org.webpki.keygen2.PassphraseFormat;
import org.webpki.keygen2.PatternRestriction;
import org.webpki.keygen2.ServerSessionKeyInterface;

import org.webpki.sks.DeviceInfo;
import org.webpki.sks.EnumeratedKey;
import org.webpki.sks.EnumeratedProvisioningSession;
import org.webpki.sks.KeyAttributes;
import org.webpki.sks.KeyPair;
import org.webpki.sks.ProvisioningSession;
import org.webpki.sks.SKSException;
import org.webpki.sks.SecureKeyStore;

import org.webpki.util.ArrayUtil;

public class SKSTest
  {
    static final byte[] TEST_STRING = new byte[]{'S','u','c','c','e','s','s',' ','o','r',' ','n','t','?'};
  
    static FileOutputStream fos;
    
    static SecureKeyStore sks;
    
    Device device;
    
   
    @BeforeClass
    public static void openFile () throws Exception
      {
        String dir = System.getProperty ("test.dir");
        if (dir.length () > 0)
          {
            fos = new FileOutputStream (dir + "/" + SKSTest.class.getCanonicalName () + ".txt");
          }
        Security.addProvider(new BouncyCastleProvider());
        sks = (SecureKeyStore) Class.forName (System.getProperty ("sks.implementation")).newInstance ();
      }

    @AfterClass
    public static void closeFile () throws Exception
      {
        if (fos != null)
          {
            fos.close ();
          }
      }
    
    @Before
    public void setup () throws Exception
      {
         device = new Device (sks);
         writeString ("Begin Test\n");
      }
        
    @After
    public void teardown () throws Exception
      {
         writeString ("End Test\n");
         EnumeratedProvisioningSession eps = new EnumeratedProvisioningSession ();
         while ((eps = sks.enumerateProvisioningSessions (eps, true)).isValid ())
           {
             writeString ("Deleted session: " + eps.getProvisioningHandle () + "\n");
             sks.abortProvisioningSession (eps.getProvisioningHandle ());
           }
      }
        
    private void write (byte[] data) throws Exception
      {
        if (fos != null)
          {
            fos.write (data);
          }
      }
    
    private void write (int b) throws Exception
      {
        write (new byte[]{(byte)b}); 
      }
    
    private void writeString (String message) throws Exception
      {
        write (message.getBytes ("UTF-8"));
      }
    
      
    @Test
    public void test1 () throws Exception
      {
        new ProvSess (device).closeSession ();
      }
    @Test(expected=SKSException.class)
    public void test2 () throws Exception
      {
        ProvSess sess = new ProvSess (device);
        sess.createPINPolicy ("PIN",
                              PassphraseFormat.NUMERIC,
                              4 /* min_length */, 
                              8 /* max_length */,
                              (short) 3 /* retry_limit*/, 
                              null /* puk_policy */);
        sess.closeSession ();
      }
    @Test
    public void test3 () throws Exception
      {
        ProvSess sess = new ProvSess (device);
        sess.createPINPolicy ("PIN",
                              PassphraseFormat.NUMERIC,
                              4 /* min_length */, 
                              8 /* max_length */,
                              (short) 3 /* retry_limit*/, 
                              null /* puk_policy */);
        sess.createPUKPolicy ("PUK",
                              PassphraseFormat.NUMERIC,
                              (short) 3 /* retry_limit*/, 
                              "012355" /* puk_policy */);
      }
    @Test(expected=SKSException.class)
    public void test4 () throws Exception
      {
        ProvSess sess = new ProvSess (device);
        PUKPol puk = sess.createPUKPolicy ("PUK",
                                              PassphraseFormat.NUMERIC,
                                              (short) 3 /* retry_limit*/, 
                                              "012355" /* puk_policy */);
        sess.createPINPolicy ("PIN",
                              PassphraseFormat.NUMERIC,
                              4 /* min_length */, 
                              8 /* max_length */,
                              (short) 3 /* retry_limit*/, 
                              puk /* puk_policy */);
        sess.closeSession ();
      }
    @Test(expected=SKSException.class)
    public void test5 () throws Exception
      {
        ProvSess sess = new ProvSess (device);
        sess.createRSAKey ("Key.1",
                           2048 /* rsa_size */,
                           null /* pin_value */,
                           null /* pin_policy */,
                           KeyUsage.AUTHENTICATION);
        sess.closeSession ();
      }
    @Test
    public void test6 () throws Exception
      {
        ProvSess sess = new ProvSess (device);
        sess.createRSAKey ("Key.1",
                           2048 /* rsa_size */,
                           null /* pin_value */,
                           null /* pin_policy */,
                           KeyUsage.AUTHENTICATION).setCertificate ("CN=TEST6");
        sess.closeSession ();
      }
    @Test
    public void test7 () throws Exception
      {
        ProvSess sess = new ProvSess (device);
        sess.createECKey ("Key.1",
                           null /* pin_value */,
                           null /* pin_policy */,
                           KeyUsage.AUTHENTICATION).setCertificate ("CN=TEST7");
        sess.closeSession ();
        
      }
    @Test
    public void test8 () throws Exception
      {
        ProvSess sess = new ProvSess (device);
        GenKey key = sess.createECKey ("Key.1",
                                       null /* pin_value */,
                                       null /* pin_policy */,
                                       KeyUsage.AUTHENTICATION).setCertificate ("CN=TEST8");
        sess.closeSession ();
        byte[] result = device.sks.signHashedData (key.key_handle, 
                                                   "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", 
                                                   new byte[0], 
                                                   HashAlgorithms.SHA256.digest (TEST_STRING));
        Signature verify = Signature.getInstance (SignatureAlgorithms.ECDSA_SHA256.getJCEName (), "BC");
        verify.initVerify (key.cert_path[0]);
        verify.update (TEST_STRING);
        if (!verify.verify (result))
          {
            fail ("Bad signature");
          }
      }
    @Test
    public void test9 () throws Exception
      {
        ProvSess sess = new ProvSess (device);
        GenKey key = sess.createRSAKey ("Key.1",
                                        2048,
                                        null /* pin_value */,
                                        null /* pin_policy */,
                                        KeyUsage.AUTHENTICATION).setCertificate ("CN=TEST9");
        sess.closeSession ();
        byte[] result = device.sks.signHashedData (key.key_handle, 
                                                   "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", 
                                                   new byte[0], 
                                                   HashAlgorithms.SHA256.digest (TEST_STRING));
        Signature verify = Signature.getInstance (SignatureAlgorithms.RSA_SHA256.getJCEName (), "BC");
        verify.initVerify (key.cert_path[0]);
        verify.update (TEST_STRING);
        if (!verify.verify (result))
          {
            fail ("Bad signature");
          }
        result = device.sks.signHashedData (key.key_handle, 
                                            "http://www.w3.org/2000/09/xmldsig#rsa-sha1", 
                                            new byte[0], 
                                            HashAlgorithms.SHA1.digest (TEST_STRING));
        verify = Signature.getInstance (SignatureAlgorithms.RSA_SHA1.getJCEName (), "BC");
        verify.initVerify (key.cert_path[0]);
        verify.update (TEST_STRING);
        if (!verify.verify (result))
          {
            fail ("Bad signature");
          }
      }

  }
