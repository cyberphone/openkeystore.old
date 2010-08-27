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

import java.io.FileOutputStream;
import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;

import java.util.EnumSet;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.BeforeClass;
import org.junit.rules.TestName;

import static org.junit.Assert.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.webpki.crypto.AsymEncryptionAlgorithms;
import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.MacAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.crypto.SymEncryptionAlgorithms;

import org.webpki.keygen2.ExportPolicy;
import org.webpki.keygen2.KeyGen2URIs;
import org.webpki.keygen2.KeyUsage;
import org.webpki.keygen2.PINGrouping;
import org.webpki.keygen2.PassphraseFormat;
import org.webpki.keygen2.PatternRestriction;

import org.webpki.sks.EnumeratedProvisioningSession;
import org.webpki.sks.SKSException;
import org.webpki.sks.SecureKeyStore;
import org.webpki.sks.test.SKSReferenceImplementation;
import org.webpki.util.ArrayUtil;

public class SKSTest
  {
    static final byte[] TEST_STRING = new byte[]{'S','u','c','c','e','s','s',' ','o','r',' ','n','o','t','?'};
  
    static FileOutputStream fos;
    
    static SecureKeyStore sks;
    
    static boolean reference_implementation;
    
    Device device;
    
    private int sessionCount () throws Exception
      {
        EnumeratedProvisioningSession eps = new EnumeratedProvisioningSession ();
        int i = 0;
        while ((eps = sks.enumerateProvisioningSessions (eps, false)).isValid ())
          {
            i++;
          }
        return i;
      }
    
    private void edgeDeleteCase (boolean post) throws Exception
      {
        ProvSess sess = new ProvSess (device);
        GenKey key1 = sess.createECKey ("Key.1",
                                        null /* pin_value */,
                                        null /* pin_policy */,
                                        KeyUsage.AUTHENTICATION).setCertificate ("CN=TEST18");
        sess.closeSession ();
        assertTrue (sess.exists ());
        ProvSess sess2 = new ProvSess (device);
        GenKey key3 = sess2.createECKey ("Key.1",
                                         null /* pin_value */,
                                         null /* pin_policy */,
                                         KeyUsage.AUTHENTICATION).setCertificate ("CN=TEST18");
        if (post)
          {
            sess2.postUpdateKey (key3, key1);
          }
        else
          {
            sks.deleteKey (key1.key_handle, new byte[0]);
          }
        try
          {
            if (post)
              {
                sks.deleteKey (key1.key_handle, new byte[0]);
              }
            else
              {
                sess2.postUpdateKey (key3, key1);
              }
            sess2.closeSession ();
            fail ("Multiple updates using the same key");
          }
        catch (SKSException e)
          {
          }
      }

    private void deleteKey (GenKey key) throws SKSException
      {
        sks.deleteKey (key.key_handle, new byte[0]);
      }
    
    
    private void checkException (SKSException e, String compare_message)
      {
        String m = e.getMessage ();
        if (reference_implementation && m != null && compare_message.indexOf ('#') == m.indexOf ('#'))
          {
            int i = m.indexOf ('#') + 1;
            int q = 0;
            while ((q + i) < m.length () && m.charAt (i + q) >= '0' && m.charAt (i + q) <= '9')
              {
                q++;
              }
            m = m.substring (0, i) + m.substring (i + q);
          }
        if (m == null || (reference_implementation && !m.equals (compare_message)))
          {
            fail ("Exception: " + m);
          }
      }
    
    private void authorizationErrorCheck (SKSException e)
      {
        assertTrue ("Wrong return code", e.getError () == SKSException.ERROR_AUTHORIZATION);
        checkException (e, "Authorization error for key #");
      }
    
    private void updateReplace (boolean order) throws Exception
      {
        int q = sessionCount ();
        String ok_pin = "1563";
        ProvSess sess = new ProvSess (device);
        PINPol pin_policy = sess.createPINPolicy ("PIN",
                                                  PassphraseFormat.NUMERIC,
                                                  EnumSet.noneOf (PatternRestriction.class),
                                                  PINGrouping.SHARED,
                                                  4 /* min_length */, 
                                                  8 /* max_length */,
                                                  (short) 3 /* retry_limit*/, 
                                                  null /* puk_policy */);
        GenKey key1 = sess.createECKey ("Key.1",
                                        ok_pin /* pin_value */,
                                        pin_policy,
                                        KeyUsage.AUTHENTICATION).setCertificate ("CN=TEST18");
        sess.closeSession ();
        assertTrue (sess.exists ());
        ProvSess sess2 = new ProvSess (device);
        GenKey key2 = sess2.createECKey ("Key.2",
                                         null /* pin_value */,
                                         null,
                                         KeyUsage.AUTHENTICATION).setCertificate ("CN=TEST18");
        GenKey key3 = sess2.createRSAKey ("Key.1",
                                          2048,
                                          null /* pin_value */,
                                          null /* pin_policy */,
                                          KeyUsage.AUTHENTICATION).setCertificate ("CN=TEST13");
        if (order) sess2.postCloneKey (key3, key1);
        sess2.postUpdateKey (key2, key1);
        if (!order) sess2.postCloneKey (key3, key1);
        sess2.closeSession ();
        assertTrue ("Old key should exist after update", key1.exists ());
        assertFalse ("New key should NOT exist after update", key2.exists ());
        assertTrue ("New key should exist after clone", key3.exists ());
        assertTrue ("Ownership error", key1.getUpdatedKeyInfo ().getProvisioningHandle () == sess2.provisioning_handle);
        assertTrue ("Ownership error", key3.getUpdatedKeyInfo ().getProvisioningHandle () == sess2.provisioning_handle);
        assertFalse ("Managed sessions MUST be deleted", sess.exists ());
        try
          {
            device.sks.signHashedData (key3.key_handle, 
                                       "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", 
                                       new byte[0], 
                                       HashAlgorithms.SHA256.digest (TEST_STRING));
            fail ("Bad PIN should not work");
          }
        catch (SKSException e)
          {
            assertTrue ("There should be an auth error", e.getError () == SKSException.ERROR_AUTHORIZATION);
          }
        try
          {
            byte[] result = device.sks.signHashedData (key3.key_handle, 
                                                      "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", 
                                                       ok_pin.getBytes ("UTF-8"), 
                                                       HashAlgorithms.SHA256.digest (TEST_STRING));
            Signature verify = Signature.getInstance (SignatureAlgorithms.RSA_SHA256.getJCEName (), "BC");
            verify.initVerify (key3.cert_path[0]);
            verify.update (TEST_STRING);
            assertTrue ("Bad signature key3", verify.verify (result));
            result = device.sks.signHashedData (key1.key_handle, 
                                                "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", 
                                                ok_pin.getBytes ("UTF-8"), 
                                                HashAlgorithms.SHA256.digest (TEST_STRING));
            verify = Signature.getInstance (SignatureAlgorithms.ECDSA_SHA256.getJCEName (), "BC");
            verify.initVerify (key2.cert_path[0]);
            verify.update (TEST_STRING);
            assertTrue ("Bad signature key1", verify.verify (result));
          }
        catch (SKSException e)
          {
            fail ("Good PIN should work");
          }
        assertTrue ("Session count", ++q == sessionCount ());
      }

    
    private boolean nameCheck (String name) throws IOException, GeneralSecurityException
      {
        try
          {
            ProvSess sess = new ProvSess (device);
            sess.createPINPolicy (name,
                                  PassphraseFormat.NUMERIC,
                                  4 /* min_length */, 
                                  8 /* max_length */,
                                  (short) 3 /* retry_limit*/, 
                                  null /* puk_policy */);
            sess.abortSession ();
          }
        catch (SKSException e)
          {
            return false;
          }
        return true;
      }
  
    private boolean PINCheck (PassphraseFormat format,
                              PatternRestriction[] patterns,
                              String pin) throws IOException, GeneralSecurityException
      {
        try
          {
            Set<PatternRestriction> pattern_restrictions = EnumSet.noneOf (PatternRestriction.class);
            if (patterns != null)
              {
                for (PatternRestriction pattern : patterns)
                  {
                    pattern_restrictions.add (pattern);
                  }
              }
            ProvSess sess = new ProvSess (device);
            PINPol pin_pol = sess.createPINPolicy ("PIN",
                                                   format,
                                                   pattern_restrictions,
                                                   PINGrouping.NONE,
                                                   4 /* min_length */, 
                                                   8 /* max_length */,
                                                   (short) 3 /* retry_limit*/, 
                                                   null /* puk_policy */);
            sess.createECKey ("Key.1",
                              pin /* pin_value */,
                              pin_pol /* pin_policy */,
                              KeyUsage.AUTHENTICATION).setCertificate ("CN=TEST8");
            sess.abortSession ();
          }
        catch (SKSException e)
          {
            return false;
          }
        return true;
      }

    private boolean PUKCheck (PassphraseFormat format,
                              String puk) throws IOException, GeneralSecurityException
      {
        try
          {
            ProvSess sess = new ProvSess (device);
            sess.createPUKPolicy ("PUK",
                                  format,
                                  (short) 3 /* retry_limit*/, 
                                  puk /* puk_policy */);
            sess.abortSession ();
          }
        catch (SKSException e)
          {
            return false;
          }
        return true;
      }

    private void PINstress(ProvSess sess) throws Exception
      {
        String ok_pin = "1563";
        PINPol pin_policy = sess.createPINPolicy ("PIN",
                                                  PassphraseFormat.NUMERIC,
                                                  4 /* min_length */, 
                                                  8 /* max_length */,
                                                  (short) 3 /* retry_limit*/, 
                                                  null /* puk_policy */);
    
        GenKey key = sess.createRSAKey ("Key.1",
                                        1024,
                                        ok_pin /* pin_value */,
                                        pin_policy /* pin_policy */,
                                        KeyUsage.AUTHENTICATION).setCertificate ("CN=" + name.getMethodName());
        sess.closeSession ();
    
        try
          {
            device.sks.signHashedData (key.key_handle, 
                                       "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", 
                                       new byte[0], 
                                       HashAlgorithms.SHA256.digest (TEST_STRING));
            fail ("Bad PIN should not work");
          }
        catch (SKSException e)
          {
          }
        try
          {
            device.sks.signHashedData (key.key_handle, 
                                       "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", 
                                       ok_pin.getBytes ("UTF-8"), 
                                       HashAlgorithms.SHA256.digest (TEST_STRING));
          }
        catch (SKSException e)
          {
            fail ("Good PIN should work");
          }
        try
          {
            device.sks.signHashedData (key.key_handle, 
                                       "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", 
                                       new byte[0], 
                                       HashAlgorithms.SHA256.digest (TEST_STRING));
            fail ("Bad PIN should not work");
          }
        catch (SKSException e)
          {
          }
        try
          {
            device.sks.signHashedData (key.key_handle, 
                                       "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", 
                                       new byte[0], 
                                       HashAlgorithms.SHA256.digest (TEST_STRING));
            fail ("Bad PIN should not work");
          }
        catch (SKSException e)
          {
          }
        try
          {
            device.sks.signHashedData (key.key_handle, 
                                       "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", 
                                       ok_pin.getBytes ("UTF-8"), 
                                       HashAlgorithms.SHA256.digest (TEST_STRING));
          }
        catch (SKSException e)
          {
            fail ("Good PIN should work");
          }
        try
          {
            device.sks.signHashedData (key.key_handle, 
                                       "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", 
                                       new byte[0], 
                                       HashAlgorithms.SHA256.digest (TEST_STRING));
            fail ("Bad PIN should not work");
          }
        catch (SKSException e)
          {
          }
        try
          {
            device.sks.signHashedData (key.key_handle, 
                                       "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", 
                                       new byte[0], 
                                       HashAlgorithms.SHA256.digest (TEST_STRING));
            fail ("Bad PIN should not work");
          }
        catch (SKSException e)
          {
          }
        try
          {
            device.sks.signHashedData (key.key_handle, 
                                       "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", 
                                       new byte[0], 
                                       HashAlgorithms.SHA256.digest (TEST_STRING));
            fail ("Bad PIN should not work");
          }
        catch (SKSException e)
          {
          }
        try
          {
            device.sks.signHashedData (key.key_handle, 
                                       "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", 
                                       ok_pin.getBytes ("UTF-8"), 
                                       HashAlgorithms.SHA256.digest (TEST_STRING));
            fail ("Good PIN but too many errors should NOT work");
          }
        catch (SKSException e)
          {
          }
      }
     
    private void sessionLimitTest (int limit, boolean encrypted_pin, boolean fail_hard) throws Exception
      {
        ProvSess sess = new ProvSess (device, (short)limit);
        if (encrypted_pin)
          {
            sess.makePINsServerDefined ();
          }
        try
          {
            String ok_pin = "1563";
            PINPol pin_policy = sess.createPINPolicy ("PIN",
                                                      PassphraseFormat.NUMERIC,
                                                      4 /* min_length */, 
                                                      8 /* max_length */,
                                                      (short) 3 /* retry_limit*/, 
                                                      null /* puk_policy */);
      
            sess.createECKey ("Key.1",
                              ok_pin /* pin_value */,
                              pin_policy /* pin_policy */,
                              KeyUsage.AUTHENTICATION).setCertificate ("CN=" + name.getMethodName());
            sess.closeSession ();
            assertFalse ("Should have failed", fail_hard);
          }
        catch (SKSException e)
          {
            if (!fail_hard) fail (e.getMessage ());
          }
      }

    private boolean PINGroupCheck (boolean same_pin, PINGrouping grouping) throws IOException, GeneralSecurityException
      {
        try
          {
            String pin1 = "1234";
            String pin2 = "4567";
            ProvSess sess = new ProvSess (device);
            PINPol pin_pol = sess.createPINPolicy ("PIN",
                                         PassphraseFormat.NUMERIC,
                                         EnumSet.noneOf (PatternRestriction.class),
                                         grouping,
                                         4 /* min_length */, 
                                         8 /* max_length */,
                                         (short) 3 /* retry_limit*/, 
                                         null /* puk_policy */);
            sess.createECKey ("Key.1",
                pin1 /* pin_value */,
                pin_pol /* pin_policy */,
                KeyUsage.AUTHENTICATION).setCertificate ("CN=TEST");
            if (grouping == PINGrouping.SIGNATURE_PLUS_STANDARD)
              {
                sess.createECKey ("Key.1s",
                    pin1 /* pin_value */,
                    pin_pol /* pin_policy */,
                    KeyUsage.UNIVERSAL).setCertificate ("CN=TEST");
                sess.createECKey ("Key.2s",
                    same_pin ? pin1 : pin2 /* pin_value */,
                    pin_pol /* pin_policy */,
                    KeyUsage.SIGNATURE).setCertificate ("CN=TEST");
              }
            sess.createECKey ("Key.2",
                same_pin ? pin1 : pin2 /* pin_value */,
                pin_pol /* pin_policy */,
                KeyUsage.SIGNATURE).setCertificate ("CN=TEST");
            sess.abortSession ();
          }
        catch (SKSException e)
          {
              return false;
          }
        return true;
      }


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
        reference_implementation = sks instanceof SKSReferenceImplementation;
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

    @Rule 
    public TestName name = new TestName();
   
    private void write (byte[] data) throws Exception
      {
        if (fos != null)
          {
            fos.write (data);
          }
      }
    
  
    private void writeString (String message) throws Exception
      {
        write (message.getBytes ("UTF-8"));
      }
    
      
    @Test
    public void test1 () throws Exception
      {
        int q = sessionCount ();
        new ProvSess (device).closeSession ();
        assertTrue ("Session count", q == sessionCount ());
      }
    @Test
    public void test2 () throws Exception
      {
        int q = sessionCount ();
        ProvSess sess = new ProvSess (device);
        sess.createPINPolicy ("PIN",
                              PassphraseFormat.NUMERIC,
                              4 /* min_length */, 
                              8 /* max_length */,
                              (short) 3 /* retry_limit*/, 
                              null /* puk_policy */);
        try
          {
            sess.closeSession ();
            fail ("Should have thrown an exception");
          }
        catch (SKSException e)
          {
          }
        assertTrue ("Session count", q == sessionCount ());
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
                           1024 /* rsa_size */,
                           null /* pin_value */,
                           null /* pin_policy */,
                           KeyUsage.AUTHENTICATION);
        sess.closeSession ();
      }
    @Test
    public void test6 () throws Exception
      {
        ProvSess sess = new ProvSess (device);
        int i = 1;
        for (short rsa_key_size : device.device_info.getRSAKeySizes ())
          {
            sess.createRSAKey ("Key." + i++,
                               rsa_key_size /* rsa_size */,
                               null /* pin_value */,
                               null /* pin_policy */,
                               KeyUsage.AUTHENTICATION).setCertificate ("CN=TEST6");
          }
        if (i == 1) fail("Missing RSA");
        sess.closeSession ();
      }
    @Test
    public void test7 () throws Exception
      {
        assertTrue (nameCheck ("a"));
        assertTrue (nameCheck ("_"));
        assertTrue (nameCheck ("a."));
        assertTrue (nameCheck ("azAZ09-._"));
        assertTrue (nameCheck ("a123456789a123456789a12345678955"));
        assertFalse (nameCheck (".a"));
        assertFalse (nameCheck ("-"));
        assertFalse (nameCheck (" I_am_a_bad_name"));
        assertFalse (nameCheck (""));
        assertFalse (nameCheck ("a123456789a123456789a123456789555"));
      }
    @Test
    public void test8 () throws Exception
      {
        ProvSess sess = new ProvSess (device);
        sess.createECKey ("Key.1",
                           null /* pin_value */,
                           null /* pin_policy */,
                           KeyUsage.AUTHENTICATION).setCertificate ("CN=" + name.getMethodName());
        sess.closeSession ();
        
      }
    @Test
    public void test9 () throws Exception
      {
        ProvSess sess = new ProvSess (device);
        GenKey key = sess.createECKey ("Key.1",
                                       null /* pin_value */,
                                       null /* pin_policy */,
                                       KeyUsage.AUTHENTICATION).setCertificate ("CN=" + name.getMethodName());
        sess.closeSession ();
        byte[] result = device.sks.signHashedData (key.key_handle, 
                                                   "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", 
                                                   new byte[0], 
                                                   HashAlgorithms.SHA256.digest (TEST_STRING));
        Signature verify = Signature.getInstance (SignatureAlgorithms.ECDSA_SHA256.getJCEName (), "BC");
        verify.initVerify (key.cert_path[0]);
        verify.update (TEST_STRING);
        assertTrue ("Bad signature", verify.verify (result));
      }
    @Test
    public void test10 () throws Exception
      {
        ProvSess sess = new ProvSess (device);
        GenKey key = sess.createRSAKey ("Key.1",
                                        2048,
                                        null /* pin_value */,
                                        null /* pin_policy */,
                                        KeyUsage.AUTHENTICATION).setCertificate ("CN=" + name.getMethodName());
        sess.closeSession ();

        byte[] result = device.sks.signHashedData (key.key_handle, 
                                                   "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", 
                                                   new byte[0], 
                                                   HashAlgorithms.SHA256.digest (TEST_STRING));
        Signature verify = Signature.getInstance (SignatureAlgorithms.RSA_SHA256.getJCEName (), "BC");
        verify.initVerify (key.cert_path[0]);
        verify.update (TEST_STRING);
        assertTrue ("Bad signature", verify.verify (result));

        result = device.sks.signHashedData (key.key_handle, 
                                            "http://www.w3.org/2000/09/xmldsig#rsa-sha1", 
                                            new byte[0], 
                                            HashAlgorithms.SHA1.digest (TEST_STRING));
        verify = Signature.getInstance (SignatureAlgorithms.RSA_SHA1.getJCEName (), "BC");
        verify.initVerify (key.cert_path[0]);
        verify.update (TEST_STRING);
        assertTrue ("Bad signature", verify.verify (result));
      }
    @Test
    public void test11 () throws Exception
      {
        ProvSess sess = new ProvSess (device);
        PINstress (sess);
      }
    @Test
    public void test12 () throws Exception
      {
        ProvSess sess = new ProvSess (device);
        sess.makePINsServerDefined ();
        PINstress (sess);
      }
    @Test
    public void test13 () throws Exception
      {
        assertTrue (PUKCheck (PassphraseFormat.ALPHANUMERIC, "AB123"));
        assertTrue (PUKCheck (PassphraseFormat.NUMERIC, "1234"));
        assertTrue (PUKCheck (PassphraseFormat.STRING, "azAB13.\n"));
        assertTrue (PUKCheck (PassphraseFormat.BINARY, "12300234FF"));

        assertFalse (PUKCheck (PassphraseFormat.ALPHANUMERIC, ""));  // too short 
        assertFalse (PUKCheck (PassphraseFormat.ALPHANUMERIC, "ab123"));  // Lowercase 
        assertFalse (PUKCheck (PassphraseFormat.NUMERIC, "AB1234"));      // Alpha

        assertTrue (PINCheck (PassphraseFormat.ALPHANUMERIC, null, "AB123"));
        assertTrue (PINCheck (PassphraseFormat.NUMERIC, null, "1234"));
        assertTrue (PINCheck (PassphraseFormat.STRING, null, "azAB13.\n"));
        assertTrue (PINCheck (PassphraseFormat.BINARY, null, "12300234FF"));

        assertFalse (PINCheck (PassphraseFormat.ALPHANUMERIC, null, "ab123"));  // Lowercase 
        assertFalse (PINCheck (PassphraseFormat.NUMERIC, null, "AB1234"));      // Alpha

        assertFalse (PINCheck (PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.SEQUENCE}, "1234"));      // Up seq
        assertFalse (PINCheck (PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.SEQUENCE}, "8765"));      // Down seq
        assertTrue (PINCheck (PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.SEQUENCE}, "1235"));      // No seq
        assertTrue (PINCheck (PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.SEQUENCE}, "1345"));      // No seq

        assertTrue (PINCheck (PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.TWO_IN_A_ROW}, "1232"));      // No two in row
        assertFalse (PINCheck (PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.TWO_IN_A_ROW}, "11345"));      // Two in a row
        assertFalse (PINCheck (PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.TWO_IN_A_ROW}, "13455"));      // Two in a row

        assertTrue (PINCheck (PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.THREE_IN_A_ROW}, "11232"));      // No two in row
        assertFalse (PINCheck (PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.THREE_IN_A_ROW}, "111345"));      // Three in a row
        assertFalse (PINCheck (PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.THREE_IN_A_ROW}, "134555"));      // Three in a row
        
        assertTrue (PINCheck (PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.SEQUENCE, PatternRestriction.THREE_IN_A_ROW}, "1235"));      // No seq or three in a row
        assertFalse (PINCheck (PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.SEQUENCE, PatternRestriction.THREE_IN_A_ROW}, "6789"));      // Seq
        assertFalse (PINCheck (PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.SEQUENCE, PatternRestriction.THREE_IN_A_ROW}, "1115"));      // Three in a row

        assertFalse (PINCheck (PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.MISSING_GROUP}, "1476"));      // Bad combo
        assertFalse (PINCheck (PassphraseFormat.BINARY, new PatternRestriction[]{PatternRestriction.MISSING_GROUP}, "12300234FF"));      // Bad combo

        assertTrue (PINCheck (PassphraseFormat.STRING, new PatternRestriction[]{PatternRestriction.MISSING_GROUP}, "2aZ."));
        assertTrue (PINCheck (PassphraseFormat.ALPHANUMERIC, new PatternRestriction[]{PatternRestriction.MISSING_GROUP}, "AB34"));

        assertFalse (PINCheck (PassphraseFormat.STRING, new PatternRestriction[]{PatternRestriction.MISSING_GROUP}, "2aZA"));  // Non alphanum missing
        assertFalse (PINCheck (PassphraseFormat.STRING, new PatternRestriction[]{PatternRestriction.MISSING_GROUP}, "a.jZ"));  // Number missing
        assertFalse (PINCheck (PassphraseFormat.STRING, new PatternRestriction[]{PatternRestriction.MISSING_GROUP}, "2 ZA"));  // Lowercase missing
        assertFalse (PINCheck (PassphraseFormat.STRING, new PatternRestriction[]{PatternRestriction.MISSING_GROUP}, "2a 6"));  // Uppercase missing

        assertFalse (PINCheck (PassphraseFormat.ALPHANUMERIC, new PatternRestriction[]{PatternRestriction.MISSING_GROUP}, "ABCK")); // Missing number
        assertFalse (PINCheck (PassphraseFormat.ALPHANUMERIC, new PatternRestriction[]{PatternRestriction.MISSING_GROUP}, "1235")); // Missing alpha
        
        assertTrue (PINCheck (PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.REPEATED}, "1345"));
        assertFalse (PINCheck (PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.REPEATED}, "1315"));  // Two of same
        
        assertTrue (PINGroupCheck (true, PINGrouping.NONE));
        assertTrue (PINGroupCheck (false, PINGrouping.NONE));
        assertTrue (PINGroupCheck (true, PINGrouping.SHARED));
        assertFalse (PINGroupCheck (false, PINGrouping.SHARED));
        assertFalse (PINGroupCheck (true, PINGrouping.UNIQUE));
        assertTrue (PINGroupCheck (false, PINGrouping.UNIQUE));
        assertFalse (PINGroupCheck (true, PINGrouping.SIGNATURE_PLUS_STANDARD));
        assertTrue (PINGroupCheck (false, PINGrouping.SIGNATURE_PLUS_STANDARD));
      }
    @Test
    public void test14 () throws Exception
      {
        int q = sessionCount ();
        ProvSess sess = new ProvSess (device);
        GenKey key1 = sess.createECKey ("Key.1",
                                        null /* pin_value */,
                                        null /* pin_policy */,
                                        KeyUsage.AUTHENTICATION).setCertificate ("CN=" + name.getMethodName());
        GenKey key2 = sess.createECKey ("Key.2",
                                        null /* pin_value */,
                                        null /* pin_policy */,
                                        KeyUsage.AUTHENTICATION).setCertificate ("CN=" + name.getMethodName());
        sess.closeSession ();
        assertTrue (sess.exists ());
        ProvSess sess2 = new ProvSess (device);
        sess2.postDeleteKey (key1);
        assertTrue ("Ownership error", key2.getUpdatedKeyInfo ().getProvisioningHandle () == sess.provisioning_handle);
        assertTrue ("Missing key, deletes MUST only be performed during session close", key1.exists ());
        sess2.closeSession ();
        assertFalse ("Key was not deleted", key1.exists ());
        assertTrue ("Ownership error", key2.getUpdatedKeyInfo ().getProvisioningHandle () == sess2.provisioning_handle);
        assertFalse ("Managed sessions MUST be deleted", sess.exists ());
        assertTrue ("Session count", ++q == sessionCount ());
      }
    @Test
    public void test15 () throws Exception
      {
        for (int i = 0; i < 2; i++)
          {
            boolean updatable = i == 0;
            int q = sessionCount ();
            ProvSess sess = new ProvSess (device, updatable);
            GenKey key1 = sess.createECKey ("Key.1",
                                            null /* pin_value */,
                                            null /* pin_policy */,
                                            KeyUsage.AUTHENTICATION).setCertificate ("CN=" + name.getMethodName());
            sess.closeSession ();
            assertTrue (sess.exists ());
            ProvSess sess2 = new ProvSess (device);
            try
              {
                sess2.postDeleteKey (key1);
                assertTrue ("Only OK for updatable", updatable);
              }
            catch (SKSException e)
              {
                assertFalse ("Only OK for non-updatable", updatable);
              }
            assertTrue ("Missing key, deletes MUST only be performed during session close", key1.exists ());
            try
              {
                sess2.closeSession ();
                assertTrue ("Ok for updatable", updatable);
              }
            catch (SKSException e)
              {
              }
            assertTrue ("Key was not deleted", key1.exists () ^ updatable);
            assertTrue ("Managed sessions MUST be deleted", sess.exists () ^ updatable);
            assertTrue ("Session count",q == sessionCount () - (updatable ? 0 : 1));
          }
      }
    @Test
    public void test16 () throws Exception
      {
        int q = sessionCount ();
        ProvSess sess = new ProvSess (device);
        GenKey key1 = sess.createECKey ("Key.1",
                                        null /* pin_value */,
                                        null /* pin_policy */,
                                        KeyUsage.AUTHENTICATION).setCertificate ("CN=" + name.getMethodName());
        GenKey key2 = sess.createECKey ("Key.2",
                                        null /* pin_value */,
                                        null /* pin_policy */,
                                        KeyUsage.AUTHENTICATION).setCertificate ("CN=TEST16");
        sess.closeSession ();
        assertTrue (sess.exists ());
        deleteKey (key1);
        assertFalse ("Key was not deleted", key1.exists ());
        assertTrue ("Key did not exist", key2.exists ());
        assertTrue ("Session count", ++q == sessionCount ());
      }
    @Test
    public void test17 () throws Exception
      {
        int q = sessionCount ();
        ProvSess sess = new ProvSess (device);
        GenKey key1 = sess.createECKey ("Key.1",
                                        null /* pin_value */,
                                        null /* pin_policy */,
                                        KeyUsage.AUTHENTICATION).setCertificate ("CN=" + name.getMethodName());
        sess.closeSession ();
        assertTrue (sess.exists ());
        deleteKey (key1);
        assertFalse ("Key was not deleted", key1.exists ());
        assertTrue ("Session count", q == sessionCount ());
      }
    @Test
    public void test18 () throws Exception
      {
        ProvSess sess = new ProvSess (device);
        GenKey key1 = sess.createECKey ("Key.1",
                                        null /* pin_value */,
                                        null /* pin_policy */,
                                        KeyUsage.AUTHENTICATION).setCertificate ("CN=" + name.getMethodName());
        sess.closeSession ();
        assertTrue (sess.exists ());
        ProvSess sess2 = new ProvSess (device);
        GenKey key2 = sess2.createECKey ("Key.1",
                                         null /* pin_value */,
                                         null /* pin_policy */,
                                         KeyUsage.AUTHENTICATION).setCertificate ("CN=" + name.getMethodName());
        sess2.postUpdateKey (key2, key1);
        sess2.closeSession ();
        assertTrue ("Key should exist even after update", key1.exists ());
        assertFalse ("Key has been used and should be removed", key2.exists ());
        assertTrue ("Ownership error", key1.getUpdatedKeyInfo ().getProvisioningHandle () == sess2.provisioning_handle);
        assertFalse ("Managed sessions MUST be deleted", sess.exists ());
      }
    @Test
    public void test19 () throws Exception
      {
        String ok_pin = "1563";
        ProvSess sess = new ProvSess (device);
        PINPol pin_policy = sess.createPINPolicy ("PIN",
                                                  PassphraseFormat.NUMERIC,
                                                  4 /* min_length */, 
                                                  8 /* max_length */,
                                                  (short) 3 /* retry_limit*/, 
                                                  null /* puk_policy */);
        GenKey key1 = sess.createECKey ("Key.1",
                                        ok_pin /* pin_value */,
                                        pin_policy,
                                        KeyUsage.AUTHENTICATION).setCertificate ("CN=" + name.getMethodName());
        sess.closeSession ();
        assertTrue (sess.exists ());
        ProvSess sess2 = new ProvSess (device);
        GenKey key2 = sess2.createECKey ("Key.1",
                                         null /* pin_value */,
                                         null /* pin_policy */,
                                         KeyUsage.AUTHENTICATION).setCertificate ("CN=" + name.getMethodName());
        sess2.postUpdateKey (key2, key1);
        sess2.closeSession ();
        assertTrue ("Key should exist even after update", key1.exists ());
        assertFalse ("Key has been used and should be removed", key2.exists ());
        assertTrue ("Ownership error", key1.getUpdatedKeyInfo ().getProvisioningHandle () == sess2.provisioning_handle);
        assertFalse ("Managed sessions MUST be deleted", sess.exists ());
        try
          {
            device.sks.signHashedData (key1.key_handle, 
                                       "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", 
                                       new byte[0], 
                                       HashAlgorithms.SHA256.digest (TEST_STRING));
            fail ("Bad PIN should not work");
          }
        catch (SKSException e)
          {
          }
        try
          {
            byte[] result = device.sks.signHashedData (key1.key_handle, 
                                                       "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", 
                                                       ok_pin.getBytes ("UTF-8"), 
                                                       HashAlgorithms.SHA256.digest (TEST_STRING));
            Signature verify = Signature.getInstance (SignatureAlgorithms.ECDSA_SHA256.getJCEName (), "BC");
            verify.initVerify (key2.cert_path[0]);
            verify.update (TEST_STRING);
            assertTrue ("Bad signature", verify.verify (result));
          }
        catch (SKSException e)
          {
            fail ("Good PIN should work");
          }
      }
    @Test
    public void test20 () throws Exception
      {
        String ok_pin = "1563";
        ProvSess sess = new ProvSess (device);
        GenKey key1 = sess.createECKey ("Key.1",
                                        null /* pin_value */,
                                        null /* pin_policy */,
                                        KeyUsage.AUTHENTICATION).setCertificate ("CN=TEST18");
        sess.closeSession ();
        assertTrue (sess.exists ());
        ProvSess sess2 = new ProvSess (device);
        PINPol pin_policy = sess2.createPINPolicy ("PIN",
                                                   PassphraseFormat.NUMERIC,
                                                   4 /* min_length */, 
                                                   8 /* max_length */,
                                                   (short) 3 /* retry_limit*/, 
                                                   null /* puk_policy */);
        GenKey key2 = sess2.createECKey ("Key.1",
                                         ok_pin /* pin_value */,
                                         pin_policy,
                                         KeyUsage.AUTHENTICATION).setCertificate ("CN=TEST18");
        try
          {
            sess2.postUpdateKey (key2, key1);
            fail ("No PINs on update keys please");
          }
        catch (SKSException e)
          {
          }
      }
    @Test
    public void test21 () throws Exception
      {
        ProvSess sess = new ProvSess (device);
        GenKey key1 = sess.createECKey ("Key.1",
                                        null /* pin_value */,
                                        null /* pin_policy */,
                                        KeyUsage.AUTHENTICATION).setCertificate ("CN=TEST18");
        sess.closeSession ();
        assertTrue (sess.exists ());
        ProvSess sess2 = new ProvSess (device);
        GenKey key2 = sess2.createECKey ("Key.1",
                                         null /* pin_value */,
                                         null /* pin_policy */,
                                         KeyUsage.AUTHENTICATION).setCertificate ("CN=TEST18");
        GenKey key3 = sess2.createECKey ("Key.2",
                                         null /* pin_value */,
                                         null /* pin_policy */,
                                         KeyUsage.AUTHENTICATION).setCertificate ("CN=TEST18");
        sess2.postUpdateKey (key2, key1);
        try
          {
            sess2.postUpdateKey (key3, key1);
            fail ("Multiple updates of the same key");
          }
        catch (SKSException e)
          {
          }
      }
    @Test
    public void test22 () throws Exception
      {
        ProvSess sess = new ProvSess (device);
        GenKey key1 = sess.createECKey ("Key.1",
                                        null /* pin_value */,
                                        null /* pin_policy */,
                                        KeyUsage.AUTHENTICATION).setCertificate ("CN=TEST18");
        GenKey key2 = sess.createECKey ("Key.2",
                                        null /* pin_value */,
                                        null /* pin_policy */,
                                        KeyUsage.AUTHENTICATION).setCertificate ("CN=TEST18");
        sess.closeSession ();
        assertTrue (sess.exists ());
        ProvSess sess2 = new ProvSess (device);
        GenKey key3 = sess2.createECKey ("Key.1",
                                         null /* pin_value */,
                                         null /* pin_policy */,
                                         KeyUsage.AUTHENTICATION).setCertificate ("CN=TEST18");
        sess2.postUpdateKey (key3, key1);
        try
          {
            sess2.postUpdateKey (key3, key2);
            fail ("Multiple updates using the same key");
          }
        catch (SKSException e)
          {
          }
      }
    @Test
    public void test23 () throws Exception
      {
        String ok_pin = "1563";
        ProvSess sess = new ProvSess (device);
        PINPol pin_policy = sess.createPINPolicy ("PIN",
                                                  PassphraseFormat.NUMERIC,
                                                  EnumSet.noneOf (PatternRestriction.class),
                                                  PINGrouping.SHARED,
                                                  4 /* min_length */, 
                                                  8 /* max_length */,
                                                  (short) 3 /* retry_limit*/, 
                                                  null /* puk_policy */);
        GenKey key1 = sess.createECKey ("Key.1",
                                        ok_pin /* pin_value */,
                                        pin_policy,
                                        KeyUsage.AUTHENTICATION).setCertificate ("CN=TEST18");
        sess.closeSession ();
        assertTrue (sess.exists ());
        ProvSess sess2 = new ProvSess (device);
        GenKey key2 = sess2.createRSAKey ("Key.1",
                                          2048,
                                          null /* pin_value */,
                                          null /* pin_policy */,
                                          KeyUsage.AUTHENTICATION).setCertificate ("CN=TEST13");
        sess2.postCloneKey (key2, key1);
        sess2.closeSession ();
        assertTrue ("Old key should exist after clone", key1.exists ());
        assertTrue ("New key should exist after clone", key2.exists ());
        assertTrue ("Ownership error", key1.getUpdatedKeyInfo ().getProvisioningHandle () == sess2.provisioning_handle);
        assertFalse ("Managed sessions MUST be deleted", sess.exists ());
        try
          {
            device.sks.signHashedData (key2.key_handle, 
                                       "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", 
                                       new byte[0], 
                                       HashAlgorithms.SHA256.digest (TEST_STRING));
            fail ("Bad PIN should not work");
          }
        catch (SKSException e)
          {
            assertTrue ("There should be an auth error", e.getError () == SKSException.ERROR_AUTHORIZATION);
          }
        try
          {
            byte[] result = device.sks.signHashedData (key2.key_handle, 
                                                      "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", 
                                                       ok_pin.getBytes ("UTF-8"), 
                                                       HashAlgorithms.SHA256.digest (TEST_STRING));
            Signature verify = Signature.getInstance (SignatureAlgorithms.RSA_SHA256.getJCEName (), "BC");
            verify.initVerify (key2.cert_path[0]);
            verify.update (TEST_STRING);
            assertTrue ("Bad signature key2", verify.verify (result));
            result = device.sks.signHashedData (key1.key_handle, 
                                                "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", 
                                                ok_pin.getBytes ("UTF-8"), 
                                                HashAlgorithms.SHA256.digest (TEST_STRING));
            verify = Signature.getInstance (SignatureAlgorithms.ECDSA_SHA256.getJCEName (), "BC");
            verify.initVerify (key1.cert_path[0]);
            verify.update (TEST_STRING);
            assertTrue ("Bad signature key1", verify.verify (result));
          }
        catch (SKSException e)
          {
            fail ("Good PIN should work");
          }
      }
    @Test
    public void test24 () throws Exception
      {
        String ok_pin = "1563";
        ProvSess sess = new ProvSess (device);
        PINPol pin_policy = sess.createPINPolicy ("PIN",
                                                  PassphraseFormat.NUMERIC,
                                                  EnumSet.noneOf (PatternRestriction.class),
                                                  PINGrouping.SHARED,
                                                  4 /* min_length */, 
                                                  8 /* max_length */,
                                                  (short) 3 /* retry_limit*/, 
                                                  null /* puk_policy */);
        GenKey key1 = sess.createECKey ("Key.1",
                                        ok_pin /* pin_value */,
                                        pin_policy,
                                        KeyUsage.AUTHENTICATION).setCertificate ("CN=TEST18");
        GenKey key2 = sess.createECKey ("Key.2",
                                        ok_pin /* pin_value */,
                                        pin_policy,
                                        KeyUsage.AUTHENTICATION).setCertificate ("CN=TEST18");
        sess.closeSession ();
        assertTrue (sess.exists ());
        ProvSess sess2 = new ProvSess (device);
        GenKey key3 = sess2.createRSAKey ("Key.1",
                                          2048,
                                          null /* pin_value */,
                                          null /* pin_policy */,
                                          KeyUsage.AUTHENTICATION).setCertificate ("CN=TEST13");
        sess2.postCloneKey (key3, key1);
        sess2.closeSession ();
        assertTrue ("Old key should exist after clone", key1.exists ());
        assertTrue ("New key should exist after clone", key2.exists ());
        assertTrue ("Ownership error", key1.getUpdatedKeyInfo ().getProvisioningHandle () == sess2.provisioning_handle);
        assertTrue ("Ownership error", key2.getUpdatedKeyInfo ().getProvisioningHandle () == sess2.provisioning_handle);
        assertFalse ("Managed sessions MUST be deleted", sess.exists ());
        try
          {
            device.sks.signHashedData (key3.key_handle, 
                                       "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", 
                                       new byte[0], 
                                       HashAlgorithms.SHA256.digest (TEST_STRING));
            fail ("Bad PIN should not work");
          }
        catch (SKSException e)
          {
            assertTrue ("There should be an auth error", e.getError () == SKSException.ERROR_AUTHORIZATION);
          }
        try
          {
            byte[] result = device.sks.signHashedData (key3.key_handle, 
                                                      "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", 
                                                       ok_pin.getBytes ("UTF-8"), 
                                                       HashAlgorithms.SHA256.digest (TEST_STRING));
            Signature verify = Signature.getInstance (SignatureAlgorithms.RSA_SHA256.getJCEName (), "BC");
            verify.initVerify (key3.cert_path[0]);
            verify.update (TEST_STRING);
            assertTrue ("Bad signature key3", verify.verify (result));
            result = device.sks.signHashedData (key1.key_handle, 
                                                "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", 
                                                ok_pin.getBytes ("UTF-8"), 
                                                HashAlgorithms.SHA256.digest (TEST_STRING));
            verify = Signature.getInstance (SignatureAlgorithms.ECDSA_SHA256.getJCEName (), "BC");
            verify.initVerify (key1.cert_path[0]);
            verify.update (TEST_STRING);
            assertTrue ("Bad signature key1", verify.verify (result));
          }
        catch (SKSException e)
          {
            fail ("Good PIN should work");
          }
      }
    @Test
    public void test25 () throws Exception
      {
        updateReplace (true);
      }
    @Test
    public void test26 () throws Exception
      {
        updateReplace (false);
      }
    @Test
    public void test27 () throws Exception
      {
        edgeDeleteCase (true);
      }
    @Test
    public void test28 () throws Exception
      {
        edgeDeleteCase (false);
      }
    @Test
    public void test29 () throws Exception
      {
        int q = sessionCount ();
        ProvSess sess = new ProvSess (device);
        GenKey key1 = sess.createECKey ("Key.1",
                                        null /* pin_value */,
                                        null /* pin_policy */,
                                        KeyUsage.AUTHENTICATION).setCertificate ("CN=TEST18");
        GenKey key2 = sess.createECKey ("Key.2",
                                        null /* pin_value */,
                                        null /* pin_policy */,
                                        KeyUsage.AUTHENTICATION).setCertificate ("CN=TEST18");
        sess.closeSession ();
        assertTrue (sess.exists ());
        ProvSess sess2 = new ProvSess (device);
        sess2.postDeleteKey (key2);
        sks.deleteKey (key1.key_handle, new byte[0]);
        sess2.closeSession ();
        assertTrue ("Session count", q == sessionCount ());
      }
    @Test
    public void test30 () throws Exception
      {
        String ok_pin = "1563";
        ProvSess sess = new ProvSess (device);
        PINPol pin_policy = sess.createPINPolicy ("PIN",
                                                  PassphraseFormat.NUMERIC,
                                                  4 /* min_length */, 
                                                  8 /* max_length */,
                                                  (short) 3 /* retry_limit*/, 
                                                  null /* puk_policy */);

        GenKey key = sess.createRSAKey ("Key.1",
                                        1024,
                                        ok_pin /* pin_value */,
                                        pin_policy /* pin_policy */,
                                        KeyUsage.ENCRYPTION).setCertificate ("CN=" + name.getMethodName());
        GenKey key2 = sess.createRSAKey ("Key.2",
                                         1024,
                                         ok_pin /* pin_value */,
                                         pin_policy /* pin_policy */,
                                         KeyUsage.AUTHENTICATION).setCertificate ("CN=" + name.getMethodName());
        sess.closeSession ();
        
        Cipher cipher = Cipher.getInstance (AsymEncryptionAlgorithms.RSA_PKCS_1.getJCEName (), "BC");
        cipher.init (Cipher.ENCRYPT_MODE, key.cert_path[0]);
        byte[] enc = cipher.doFinal (TEST_STRING);
        assertTrue ("Encryption error", ArrayUtil.compare (device.sks.asymmetricKeyDecrypt (key.key_handle,
                                                                                            new byte[0],
                                                                                            AsymEncryptionAlgorithms.RSA_PKCS_1.getURI (), 
                                                                                            ok_pin.getBytes ("UTF-8"), 
                                                                                            enc), TEST_STRING));
        try
          {
            device.sks.asymmetricKeyDecrypt (key.key_handle, 
                                             new byte[0], SignatureAlgorithms.RSA_SHA256.getURI (), 
                                             ok_pin.getBytes ("UTF-8"), 
                                             enc);
            fail ("Alg error");
          }
        catch (SKSException e)
          {
            checkException (e, "Not an asymmetric key encryption algorithm: http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
          }
        try
          {
            device.sks.asymmetricKeyDecrypt (key.key_handle, 
                                             new byte[]{6},
                                             AsymEncryptionAlgorithms.RSA_PKCS_1.getURI (), 
                                             ok_pin.getBytes ("UTF-8"), 
                                             enc);
            fail ("Parm error");
          }
        catch (SKSException e)
          {
            checkException (e, "\"Parameters\" for key # do not match algorithm");
          }
        try
          {
            device.sks.asymmetricKeyDecrypt (key.key_handle, 
                                             new byte[0],
                                             AsymEncryptionAlgorithms.RSA_PKCS_1.getURI (), 
                                             (ok_pin + "4").getBytes ("UTF-8"), 
                                             enc);
            fail ("PIN error");
          }
        catch (SKSException e)
          {
            authorizationErrorCheck (e);
          }
        try
          {
            device.sks.asymmetricKeyDecrypt (key2.key_handle, 
                                             new byte[0],
                                             AsymEncryptionAlgorithms.RSA_PKCS_1.getURI (), 
                                             ok_pin.getBytes ("UTF-8"), 
                                             enc);
            fail ("Key usage error");
          }
        catch (SKSException e)
          {
            checkException (e, "\"KeyUsage\" for key # does not permit \"asymmetricKeyDecrypt\"");
          }
      }
    @Test
    public void test31 () throws Exception
      {
        String ok_pin = "1563";
        String puk_ok = "17644";
        ProvSess sess = new ProvSess (device);
        PUKPol puk = sess.createPUKPolicy ("PUK",
                                           PassphraseFormat.NUMERIC,
                                           (short) 3 /* retry_limit*/, 
                                           puk_ok /* puk_policy */);
        PINPol pin_policy = sess.createPINPolicy ("PIN",
                                                  PassphraseFormat.NUMERIC,
                                                  4 /* min_length */, 
                                                  8 /* max_length */,
                                                  (short) 3 /* retry_limit*/, 
                                                  puk /* puk_policy */);

        GenKey key = sess.createRSAKey ("Key.1",
                                        1024,
                                        ok_pin /* pin_value */,
                                        pin_policy /* pin_policy */,
                                        KeyUsage.ENCRYPTION).setCertificate ("CN=" + name.getMethodName());
        sess.closeSession ();
        
        Cipher cipher = Cipher.getInstance (AsymEncryptionAlgorithms.RSA_PKCS_1.getJCEName (), "BC");
        cipher.init (Cipher.ENCRYPT_MODE, key.cert_path[0]);
        byte[] enc = cipher.doFinal (TEST_STRING);
        assertTrue ("Encryption error", ArrayUtil.compare (device.sks.asymmetricKeyDecrypt (key.key_handle,
                                                                                            new byte[0],
                                                                                            AsymEncryptionAlgorithms.RSA_PKCS_1.getURI (), 
                                                                                            ok_pin.getBytes ("UTF-8"), 
                                                                                            enc), TEST_STRING));
        for (int i = 0; i < 4; i++)
          {
            try
              {
                device.sks.asymmetricKeyDecrypt (key.key_handle, 
                                                 new byte[0],
                                                 AsymEncryptionAlgorithms.RSA_PKCS_1.getURI (), 
                                                 (ok_pin + "4").getBytes ("UTF-8"), 
                                                 enc);
                fail ("PIN error");
              }
            catch (SKSException e)
              {
                
              }
          }
        try
          {
            device.sks.asymmetricKeyDecrypt (key.key_handle, 
                                             new byte[0],
                                             AsymEncryptionAlgorithms.RSA_PKCS_1.getURI (), 
                                             ok_pin.getBytes ("UTF-8"), 
                                             enc);
            fail ("PIN lock error");
          }
        catch (SKSException e)
          {
            authorizationErrorCheck (e);
          }
        try
          {
            device.sks.unlockKey (key.key_handle, (puk_ok + "2").getBytes ("UTF-8"));
            fail ("PUK unlock error");
          }
        catch (SKSException e)
          {
            authorizationErrorCheck (e);
          }
        device.sks.unlockKey (key.key_handle, puk_ok.getBytes ("UTF-8"));
        assertTrue ("Encryption error", ArrayUtil.compare (device.sks.asymmetricKeyDecrypt (key.key_handle,
                                                                                            new byte[0],
                                                                                            AsymEncryptionAlgorithms.RSA_PKCS_1.getURI (), 
                                                                                            ok_pin.getBytes ("UTF-8"), 
                                                                                            enc), TEST_STRING));
      }
    @Test
    public void test32 () throws Exception
      {
        ProvSess sess = new ProvSess (device);
        GenKey key = sess.createRSAKey ("Key.1",
                           1024 /* rsa_size */,
                           null /* pin_value */,
                           null /* pin_policy */,
                           KeyUsage.AUTHENTICATION).setCertificate ("CN=TEST6");
        sess.closeSession ();
        try
          {
            device.sks.exportKey (key.key_handle, new byte[0]);
            fail ("Shouldn't export");
          }
        catch (SKSException e)
          {
            assertTrue ("Wrong return code", e.getError () == SKSException.ERROR_NOT_ALLOWED);
          }
      }
    @Test
    public void test33 () throws Exception
      {
        ProvSess sess = new ProvSess (device);
        sess.overrideExportPolicy (ExportPolicy.NONE.getSKSValue ());
        GenKey key = sess.createRSAKey ("Key.1",
                           1024 /* rsa_size */,
                           null /* pin_value */,
                           null /* pin_policy */,
                           KeyUsage.AUTHENTICATION).setCertificate ("CN=TEST6");
        sess.closeSession ();
        try
          {
            device.sks.exportKey (key.key_handle, new byte[0]);
          }
        catch (SKSException e)
          {
            fail ("Should export");
          }
      }
    @Test
    public void test34 () throws Exception
      {
        ProvSess sess = new ProvSess (device);
        sess.overrideExportPolicy (ExportPolicy.PIN.getSKSValue ());
        try
          {
            sess.createRSAKey ("Key.1",
                           1024 /* rsa_size */,
                           null /* pin_value */,
                           null /* pin_policy */,
                           KeyUsage.AUTHENTICATION).setCertificate ("CN=TEST6");
            fail ("Missing PIN");
          }
        catch (SKSException e)
          {
            checkException (e, "Export or delete policy lacks a PIN object");
          }
      }
    @Test
    public void test35 () throws Exception
      {
        String ok_pin = "1563";
        ProvSess sess = new ProvSess (device);
        sess.overrideExportPolicy (ExportPolicy.PIN.getSKSValue ());
        PINPol pin_policy = sess.createPINPolicy ("PIN",
                                                  PassphraseFormat.NUMERIC,
                                                  4 /* min_length */, 
                                                  8 /* max_length */,
                                                  (short) 3 /* retry_limit*/, 
                                                  null /* puk_policy */);

        GenKey key = sess.createRSAKey ("Key.1",
                                        1024,
                                        ok_pin /* pin_value */,
                                        pin_policy /* pin_policy */,
                                        KeyUsage.AUTHENTICATION).setCertificate ("CN=" + name.getMethodName());
        sess.closeSession ();

        try
          {
            device.sks.exportKey (key.key_handle, new byte[0]);
            fail ("Bad PIN should not work");
          }
        catch (SKSException e)
          {
            authorizationErrorCheck (e);
          }
        try
          {
            device.sks.exportKey (key.key_handle, ok_pin.getBytes ("UTF-8"));
          }
        catch (SKSException e)
          {
            fail ("Good PIN should work");
          }
      }
    @Test
    public void test36 () throws Exception
      {
        String ok_pin = "1563";
        ProvSess sess = new ProvSess (device);
        sess.overrideExportPolicy (ExportPolicy.PUK.getSKSValue ());
        PINPol pin_policy = sess.createPINPolicy ("PIN",
                                                  PassphraseFormat.NUMERIC,
                                                  4 /* min_length */, 
                                                  8 /* max_length */,
                                                  (short) 3 /* retry_limit*/, 
                                                  null /* puk_policy */);

        try
          {
             sess.createRSAKey ("Key.1",
                                        1024,
                                        ok_pin /* pin_value */,
                                        pin_policy /* pin_policy */,
                                        KeyUsage.AUTHENTICATION).setCertificate ("CN=" + name.getMethodName());
            fail ("No PUK");
          }
        catch (SKSException e)
          {
            checkException (e, "Export or delete policy lacks a PUK object");
          }
      }
    @Test
    public void test37 () throws Exception
      {
        String ok_pin = "1563";
        String puk_ok = "17644";
        ProvSess sess = new ProvSess (device);
        sess.overrideExportPolicy (ExportPolicy.PUK.getSKSValue ());
        PUKPol puk = sess.createPUKPolicy ("PUK",
                                           PassphraseFormat.NUMERIC,
                                           (short) 3 /* retry_limit*/, 
                                           puk_ok /* puk_policy */);
        PINPol pin_policy = sess.createPINPolicy ("PIN",
                                                  PassphraseFormat.NUMERIC,
                                                  4 /* min_length */, 
                                                  8 /* max_length */,
                                                  (short) 3 /* retry_limit*/, 
                                                  puk /* puk_policy */);
        GenKey key = sess.createRSAKey ("Key.1",
                                        1024,
                                        ok_pin /* pin_value */,
                                        pin_policy /* pin_policy */,
                                        KeyUsage.AUTHENTICATION).setCertificate ("CN=" + name.getMethodName());
        sess.closeSession ();
        try
          {
            device.sks.exportKey (key.key_handle, new byte[0]);
            fail ("Bad PIN should not work");
          }
        catch (SKSException e)
          {
            authorizationErrorCheck (e);
          }
        try
          {
            device.sks.exportKey (key.key_handle, ok_pin.getBytes ("UTF-8"));
            fail ("PIN should not work");
          }
        catch (SKSException e)
          {
            authorizationErrorCheck (e);
          }
        try
          {
            device.sks.exportKey (key.key_handle, puk_ok.getBytes ("UTF-8"));
          }
        catch (SKSException e)
          {
            fail ("Good PUK should work");
          }
      }
    @Test
    public void test38 () throws Exception
      {
        for (KeyUsage key_usage : KeyUsage.values ())
          {
            if (key_usage != KeyUsage.SYMMETRIC_KEY)
              {
                try
                  {
                    String ok_pin = "1563";
                    byte[] symmetric_key = {0,5};
                    ProvSess sess = new ProvSess (device);
                    PINPol pin_policy = sess.createPINPolicy ("PIN",
                                                              PassphraseFormat.NUMERIC,
                                                              EnumSet.noneOf (PatternRestriction.class),
                                                              PINGrouping.SHARED,
                                                              4 /* min_length */, 
                                                              8 /* max_length */,
                                                              (short) 3 /* retry_limit*/, 
                                                              null /* puk_policy */);
                    GenKey key = sess.createECKey ("Key.1",
                                                    ok_pin /* pin_value */,
                                                    pin_policy,
                                                    key_usage).setCertificate ("CN=TEST18");
                    sess.setSymmetricKey (key, symmetric_key, new String[]{MacAlgorithms.HMAC_SHA1.getURI ()});
                    fail ("Not allowed");
                  }
                catch (SKSException e)
                  {
                    checkException (e, "Invalid \"KeyUsage\" for \"setSymmetricKey\"");
                  }
              }
          }
      }
    @Test
    public void test39 () throws Exception
      {
        String ok_pin = "1563";
        byte[] symmetric_key = {0,5,3,9,0,23,67,56,8,34,-45,4,2,5,6, 6};
        ProvSess sess = new ProvSess (device);
        PINPol pin_policy = sess.createPINPolicy ("PIN",
                                                  PassphraseFormat.NUMERIC,
                                                  EnumSet.noneOf (PatternRestriction.class),
                                                  PINGrouping.SHARED,
                                                  4 /* min_length */, 
                                                  8 /* max_length */,
                                                  (short) 3 /* retry_limit*/, 
                                                  null /* puk_policy */);
        GenKey key = sess.createECKey ("Key.1",
                                        ok_pin /* pin_value */,
                                        pin_policy,
                                        KeyUsage.SYMMETRIC_KEY).setCertificate ("CN=TEST18");
        sess.setSymmetricKey (key, symmetric_key, new String[]{MacAlgorithms.HMAC_SHA1.getURI ()});
        sess.closeSession ();
        byte[] result = sess.sks.performHMAC (key.key_handle, MacAlgorithms.HMAC_SHA1.getURI (), ok_pin.getBytes ("UTF-8"), TEST_STRING);
        assertTrue ("HMAC error", ArrayUtil.compare (result, MacAlgorithms.HMAC_SHA1.digest (symmetric_key, TEST_STRING)));
        try
          {
            sess.sks.performHMAC (key.key_handle, MacAlgorithms.HMAC_SHA256.getURI (), ok_pin.getBytes ("UTF-8"), TEST_STRING);
            fail ("Algorithm not allowed");
          }
        catch (SKSException e)
          {
          }
        try
          {
            sess.sks.performHMAC (key.key_handle, SymEncryptionAlgorithms.AES128_CBC.getURI (), ok_pin.getBytes ("UTF-8"), TEST_STRING);
            fail ("Algorithm not allowed");
          }
        catch (SKSException e)
          {
          }
      }
    @Test
    public void test40 () throws Exception
      {
        for (SymEncryptionAlgorithms sym_enc : SymEncryptionAlgorithms.values ())
          {
            byte[] data = TEST_STRING;
            if (sym_enc.needsPadding ())
              {
                data = new byte[] {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
              }
            int key_length = sym_enc.getKeyLength ();
            if (key_length == 0)
              {
                key_length = 16;
              }
            byte[] symmetric_key = new byte[key_length];
            new SecureRandom ().nextBytes (symmetric_key);
            String ok_pin = "1563";
            ProvSess sess = new ProvSess (device);
            PINPol pin_policy = sess.createPINPolicy ("PIN",
                                                      PassphraseFormat.NUMERIC,
                                                      EnumSet.noneOf (PatternRestriction.class),
                                                      PINGrouping.SHARED,
                                                      4 /* min_length */, 
                                                      8 /* max_length */,
                                                      (short) 3 /* retry_limit*/, 
                                                      null /* puk_policy */);
            GenKey key = sess.createECKey ("Key.1",
                                            ok_pin /* pin_value */,
                                            pin_policy,
                                            KeyUsage.SYMMETRIC_KEY).setCertificate ("CN=TEST18");
            try
              {
                sess.setSymmetricKey (key, symmetric_key, new String[]{sym_enc.getURI ()});
              }
            catch (SKSException e)
              {
                assertFalse ("Should not throw", sym_enc.isMandatorySKSAlgorithm ());
                checkException (e, "Unsupported algorithm: " + sym_enc.getURI ());
                continue;
              }
            sess.closeSession ();
            byte[] iv_none = new byte[0];
            byte[] iv_val = new byte[16];
            new SecureRandom ().nextBytes (iv_val);
            byte[] result = sess.sks.symmetricKeyEncrypt (key.key_handle,
                                                          true,
                                                          sym_enc.needsIV () ? iv_val : iv_none,
                                                          sym_enc.getURI (),
                                                          ok_pin.getBytes ("UTF-8"),
                                                          data);
            Cipher crypt = Cipher.getInstance (sym_enc.getJCEName ());
            if (sym_enc.needsIV ())
              {
                crypt.init (Cipher.ENCRYPT_MODE, new SecretKeySpec (symmetric_key, "AES"), new IvParameterSpec (iv_val));
              }
            else
              {
                crypt.init (Cipher.ENCRYPT_MODE, new SecretKeySpec (symmetric_key, "AES"));
              }
            assertTrue ("encrypt error", ArrayUtil.compare (result, crypt.doFinal (data)));
            assertTrue ("decrypt error", ArrayUtil.compare (data, sess.sks.symmetricKeyEncrypt (key.key_handle, 
                                                                                                false,
                                                                                                sym_enc.needsIV () ? iv_val : iv_none,
                                                                                                sym_enc.getURI (),
                                                                                                ok_pin.getBytes ("UTF-8"),
                                                                                                result)));
            try
              {
                sess.sks.symmetricKeyEncrypt (key.key_handle,
                                              true,
                                              sym_enc.needsIV () ? iv_none : iv_val,
                                              sym_enc.getURI (),
                                              ok_pin.getBytes ("UTF-8"),
                                              data);
                fail ("Incorrect IV must fail");
              }
            catch (SKSException e)
              {
                
              }
          }
      }
    @Test
    public void test41 () throws Exception
      {
        for (MacAlgorithms hmac : MacAlgorithms.values ())
          {
            byte[] data = TEST_STRING;
            byte[] symmetric_key = new byte[20];
            new SecureRandom ().nextBytes (symmetric_key);
            String ok_pin = "1563";
            ProvSess sess = new ProvSess (device);
            PINPol pin_policy = sess.createPINPolicy ("PIN",
                                                      PassphraseFormat.NUMERIC,
                                                      EnumSet.noneOf (PatternRestriction.class),
                                                      PINGrouping.SHARED,
                                                      4 /* min_length */, 
                                                      8 /* max_length */,
                                                      (short) 3 /* retry_limit*/, 
                                                      null /* puk_policy */);
            GenKey key = sess.createECKey ("Key.1",
                                            ok_pin /* pin_value */,
                                            pin_policy,
                                            KeyUsage.SYMMETRIC_KEY).setCertificate ("CN=TEST18");
            try
              {
                sess.setSymmetricKey (key, symmetric_key, new String[]{hmac.getURI ()});
              }
            catch (SKSException e)
              {
                assertFalse ("Should not throw", hmac.isMandatorySKSAlgorithm ());
                checkException (e, "Unsupported algorithm: " + hmac.getURI ());
                continue;
              }
            sess.closeSession ();
            byte[] result = sess.sks.performHMAC (key.key_handle,
                                                  hmac.getURI (),
                                                  ok_pin.getBytes ("UTF-8"),
                                                  data);
            assertTrue ("HMAC error", ArrayUtil.compare (result, hmac.digest (symmetric_key, data)));
          }
      }
    @Test
    public void test42 () throws Exception
      {
        String ok_pin = "1563";
        byte[] symmetric_key = {0,5,3,9,0,23,67,56,8,34,-45,4,2,5,6};  // 15 bytes only
        ProvSess sess = new ProvSess (device);
        PINPol pin_policy = sess.createPINPolicy ("PIN",
                                                  PassphraseFormat.NUMERIC,
                                                  EnumSet.noneOf (PatternRestriction.class),
                                                  PINGrouping.SHARED,
                                                  4 /* min_length */, 
                                                  8 /* max_length */,
                                                  (short) 3 /* retry_limit*/, 
                                                  null /* puk_policy */);
        GenKey key = sess.createECKey ("Key.1",
                                        ok_pin /* pin_value */,
                                        pin_policy,
                                        KeyUsage.SYMMETRIC_KEY).setCertificate ("CN=TEST18");
        try
          {
            sess.setSymmetricKey (key, symmetric_key, new String[]{SymEncryptionAlgorithms.AES128_CBC.getURI ()});
            fail ("Wrong key size");
          }
        catch (SKSException e)
          {
            checkException (e, "Incorrect key size (15) for algorithm: http://www.w3.org/2001/04/xmlenc#aes128-cbc");
          }
      }
    @Test
    public void test43 () throws Exception
      {
        byte[] symmetric_key = {0,5,3,9,0,23,67,56,8,34,-45,4,2,5,6, 6, 54,-3};
        String ok_pin = "1563";
        ProvSess sess = new ProvSess (device);
        sess.overrideExportPolicy (ExportPolicy.PIN.getSKSValue ());
        PINPol pin_policy = sess.createPINPolicy ("PIN",
                                                  PassphraseFormat.NUMERIC,
                                                  4 /* min_length */, 
                                                  8 /* max_length */,
                                                  (short) 3 /* retry_limit*/, 
                                                  null /* puk_policy */);

        GenKey key = sess.createECKey ("Key.1",
                                       ok_pin /* pin_value */,
                                       pin_policy /* pin_policy */,
                                       KeyUsage.SYMMETRIC_KEY).setCertificate ("CN=" + name.getMethodName());
        sess.setSymmetricKey (key, symmetric_key, new String[]{KeyGen2URIs.ALGORITHMS.NONE});
        sess.closeSession ();
        try
          {
            device.sks.exportKey (key.key_handle, new byte[0]);
            fail ("Bad PIN should not work");
          }
        catch (SKSException e)
          {
            assertTrue ("Auth error", e.getError () == SKSException.ERROR_AUTHORIZATION);
          }
        try
          {
            assertTrue ("Wrong key", ArrayUtil.compare (symmetric_key, device.sks.exportKey (key.key_handle, ok_pin.getBytes ("UTF-8"))));
          }
        catch (SKSException e)
          {
            fail ("Good PIN should work");
          }
      }
    @Test
    public void test44 () throws Exception
      {
        String ok_pin = "1563";
        ProvSess sess = new ProvSess (device);
        sess.overrideExportPolicy (ExportPolicy.PIN.getSKSValue ());
        PINPol pin_policy = sess.createPINPolicy ("PIN",
                                                  PassphraseFormat.NUMERIC,
                                                  4 /* min_length */, 
                                                  8 /* max_length */,
                                                  (short) 3 /* retry_limit*/, 
                                                  null /* puk_policy */);

       sess.createRSAKey ("Key.1",
                          1024,
                          ok_pin /* pin_value */,
                          pin_policy /* pin_policy */,
                          KeyUsage.SYMMETRIC_KEY).setCertificate ("CN=" + name.getMethodName());
        try
          {
            sess.closeSession ();
            fail ("Missing symmetric key");
          }
        catch (SKSException e)
          {
            checkException (e, "Missing \"setSymmetricKey\" for key: Key.1");
          }
      }
    @Test
    public void test45 () throws Exception
      {
        sessionLimitTest (5, false, true);
        sessionLimitTest (6, false, false);
        sessionLimitTest (6, true, true);
        sessionLimitTest (7, true, false);
      }
    @Test
    public void test46 () throws Exception
      {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance ("RSA", "BC");
        kpg.initialize (1024);
        java.security.KeyPair key_pair = kpg.generateKeyPair ();
        String ok_pin = "1563";
        for (KeyUsage key_usage : KeyUsage.values ())
          {
            ProvSess sess = new ProvSess (device);
            PINPol pin_policy = sess.createPINPolicy ("PIN",
                                                      PassphraseFormat.NUMERIC,
                                                      EnumSet.noneOf (PatternRestriction.class),
                                                      PINGrouping.SHARED,
                                                      4 /* min_length */, 
                                                      8 /* max_length */,
                                                      (short) 3 /* retry_limit*/, 
                                                      null /* puk_policy */);
            GenKey key = sess.createECKey ("Key.1",
                                           ok_pin /* pin_value */,
                                           pin_policy,
                                           key_usage).setCertificate ("CN=TEST18", key_pair.getPublic ());
            try
              {
                sess.restorePrivateKey (key, key_pair.getPrivate ());
                assertFalse ("Not allowed", key_usage == KeyUsage.TRANSPORT || key_usage == KeyUsage.SYMMETRIC_KEY);
              }
            catch (SKSException e)
              {
                checkException (e, "Invalid \"KeyUsage\" for \"restorePrivateKey\"");
                continue;
              }
            sess.closeSession ();
            try
              {
                Cipher cipher = Cipher.getInstance (AsymEncryptionAlgorithms.RSA_PKCS_1.getJCEName (), "BC");
                cipher.init (Cipher.ENCRYPT_MODE, key.cert_path[0]);
                byte[] enc = cipher.doFinal (TEST_STRING);
                assertTrue ("Encryption error", ArrayUtil.compare (device.sks.asymmetricKeyDecrypt (key.key_handle,
                                                                                                    new byte[0],
                                                                                                    AsymEncryptionAlgorithms.RSA_PKCS_1.getURI (), 
                                                                                                    ok_pin.getBytes ("UTF-8"), 
                                                                                                    enc), TEST_STRING));
                assertTrue ("Bad alg", key_usage == KeyUsage.ENCRYPTION || key_usage == KeyUsage.UNIVERSAL);
              }
            catch (SKSException e)
              {
                checkException (e, "\"KeyUsage\" for key # does not permit \"asymmetricKeyDecrypt\"");
              }
            try
              {
                byte[] result = device.sks.signHashedData (key.key_handle, 
                                                           "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", 
                                                           ok_pin.getBytes ("UTF-8"), 
                                                           HashAlgorithms.SHA256.digest (TEST_STRING));
                Signature verify = Signature.getInstance (SignatureAlgorithms.RSA_SHA256.getJCEName (), "BC");
                verify.initVerify (key.cert_path[0]);
                verify.update (TEST_STRING);
                assertTrue ("Bad signature", verify.verify (result));
                assertFalse ("Bad alg", key_usage == KeyUsage.ENCRYPTION);
              }
            catch (SKSException e)
              {
                checkException (e, "\"KeyUsage\" for key # does not permit \"signHashedData\"");
              }
          }
      }
  }
