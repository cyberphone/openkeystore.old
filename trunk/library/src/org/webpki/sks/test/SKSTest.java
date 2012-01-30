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
package org.webpki.sks.test;

import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;

import java.util.EnumSet;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;

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

import org.webpki.keygen2.KeyGen2URIs;

import org.webpki.sks.AppUsage;
import org.webpki.sks.DeviceInfo;
import org.webpki.sks.EnumeratedProvisioningSession;
import org.webpki.sks.ExportProtection;
import org.webpki.sks.Grouping;
import org.webpki.sks.InputMethod;
import org.webpki.sks.KeyProtectionInfo;
import org.webpki.sks.PassphraseFormat;
import org.webpki.sks.PatternRestriction;
import org.webpki.sks.SKSException;
import org.webpki.sks.SecureKeyStore;
import org.webpki.sks.test.SKSReferenceImplementation;
import org.webpki.sks.ws.TrustedGUIAuthorization;
import org.webpki.sks.ws.WSSpecific;
import org.webpki.util.ArrayUtil;

public class SKSTest
  {
    static final byte[] TEST_STRING = new byte[]{'S','u','c','c','e','s','s',' ','o','r',' ','n','o','t','?'};
  
    static SecureKeyStore sks;
    
    static TrustedGUIAuthorization tga;
    
    static boolean reference_implementation;
    
    static boolean standalone_testing;
    
    Device device;
    
    int sessionCount () throws Exception
      {
        EnumeratedProvisioningSession eps = new EnumeratedProvisioningSession ();
        int i = 0;
        while ((eps = sks.enumerateProvisioningSessions (eps.getProvisioningHandle (), false)) != null)
          {
            i++;
          }
        return i;
      }
    
    void sessionTest (int sess_nr) throws Exception
      {
        if (sess_nr != sessionCount () && standalone_testing)
          {
            fail ("Session count failed, are you actually running a stand-alone test?");
          }
      }
    
    void edgeDeleteCase (boolean post) throws Exception
      {
        ProvSess sess = new ProvSess (device, 0);
        GenKey key1 = sess.createECKey ("Key.1",
                                        null /* pin_value */,
                                        null /* pin_policy */,
                                        AppUsage.AUTHENTICATION).setCertificate ("CN=TEST18");
        sess.closeSession ();
        assertTrue (sess.exists ());
        ProvSess sess2 = new ProvSess (device);
        GenKey key3 = sess2.createECKey ("Key.1",
                                         null /* pin_value */,
                                         null /* pin_policy */,
                                         AppUsage.AUTHENTICATION).setCertificate ("CN=TEST18");
        if (post)
          {
            key3.postUpdateKey (key1);
          }
        else
          {
            sks.deleteKey (key1.key_handle, null);
          }
        try
          {
            if (post)
              {
                sks.deleteKey (key1.key_handle, null);
              }
            else
              {
                key3.postUpdateKey (key1);
              }
            sess2.closeSession ();
            fail ("Multiple updates using the same key");
          }
        catch (SKSException e)
          {
          }
      }

    void deleteKey (GenKey key) throws SKSException
      {
        sks.deleteKey (key.key_handle, null);
      }

    void checkException (SKSException e, String compare_message)
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
    
    void algOrder (String[] algorithms, String culprit_alg) throws Exception
      {
        try
          {
            ProvSess sess = new ProvSess (device, 0);
            sess.createRSAKey ("Key.1",
                               1000,
                               null /* pin_value */,
                               null,
                               AppUsage.AUTHENTICATION,
                               algorithms);
            assertTrue ("Should have thrown", culprit_alg == null);
          }
        catch (SKSException e)
          {
            assertFalse ("Should not have thrown", culprit_alg == null);
            checkException (e, "Duplicate or incorrectly sorted algorithm: " + culprit_alg);
          }
      }

    void authorizationErrorCheck (SKSException e)
      {
        assertTrue ("Wrong return code", e.getError () == SKSException.ERROR_AUTHORIZATION);
        checkException (e, "Authorization error for key #");
      }
    
    void updateReplace (boolean order) throws Exception
      {
        int q = sessionCount ();
        String ok_pin = "1563";
        ProvSess sess = new ProvSess (device, 0);
        PINPol pin_policy = sess.createPINPolicy ("PIN",
                                                  PassphraseFormat.NUMERIC,
                                                  EnumSet.noneOf (PatternRestriction.class),
                                                  Grouping.SHARED,
                                                  4 /* min_length */, 
                                                  8 /* max_length */,
                                                  (short) 3 /* retry_limit*/, 
                                                  null /* puk_policy */);
        GenKey key1 = sess.createECKey ("Key.1",
                                        ok_pin /* pin_value */,
                                        pin_policy,
                                        AppUsage.AUTHENTICATION).setCertificate ("CN=TEST18");
        sess.closeSession ();
        assertTrue (sess.exists ());
        ProvSess sess2 = new ProvSess (device);
        GenKey key2 = sess2.createECKey ("Key.2",
                                         null /* pin_value */,
                                         null,
                                         AppUsage.AUTHENTICATION).setCertificate ("CN=TEST18");
        GenKey key3 = sess2.createRSAKey ("Key.1",
                                          2048,
                                          null /* pin_value */,
                                          null /* pin_policy */,
                                          AppUsage.AUTHENTICATION).setCertificate ("CN=TEST13");
        if (order) key3.postCloneKey (key1);
        key2.postUpdateKey (key1);
        if (!order) key3.postCloneKey (key1);
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
                                       null,
                                       new byte[0], 
                                       HashAlgorithms.SHA256.digest (TEST_STRING));
            fail ("Bad PIN should not work");
          }
        catch (SKSException e)
          {
            authorizationErrorCheck (e);
          }
        try
          {
            byte[] result = device.sks.signHashedData (key3.key_handle,
                                                       "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", 
                                                       null,
                                                       ok_pin.getBytes ("UTF-8"), 
                                                       HashAlgorithms.SHA256.digest (TEST_STRING));
            Signature verify = Signature.getInstance (SignatureAlgorithms.RSA_SHA256.getJCEName ());
            verify.initVerify (key3.getPublicKey ());
            verify.update (TEST_STRING);
            assertTrue ("Bad signature key3", verify.verify (result));
            result = device.sks.signHashedData (key1.key_handle, 
                                                "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", 
                                                null,
                                                ok_pin.getBytes ("UTF-8"), 
                                                HashAlgorithms.SHA256.digest (TEST_STRING));
            verify = Signature.getInstance (SignatureAlgorithms.ECDSA_SHA256.getJCEName ());
            verify.initVerify (key2.getPublicKey ());
            verify.update (TEST_STRING);
            assertTrue ("Bad signature key1", verify.verify (result));
          }
        catch (SKSException e)
          {
            fail ("Good PIN should work");
          }
        sessionTest (++q);
      }

    
    boolean nameCheck (String name) throws IOException, GeneralSecurityException
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
  
    boolean PINCheck (PassphraseFormat format,
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
                                                   Grouping.NONE,
                                                   4 /* min_length */, 
                                                   8 /* max_length */,
                                                   (short) 3 /* retry_limit*/, 
                                                   null /* puk_policy */);
            sess.createECKey ("Key.1",
                              pin /* pin_value */,
                              pin_pol /* pin_policy */,
                              AppUsage.AUTHENTICATION).setCertificate ("CN=TEST8");
            sess.abortSession ();
          }
        catch (SKSException e)
          {
            return false;
          }
        return true;
      }

    boolean PUKCheck (PassphraseFormat format,
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

    void PINstress(ProvSess sess) throws Exception
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
                                        AppUsage.AUTHENTICATION).setCertificate ("CN=" + name.getMethodName());
        sess.closeSession ();
    
        for (int count = 0; count < 2; count++)
          {
            try
              {
                key.signData (SignatureAlgorithms.RSA_SHA256, ok_pin + "2", TEST_STRING);
                fail ("Bad PIN should not work");
              }
            catch (SKSException e)
              {
                authorizationErrorCheck (e);
              }
          }
        try
          {
            key.signData (SignatureAlgorithms.RSA_SHA256, ok_pin, TEST_STRING);
          }
        catch (SKSException e)
          {
            fail ("Good PIN should work");
          }
        for (int count = 0; count < 3; count++)
          {
            try
              {
                key.signData (SignatureAlgorithms.RSA_SHA256, ok_pin + "2", TEST_STRING);
                fail ("Bad PIN should not work");
              }
            catch (SKSException e)
              {
                authorizationErrorCheck (e);
              }
          }
        try
          {
            key.signData (SignatureAlgorithms.RSA_SHA256, ok_pin, TEST_STRING);
            fail ("Good PIN but too many errors should NOT work");
          }
        catch (SKSException e)
          {
            authorizationErrorCheck (e);
          }
      }
     
    void sessionLimitTest (int limit, boolean encrypted_pin, boolean fail_hard) throws Exception
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
                              AppUsage.AUTHENTICATION).setCertificate ("CN=" + name.getMethodName());
            sess.closeSession ();
            assertFalse ("Should have failed", fail_hard);
          }
        catch (SKSException e)
          {
            if (!fail_hard) fail (e.getMessage ());
            return;
          }
      }

    boolean PINGroupCheck (boolean same_pin, Grouping grouping) throws IOException, GeneralSecurityException
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
                              AppUsage.AUTHENTICATION).setCertificate ("CN=TEST");
            if (grouping == Grouping.SIGNATURE_PLUS_STANDARD)
              {
                sess.createECKey ("Key.1s",
                                  pin1 /* pin_value */,
                                  pin_pol /* pin_policy */,
                                  AppUsage.UNIVERSAL).setCertificate ("CN=TEST");
                sess.createECKey ("Key.2s",
                                  same_pin ? pin1 : pin2 /* pin_value */,
                                  pin_pol /* pin_policy */,
                                  AppUsage.SIGNATURE).setCertificate ("CN=TEST");
              }
            sess.createECKey ("Key.2",
                              same_pin ? pin1 : pin2 /* pin_value */,
                              pin_pol /* pin_policy */,
                              AppUsage.SIGNATURE).setCertificate ("CN=TEST");
            sess.abortSession ();
          }
        catch (SKSException e)
          {
              return false;
          }
        return true;
      }

    void lockECKey (GenKey key, String ok_pin) throws Exception
      {
        for (int i = 1; i < 4; i++)
          {
            try
              {
                key.signData (SignatureAlgorithms.ECDSA_SHA256, ok_pin + "4", TEST_STRING);
                assertTrue ("PIN fail", i < 3);
              }
            catch (SKSException e)
              {
                authorizationErrorCheck (e);
              }
          }
        try
          {
            key.signData (SignatureAlgorithms.ECDSA_SHA256, ok_pin, TEST_STRING);
            fail ("PIN fail");
          }
        catch (SKSException e)
          {
            authorizationErrorCheck (e);
          }
      }

    void create3Keys (String s_pin, String a_pin, String e_pin) throws Exception
      {
        boolean sa = s_pin.equals (a_pin);
        boolean ae = a_pin.equals (e_pin);
        boolean se = s_pin.equals (e_pin);
        String other_pin = "5555";
        for (Grouping pg : Grouping.values ())
          {
            String puk_ok = "17644";
            short pin_retry = 3;
            ProvSess sess = new ProvSess (device);
            sess.makePINsUserModifiable ();
            PUKPol puk = sess.createPUKPolicy ("PUK", PassphraseFormat.NUMERIC, (short) 3 /* retry_limit */, puk_ok /* puk_policy */);
            PINPol pin_policy = sess.createPINPolicy ("PIN", PassphraseFormat.NUMERIC, EnumSet.noneOf (PatternRestriction.class), pg, 4 /* min_length */, 8 /* max_length */, pin_retry/* retry_limit */, puk /* puk_policy */);

            GenKey key1 = sess.createRSAKey ("Key.1", 1024, s_pin /* pin_value */, pin_policy /* pin_policy */, AppUsage.SIGNATURE).setCertificate ("CN=" + name.getMethodName ());
            try
              {
                sess.createRSAKey ("Key.2", 1024, a_pin /* pin_value */, pin_policy /* pin_policy */, AppUsage.AUTHENTICATION).setCertificate ("CN=" + name.getMethodName ());
                assertTrue ("Bad combo " + pg + s_pin + a_pin + e_pin, pg == Grouping.NONE || (pg == Grouping.SHARED && sa) || (pg == Grouping.SIGNATURE_PLUS_STANDARD && !sa) || (pg == Grouping.UNIQUE && !sa));
              }
            catch (SKSException e)
              {
                assertTrue ("Bad combo " + pg + s_pin + a_pin + e_pin, (pg == Grouping.SHARED && !sa) || (pg == Grouping.SIGNATURE_PLUS_STANDARD && sa) || (pg == Grouping.UNIQUE && sa));
                continue;
              }
            try
              {
                sess.createRSAKey ("Key.3", 1024, e_pin /* pin_value */, pin_policy /* pin_policy */, AppUsage.ENCRYPTION).setCertificate ("CN=" + name.getMethodName ());
                assertTrue ("Bad combo " + pg + s_pin + a_pin + e_pin, pg == Grouping.NONE || (pg == Grouping.SHARED && sa && ae) || (pg == Grouping.SIGNATURE_PLUS_STANDARD && !sa && ae && !se) || (pg == Grouping.UNIQUE && !sa && !ae && !se));
              }
            catch (SKSException e)
              {
                assertTrue ("Bad combo " + pg + s_pin + a_pin + e_pin, (pg == Grouping.SHARED && (!sa || !ae)) || (pg == Grouping.SIGNATURE_PLUS_STANDARD && (sa || !ae || se)) || (pg == Grouping.UNIQUE && (sa || ae || se)));
                continue;
              }
            GenKey key4 = sess.createRSAKey ("Key.4", 1024, s_pin /* pin_value */, pin_policy /* pin_policy */, AppUsage.SIGNATURE).setCertificate ("CN=" + name.getMethodName ());
            sess.createRSAKey ("Key.5", 1024, e_pin /* pin_value */, pin_policy /* pin_policy */, AppUsage.ENCRYPTION).setCertificate ("CN=" + name.getMethodName ());
            sess.closeSession ();
            device.sks.changePIN (key4.key_handle, s_pin.getBytes ("UTF-8"), other_pin.getBytes ("UTF-8"));
            try
              {
                key1.signData (SignatureAlgorithms.RSA_SHA256, other_pin, TEST_STRING);
              }
            catch (SKSException e)
              {
                assertTrue ("None does not distribute PINs", pg == Grouping.NONE);
              }
          }
      }

    @BeforeClass
    public static void openFile () throws Exception
      {
        standalone_testing = new Boolean (System.getProperty ("sks.standalone"));
        Security.insertProviderAt (new BouncyCastleProvider(), 1);
        sks = (SecureKeyStore) Class.forName (System.getProperty ("sks.implementation")).newInstance ();
        if (sks instanceof WSSpecific)
          {
            tga = (TrustedGUIAuthorization) Class.forName (System.getProperty ("sks.auth.gui")).newInstance ();
            ((WSSpecific) sks).setTrustedGUIAuthorizationProvider (tga);
            String device_id = System.getProperty ("sks.device");
            if (device_id != null && device_id.length () != 0)
              {
                ((WSSpecific) sks).setDeviceID (device_id);
              }
          }
        DeviceInfo dev = sks.getDeviceInfo ();
        reference_implementation = SKSReferenceImplementation.SKS_VENDOR_DESCRIPTION.equals (dev.getVendorDescription ());
        if (reference_implementation)
          {
            System.out.println ("Reference Implementation");
          }
        System.out.println ("Description: " + dev.getVendorDescription ());
        System.out.println ("Vendor: " + dev.getVendorName ());
        System.out.println ("API Level: " + dev.getAPILevel ());
        System.out.println ("Trusted GUI: " + (tga == null ? "N/A" : tga.getImplementation ()));
        System.out.println ("Testing mode: " + (standalone_testing ? "StandAlone" : "MultiThreaded"));
      }

    @AfterClass
    public static void closeFile () throws Exception
      {
      }
    
    @Before
    public void setup () throws Exception
      {
         device = new Device (sks);
      }
        
    @After
    public void teardown () throws Exception
      {
      }

    @Rule 
    public TestName name = new TestName();
  
    @Test
    public void test1 () throws Exception
      {
        int q = sessionCount ();
        new ProvSess (device).closeSession ();
        sessionTest (q);
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
            checkException (e, "Unreferenced object \"ID\" : PIN");
          }
        sessionTest (q);
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

    @Test
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
        try
          {
            sess.closeSession ();
          }
        catch (SKSException e)
          {
            checkException (e, "Unreferenced object \"ID\" : PIN");
          }
      }

    @Test
    public void test5 () throws Exception
      {
        ProvSess sess = new ProvSess (device);
        sess.createRSAKey ("Key.1",
                           1024 /* rsa_size */,
                           null /* pin_value */,
                           null /* pin_policy */,
                           AppUsage.AUTHENTICATION);
        try
          {
            sess.closeSession ();
          }
        catch (SKSException e)
          {
            checkException (e, "Missing \"setCertificatePath\" for: Key.1");
          }
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
                               AppUsage.AUTHENTICATION).setCertificate ("CN=TEST6");
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
                           AppUsage.AUTHENTICATION).setCertificate ("CN=" + name.getMethodName());
        sess.closeSession ();
        
      }

    @Test
    public void test9 () throws Exception
      {
        ProvSess sess = new ProvSess (device);
        GenKey key = sess.createECKey ("Key.1",
                                       null /* pin_value */,
                                       null /* pin_policy */,
                                       AppUsage.AUTHENTICATION).setCertificate ("CN=" + name.getMethodName());
        sess.closeSession ();
        byte[] result = key.signData (SignatureAlgorithms.ECDSA_SHA256, null, TEST_STRING);
        Signature verify = Signature.getInstance (SignatureAlgorithms.ECDSA_SHA256.getJCEName ());
        verify.initVerify (key.getPublicKey ());
        verify.update (TEST_STRING);
        assertTrue ("Bad signature", verify.verify (result));
        try
          {
            key.changePin ("1274", "3421");
            fail ("Should bomb since this has no pin");
          }
        catch (SKSException e)
          {
            checkException (e, "Redundant authorization information for key #");
          }
      }

    @Test
    public void test10 () throws Exception
      {
        ProvSess sess = new ProvSess (device);
        GenKey key = sess.createRSAKey ("Key.1",
                                        2048,
                                        null /* pin_value */,
                                        null /* pin_policy */,
                                        AppUsage.AUTHENTICATION).setCertificate ("CN=" + name.getMethodName());
        sess.closeSession ();
        assertTrue ("Must be 0", device.sks.getKeyProtectionInfo (key.key_handle).getKeyBackup () == 0);

        byte[] result = key.signData (SignatureAlgorithms.RSA_SHA256, null, TEST_STRING);
        Signature verify = Signature.getInstance (SignatureAlgorithms.RSA_SHA256.getJCEName ());
        verify.initVerify (key.getPublicKey ());
        verify.update (TEST_STRING);
        assertTrue ("Bad signature", verify.verify (result));

        result = key.signData (SignatureAlgorithms.RSA_SHA1, null, TEST_STRING);
        verify = Signature.getInstance (SignatureAlgorithms.RSA_SHA1.getJCEName ());
        verify.initVerify (key.getPublicKey ());
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
        int q = sessionCount ();
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
        
        assertTrue (PINGroupCheck (true, Grouping.NONE));
        assertTrue (PINGroupCheck (false, Grouping.NONE));
        assertTrue (PINGroupCheck (true, Grouping.SHARED));
        assertFalse (PINGroupCheck (false, Grouping.SHARED));
        assertFalse (PINGroupCheck (true, Grouping.UNIQUE));
        assertTrue (PINGroupCheck (false, Grouping.UNIQUE));
        assertFalse (PINGroupCheck (true, Grouping.SIGNATURE_PLUS_STANDARD));
        assertTrue (PINGroupCheck (false, Grouping.SIGNATURE_PLUS_STANDARD));
        sessionTest (q);
      }

    @Test
    public void test14 () throws Exception
      {
        int q = sessionCount ();
        ProvSess sess = new ProvSess (device, 0);
        GenKey key1 = sess.createECKey ("Key.1",
                                        null /* pin_value */,
                                        null /* pin_policy */,
                                        AppUsage.AUTHENTICATION).setCertificate ("CN=" + name.getMethodName());
        GenKey key2 = sess.createECKey ("Key.2",
                                        null /* pin_value */,
                                        null /* pin_policy */,
                                        AppUsage.AUTHENTICATION).setCertificate ("CN=" + name.getMethodName());
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
        sessionTest (++q);
      }

    @Test
    public void test15 () throws Exception
      {
        for (int i = 0; i < 2; i++)
          {
            boolean updatable = i == 0;
            int q = sessionCount ();
            ProvSess sess = new ProvSess (device, updatable ? new Integer (0) : null);
            GenKey key1 = sess.createECKey ("Key.1",
                                            null /* pin_value */,
                                            null /* pin_policy */,
                                            AppUsage.AUTHENTICATION).setCertificate ("CN=" + name.getMethodName());
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
                checkException (e, "Key # belongs to a non-updatable provisioning session");
              }
            assertTrue ("Missing key, deletes MUST only be performed during session close", key1.exists ());
            try
              {
                sess2.closeSession ();
                assertTrue ("Ok for updatable", updatable);
              }
            catch (SKSException e)
              {
                checkException (e, "No such provisioning session: " + sess2.provisioning_handle);
              }
            assertTrue ("Key was not deleted", key1.exists () ^ updatable);
            assertTrue ("Managed sessions MUST be deleted", sess.exists () ^ updatable);
            sessionTest (q + (updatable ? 0 : 1));
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
                                        AppUsage.AUTHENTICATION).setCertificate ("CN=" + name.getMethodName());
        GenKey key2 = sess.createECKey ("Key.2",
                                        null /* pin_value */,
                                        null /* pin_policy */,
                                        AppUsage.AUTHENTICATION).setCertificate ("CN=TEST16");
        sess.closeSession ();
        assertTrue (sess.exists ());
        deleteKey (key1);
        assertFalse ("Key was not deleted", key1.exists ());
        assertTrue ("Key did not exist", key2.exists ());
        sessionTest (++q);
      }

    @Test
    public void test17 () throws Exception
      {
        int q = sessionCount ();
        ProvSess sess = new ProvSess (device);
        GenKey key1 = sess.createECKey ("Key.1",
                                        null /* pin_value */,
                                        null /* pin_policy */,
                                        AppUsage.AUTHENTICATION).setCertificate ("CN=" + name.getMethodName());
        sess.closeSession ();
        assertTrue (sess.exists ());
        deleteKey (key1);
        assertFalse ("Key was not deleted", key1.exists ());
        sessionTest (q);
      }

    @Test
    public void test18 () throws Exception
      {
        ProvSess sess = new ProvSess (device, 0);
        GenKey key1 = sess.createECKey ("Key.1",
                                        null /* pin_value */,
                                        null /* pin_policy */,
                                        AppUsage.AUTHENTICATION).setCertificate ("CN=" + name.getMethodName());
        sess.closeSession ();
        assertTrue (sess.exists ());
        ProvSess sess2 = new ProvSess (device);
        GenKey key2 = sess2.createECKey ("Key.1",
                                         null /* pin_value */,
                                         null /* pin_policy */,
                                         AppUsage.AUTHENTICATION).setCertificate ("CN=" + name.getMethodName());
        key2.postUpdateKey (key1);
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
        ProvSess sess = new ProvSess (device, 0);
        PINPol pin_policy = sess.createPINPolicy ("PIN",
                                                  PassphraseFormat.NUMERIC,
                                                  4 /* min_length */, 
                                                  8 /* max_length */,
                                                  (short) 3 /* retry_limit*/, 
                                                  null /* puk_policy */);
        GenKey key1 = sess.createECKey ("Key.1",
                                        ok_pin /* pin_value */,
                                        pin_policy,
                                        AppUsage.AUTHENTICATION).setCertificate ("CN=" + name.getMethodName());
        sess.closeSession ();
        assertTrue (sess.exists ());
        ProvSess sess2 = new ProvSess (device);
        GenKey key2 = sess2.createECKey ("Key.1",
                                         null /* pin_value */,
                                         null /* pin_policy */,
                                         AppUsage.AUTHENTICATION).setCertificate ("CN=" + name.getMethodName());
        key2.postUpdateKey (key1);
        sess2.closeSession ();
        assertTrue ("Key should exist even after update", key1.exists ());
        assertFalse ("Key has been used and should be removed", key2.exists ());
        assertTrue ("Ownership error", key1.getUpdatedKeyInfo ().getProvisioningHandle () == sess2.provisioning_handle);
        assertFalse ("Managed sessions MUST be deleted", sess.exists ());
        try
          {
            key1.signData (SignatureAlgorithms.ECDSA_SHA256, "bad", TEST_STRING);
            fail ("Bad PIN should not work");
          }
        catch (SKSException e)
          {
            authorizationErrorCheck (e);
          }
        try
          {
            byte[] result = key1.signData (SignatureAlgorithms.ECDSA_SHA256, ok_pin, TEST_STRING);
            Signature verify = Signature.getInstance (SignatureAlgorithms.ECDSA_SHA256.getJCEName ());
            verify.initVerify (key2.getPublicKey ());
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
        ProvSess sess = new ProvSess (device, 0);
        GenKey key1 = sess.createECKey ("Key.1",
                                        null /* pin_value */,
                                        null /* pin_policy */,
                                        AppUsage.AUTHENTICATION).setCertificate ("CN=TEST18");
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
                                         AppUsage.AUTHENTICATION).setCertificate ("CN=TEST18");
        try
          {
            key2.postUpdateKey (key1);
            fail ("No PINs on update keys please");
          }
        catch (SKSException e)
          {
            checkException (e, "Update/clone keys cannot have PIN codes");
          }
      }

    @Test
    public void test21 () throws Exception
      {
        ProvSess sess = new ProvSess (device, 0);
        GenKey key1 = sess.createECKey ("Key.1",
                                        null /* pin_value */,
                                        null /* pin_policy */,
                                        AppUsage.AUTHENTICATION).setCertificate ("CN=TEST18");
        sess.closeSession ();
        assertTrue (sess.exists ());
        ProvSess sess2 = new ProvSess (device);
        GenKey key2 = sess2.createECKey ("Key.1",
                                         null /* pin_value */,
                                         null /* pin_policy */,
                                         AppUsage.AUTHENTICATION).setCertificate ("CN=TEST18");
        GenKey key3 = sess2.createECKey ("Key.2",
                                         null /* pin_value */,
                                         null /* pin_policy */,
                                         AppUsage.AUTHENTICATION).setCertificate ("CN=TEST18");
        key2.postUpdateKey (key1);
        try
          {
            key3.postUpdateKey (key1);
            fail ("Multiple updates of the same key");
          }
        catch (SKSException e)
          {
            checkException (e, "Multiple updates of key #");
          }
      }

    @Test
    public void test22 () throws Exception
      {
        ProvSess sess = new ProvSess (device, 0);
        GenKey key1 = sess.createECKey ("Key.1",
                                        null /* pin_value */,
                                        null /* pin_policy */,
                                        AppUsage.AUTHENTICATION).setCertificate ("CN=TEST18");
        GenKey key2 = sess.createECKey ("Key.2",
                                        null /* pin_value */,
                                        null /* pin_policy */,
                                        AppUsage.AUTHENTICATION).setCertificate ("CN=TEST18");
        sess.closeSession ();
        assertTrue (sess.exists ());
        ProvSess sess2 = new ProvSess (device);
        GenKey key3 = sess2.createECKey ("Key.3",
                                         null /* pin_value */,
                                         null /* pin_policy */,
                                         AppUsage.AUTHENTICATION).setCertificate ("CN=TEST18");
        key3.postUpdateKey (key1);
        try
          {
            key3.postUpdateKey (key2);
            fail ("Multiple updates using the same key");
          }
        catch (SKSException e)
          {
            checkException (e, "New key used for multiple operations: Key.3");
          }
      }

    @Test
    public void test23 () throws Exception
      {
        String ok_pin = "1563";
        ProvSess sess = new ProvSess (device, 0);
        PINPol pin_policy = sess.createPINPolicy ("PIN",
                                                  PassphraseFormat.NUMERIC,
                                                  EnumSet.noneOf (PatternRestriction.class),
                                                  Grouping.SHARED,
                                                  4 /* min_length */, 
                                                  8 /* max_length */,
                                                  (short) 3 /* retry_limit*/, 
                                                  null /* puk_policy */);
        GenKey key1 = sess.createECKey ("Key.1",
                                        ok_pin /* pin_value */,
                                        pin_policy,
                                        AppUsage.AUTHENTICATION).setCertificate ("CN=TEST18");
        sess.closeSession ();
        assertTrue (sess.exists ());
        ProvSess sess2 = new ProvSess (device);
        GenKey key2 = sess2.createRSAKey ("Key.1",
                                          2048,
                                          null /* pin_value */,
                                          null /* pin_policy */,
                                          AppUsage.AUTHENTICATION).setCertificate ("CN=TEST13");
        key2.postCloneKey (key1);
        sess2.closeSession ();
        assertTrue ("Old key should exist after clone", key1.exists ());
        assertTrue ("New key should exist after clone", key2.exists ());
        assertTrue ("Ownership error", key1.getUpdatedKeyInfo ().getProvisioningHandle () == sess2.provisioning_handle);
        assertFalse ("Managed sessions MUST be deleted", sess.exists ());
        try
          {
            key2.signData (SignatureAlgorithms.RSA_SHA256, "1111", TEST_STRING);
            fail ("Bad PIN should not work");
          }
        catch (SKSException e)
          {
            authorizationErrorCheck (e);
          }
        try
          {
            byte[] result = key2.signData (SignatureAlgorithms.RSA_SHA256, ok_pin, TEST_STRING);
            Signature verify = Signature.getInstance (SignatureAlgorithms.RSA_SHA256.getJCEName ());
            verify.initVerify (key2.getPublicKey ());
            verify.update (TEST_STRING);
            assertTrue ("Bad signature key2", verify.verify (result));
            result = key1.signData (SignatureAlgorithms.ECDSA_SHA256, ok_pin, TEST_STRING);
            verify = Signature.getInstance (SignatureAlgorithms.ECDSA_SHA256.getJCEName ());
            verify.initVerify (key1.getPublicKey ());
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
        ProvSess sess = new ProvSess (device, 0);
        PINPol pin_policy = sess.createPINPolicy ("PIN",
                                                  PassphraseFormat.NUMERIC,
                                                  EnumSet.noneOf (PatternRestriction.class),
                                                  Grouping.SHARED,
                                                  4 /* min_length */, 
                                                  8 /* max_length */,
                                                  (short) 3 /* retry_limit*/, 
                                                  null /* puk_policy */);
        GenKey key1 = sess.createECKey ("Key.1",
                                        ok_pin /* pin_value */,
                                        pin_policy,
                                        AppUsage.AUTHENTICATION).setCertificate ("CN=TEST18");
        GenKey key2 = sess.createECKey ("Key.2",
                                        ok_pin /* pin_value */,
                                        pin_policy,
                                        AppUsage.AUTHENTICATION).setCertificate ("CN=TEST18");
        sess.closeSession ();
        assertTrue (sess.exists ());
        ProvSess sess2 = new ProvSess (device);
        GenKey key3 = sess2.createRSAKey ("Key.1",
                                          2048,
                                          null /* pin_value */,
                                          null /* pin_policy */,
                                          AppUsage.AUTHENTICATION).setCertificate ("CN=TEST13");
        key3.postCloneKey (key1);
        sess2.closeSession ();
        assertTrue ("Old key should exist after clone", key1.exists ());
        assertTrue ("New key should exist after clone", key2.exists ());
        assertTrue ("Ownership error", key1.getUpdatedKeyInfo ().getProvisioningHandle () == sess2.provisioning_handle);
        assertTrue ("Ownership error", key2.getUpdatedKeyInfo ().getProvisioningHandle () == sess2.provisioning_handle);
        assertFalse ("Managed sessions MUST be deleted", sess.exists ());
        try
          {
            key3.signData (SignatureAlgorithms.RSA_SHA256, "1111", TEST_STRING);
            fail ("Bad PIN should not work");
          }
        catch (SKSException e)
          {
            authorizationErrorCheck (e);
          }
        try
          {
            byte[] result = key3.signData (SignatureAlgorithms.RSA_SHA256, ok_pin, TEST_STRING);
            Signature verify = Signature.getInstance (SignatureAlgorithms.RSA_SHA256.getJCEName ());
            verify.initVerify (key3.getPublicKey ());
            verify.update (TEST_STRING);
            assertTrue ("Bad signature key3", verify.verify (result));
            result = key1.signData (SignatureAlgorithms.ECDSA_SHA256, ok_pin, TEST_STRING);
            verify = Signature.getInstance (SignatureAlgorithms.ECDSA_SHA256.getJCEName ());
            verify.initVerify (key1.getPublicKey ());
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
        ProvSess sess = new ProvSess (device, 0);
        GenKey key1 = sess.createECKey ("Key.1",
                                        null /* pin_value */,
                                        null /* pin_policy */,
                                        AppUsage.AUTHENTICATION).setCertificate ("CN=TEST18");
        GenKey key2 = sess.createECKey ("Key.2",
                                        null /* pin_value */,
                                        null /* pin_policy */,
                                        AppUsage.AUTHENTICATION).setCertificate ("CN=TEST18");
        sess.closeSession ();
        assertTrue (sess.exists ());
        ProvSess sess2 = new ProvSess (device);
        sess2.postDeleteKey (key2);
        sks.deleteKey (key1.key_handle, null);
        sess2.closeSession ();
        sessionTest (q);
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
                                        AppUsage.ENCRYPTION).setCertificate ("CN=" + name.getMethodName());
        GenKey key2 = sess.createRSAKey ("Key.2",
                                         1024,
                                         ok_pin /* pin_value */,
                                         pin_policy /* pin_policy */,
                                         AppUsage.AUTHENTICATION).setCertificate ("CN=" + name.getMethodName());
        sess.closeSession ();
        
        Cipher cipher = Cipher.getInstance (AsymEncryptionAlgorithms.RSA_PKCS_1.getJCEName ());
        cipher.init (Cipher.ENCRYPT_MODE, key.getPublicKey ());
        byte[] enc = cipher.doFinal (TEST_STRING);
        assertTrue ("Encryption error", ArrayUtil.compare (device.sks.asymmetricKeyDecrypt (key.key_handle,
                                                                                            AsymEncryptionAlgorithms.RSA_PKCS_1.getURI (), 
                                                                                            null,
                                                                                            ok_pin.getBytes ("UTF-8"), 
                                                                                            enc), TEST_STRING));
        try
          {
            device.sks.asymmetricKeyDecrypt (key.key_handle, 
                                             SignatureAlgorithms.RSA_SHA256.getURI (), 
                                             null,
                                             ok_pin.getBytes ("UTF-8"), 
                                             enc);
            fail ("Alg error");
          }
        catch (SKSException e)
          {
            checkException (e, "Algorithm does not match operation: http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
          }
        try
          {
            device.sks.asymmetricKeyDecrypt (key.key_handle, 
                                             AsymEncryptionAlgorithms.RSA_PKCS_1.getURI (), 
                                             new byte[]{6},
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
            key.asymmetricKeyDecrypt (AsymEncryptionAlgorithms.RSA_PKCS_1, ok_pin + "4", enc);
            fail ("PIN error");
          }
        catch (SKSException e)
          {
            authorizationErrorCheck (e);
          }
        try
          {
            key2.asymmetricKeyDecrypt (AsymEncryptionAlgorithms.RSA_PKCS_1, ok_pin, enc);
            fail ("PKCS #1 error");
          }
        catch (SKSException e)
          {
          }
      }

    @Test
    public void test31 () throws Exception
      {
        String ok_pin = "1563";
        String puk_ok = "17644";
        short pin_retry = 3;
        ProvSess sess = new ProvSess (device);
        sess.makePINsUserModifiable ();
        PUKPol puk = sess.createPUKPolicy ("PUK",
                                           PassphraseFormat.NUMERIC,
                                           (short) 3 /* retry_limit*/, 
                                           puk_ok /* puk_policy */);
        PINPol pin_policy = sess.createPINPolicy ("PIN",
                                                  PassphraseFormat.NUMERIC,
                                                  4 /* min_length */, 
                                                  8 /* max_length */,
                                                  pin_retry/* retry_limit*/, 
                                                  puk /* puk_policy */);

        GenKey key = sess.createRSAKey ("Key.1",
                                        1024,
                                        ok_pin /* pin_value */,
                                        pin_policy /* pin_policy */,
                                        AppUsage.ENCRYPTION).setCertificate ("CN=" + name.getMethodName());
        sess.closeSession ();
        
        try
          {
            key.changePin (ok_pin, "843");
          }
        catch (SKSException e)
          {
            checkException (e, "PIN length error");
          }
        key.changePin (ok_pin, ok_pin = "8463");
        
        Cipher cipher = Cipher.getInstance (AsymEncryptionAlgorithms.RSA_PKCS_1.getJCEName ());
        cipher.init (Cipher.ENCRYPT_MODE, key.getPublicKey ());
        byte[] enc = cipher.doFinal (TEST_STRING);
        assertTrue ("Encryption error", ArrayUtil.compare (device.sks.asymmetricKeyDecrypt (key.key_handle,
                                                                                            AsymEncryptionAlgorithms.RSA_PKCS_1.getURI (), 
                                                                                            null,
                                                                                            ok_pin.getBytes ("UTF-8"), 
                                                                                            enc), TEST_STRING));
        for (int i = 1; i <= (pin_retry * 2); i++)
          {
            try
              {
                key.asymmetricKeyDecrypt (AsymEncryptionAlgorithms.RSA_PKCS_1, ok_pin + "4", enc);
                fail ("PIN error");
              }
            catch (SKSException e)
              {
                
              }
            assertTrue ("PIN should be blocked", device.sks.getKeyProtectionInfo (key.key_handle).isPINBlocked () ^ (i < pin_retry));
          }
        try
          {
            key.asymmetricKeyDecrypt (AsymEncryptionAlgorithms.RSA_PKCS_1, ok_pin, enc);
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
                                                                                            AsymEncryptionAlgorithms.RSA_PKCS_1.getURI (), 
                                                                                            null,
                                                                                            ok_pin.getBytes ("UTF-8"), 
                                                                                            enc), TEST_STRING));
        for (int i = 1; i <= (pin_retry * 2); i++)
          {
            try
              {
                device.sks.changePIN (key.key_handle, (ok_pin + "2").getBytes ("UTF-8"), ok_pin.getBytes ("UTF-8"));
                fail ("PIN error");
              }
            catch (SKSException e)
              {
                
              }
            assertTrue ("PIN should be blocked", device.sks.getKeyProtectionInfo (key.key_handle).isPINBlocked () ^ (i < pin_retry));
          }
        try
          {
            device.sks.setPIN (key.key_handle, (puk_ok + "2").getBytes ("UTF-8"), ok_pin.getBytes ("UTF-8"));
            fail ("PUK error");
          }
        catch (SKSException e)
          {
            authorizationErrorCheck (e);
          }
        device.sks.setPIN (key.key_handle, puk_ok.getBytes ("UTF-8"), (ok_pin + "2").getBytes ("UTF-8"));
        assertTrue ("Encryption error", ArrayUtil.compare (key.asymmetricKeyDecrypt (AsymEncryptionAlgorithms.RSA_PKCS_1, 
                                                                                     ok_pin + "2", 
                                                                                     enc),
                                                           TEST_STRING));
      }

    @Test
    public void test32 () throws Exception
      {
        String ok_pin = "1563";
        String ok_puk = "234567";
        for (int i = 0; i < 4; i++)
          {
            boolean modifiable = i % 2 != 0;
            boolean have_puk = i > 1;
            
            ProvSess sess = new ProvSess (device);
            if (modifiable)
              {
                sess.makePINsUserModifiable ();
              }
            PUKPol puk = have_puk ? sess.createPUKPolicy ("PUK",
                                                          PassphraseFormat.NUMERIC,
                                                         (short) 3 /* retry_limit*/, 
                                                          ok_puk /* puk_policy */)
                                                         
                                   : null;
            PINPol pin_policy = sess.createPINPolicy ("PIN",
                                                      PassphraseFormat.NUMERIC,
                                                      EnumSet.noneOf (PatternRestriction.class),
                                                      Grouping.SHARED,
                                                      4 /* min_length */, 
                                                      8 /* max_length */,
                                                      (short) 3 /* retry_limit*/, 
                                                      puk /* puk_policy */);
            GenKey key = sess.createECKey ("Key.1",
                                           ok_pin /* pin_value */,
                                           pin_policy,
                                           AppUsage.AUTHENTICATION).setCertificate ("CN=TEST18");
            sess.closeSession ();
            key.signData (SignatureAlgorithms.ECDSA_SHA256, ok_pin, TEST_STRING);
            try
              {
                device.sks.changePIN (key.key_handle, ok_pin.getBytes ("UTF-8"), "8437".getBytes ("UTF-8"));
                assertTrue ("Modifiable", modifiable);
              }
            catch (SKSException e)
              {
                assertFalse ("Non-modifiable", modifiable);
                checkException (e, "PIN for key # is not user modifiable");
              }
            try
              {
                device.sks.setPIN (key.key_handle, ok_puk.getBytes ("UTF-8"), "8437".getBytes ("UTF-8"));
                assertTrue ("Non modifiable with set PIN", have_puk);
              }
            catch (SKSException e)
              {
                checkException (e, have_puk ? "PIN for key # is not user modifiable" : "Key # has no PUK");
              }
          }
      }

    @Test
    public void test33 () throws Exception
      {
        ProvSess sess = new ProvSess (device);
        GenKey key = sess.createRSAKey ("Key.1",
                                        1024 /* rsa_size */,
                                        null /* pin_value */,
                                        null /* pin_policy */,
                                        AppUsage.AUTHENTICATION).setCertificate ("CN=TEST6");
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
    public void test34 () throws Exception
      {
        ProvSess sess = new ProvSess (device);
        sess.overrideExportProtection (ExportProtection.NONE.getSKSValue ());
        GenKey key = sess.createRSAKey ("Key.1",
                                        1024 /* rsa_size */,
                                        null /* pin_value */,
                                        null /* pin_policy */,
                                        AppUsage.AUTHENTICATION).setCertificate ("CN=TEST6");
        sess.closeSession ();
        try
          {
            KeyProtectionInfo kpi = device.sks.getKeyProtectionInfo (key.key_handle);
            assertTrue ("No flags should be set", kpi.getKeyBackup () == 0);
            device.sks.exportKey (key.key_handle, null);
            kpi = device.sks.getKeyProtectionInfo (key.key_handle);
            assertTrue ("Flag must be set", kpi.getKeyBackup () == KeyProtectionInfo.KEYBACKUP_LOCAL);
          }
        catch (SKSException e)
          {
            fail ("Should export");
          }
      }

    @Test
    public void test35 () throws Exception
      {
        ProvSess sess = new ProvSess (device);
        sess.overrideExportProtection (ExportProtection.PIN.getSKSValue ());
        try
          {
            sess.createRSAKey ("Key.1",
                               1024 /* rsa_size */,
                               null /* pin_value */,
                               null /* pin_policy */,
                               AppUsage.AUTHENTICATION).setCertificate ("CN=TEST6");
            fail ("Missing PIN");
          }
        catch (SKSException e)
          {
            checkException (e, "Protection object lacks a PIN or PUK object");
          }
      }

    @Test
    public void test36 () throws Exception
      {
        String ok_pin = "1563";
        ProvSess sess = new ProvSess (device);
        sess.overrideExportProtection (ExportProtection.PIN.getSKSValue ());
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
                                        AppUsage.AUTHENTICATION).setCertificate ("CN=" + name.getMethodName());
        sess.closeSession ();

        try
          {
            device.sks.exportKey (key.key_handle, new byte[0]);
            fail ("Bad PIN should not work");
          }
        catch (SKSException e)
          {
            authorizationErrorCheck (e);
            assertTrue ("PIN Error count", key.getKeyProtectionInfo ().getPINErrorCount () == 1);
          }
        try
          {
            device.sks.exportKey (key.key_handle, ok_pin.getBytes ("UTF-8"));
            assertTrue ("PIN Error count", key.getKeyProtectionInfo ().getPINErrorCount () == 0);
          }
        catch (SKSException e)
          {
            fail ("Good PIN should work");
          }
      }

    @Test
    public void test37 () throws Exception
      {
        String ok_pin = "1563";
        ProvSess sess = new ProvSess (device);
        sess.overrideExportProtection (ExportProtection.PUK.getSKSValue ());
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
                                AppUsage.AUTHENTICATION).setCertificate ("CN=" + name.getMethodName());
            fail ("No PUK");
          }
        catch (SKSException e)
          {
            checkException (e, "Protection object lacks a PIN or PUK object");
          }
      }

    @Test
    public void test38 () throws Exception
      {
        String ok_pin = "1563";
        String puk_ok = "17644";
        ProvSess sess = new ProvSess (device);
        sess.overrideExportProtection (ExportProtection.PUK.getSKSValue ());
        PUKPol puk = sess.createPUKPolicy ("PUK",
                                           PassphraseFormat.NUMERIC,
                                           (short) 5 /* retry_limit*/, 
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
                                        AppUsage.AUTHENTICATION).setCertificate ("CN=" + name.getMethodName());
        sess.closeSession ();
        assertFalse ("Not asymmetric key", device.sks.getKeyAttributes (key.key_handle).isSymmetricKey ());
        try
          {
            device.sks.exportKey (key.key_handle, new byte[0]);
            fail ("Bad PUK should not work");
          }
        catch (SKSException e)
          {
            authorizationErrorCheck (e);
            assertTrue ("PUK Error count", key.getKeyProtectionInfo ().getPUKErrorCount () == 1);
            assertTrue ("PIN Error count", key.getKeyProtectionInfo ().getPINErrorCount () == 0);
          }
        try
          {
            device.sks.exportKey (key.key_handle, ok_pin.getBytes ("UTF-8"));
            fail ("PIN should not work");
          }
        catch (SKSException e)
          {
            authorizationErrorCheck (e);
            assertTrue ("PUK Error count", key.getKeyProtectionInfo ().getPUKErrorCount () == 2);
          }
        try
          {
            device.sks.exportKey (key.key_handle, puk_ok.getBytes ("UTF-8"));
            assertTrue ("PUK Error count", key.getKeyProtectionInfo ().getPUKErrorCount () == 0);
          }
        catch (SKSException e)
          {
            fail ("Good PUK should work");
          }
      }

    @Test
    public void test39 () throws Exception
      {
        for (AppUsage key_usage : AppUsage.values ())
          {
            byte[] symmetric_key = {0,5,3,9,0,23,67,56,8,34,-45,4,2,5,6, 6};
            String ok_pin = "1563";
            ProvSess sess = new ProvSess (device);
            PINPol pin_policy = sess.createPINPolicy ("PIN",
                                                      PassphraseFormat.NUMERIC,
                                                      EnumSet.noneOf (PatternRestriction.class),
                                                      Grouping.SHARED,
                                                      4 /* min_length */, 
                                                      8 /* max_length */,
                                                      (short) 3 /* retry_limit*/, 
                                                      null /* puk_policy */);
            GenKey key = sess.createECKey ("Key.1",
                                           ok_pin /* pin_value */,
                                           pin_policy,
                                           key_usage,
                                           new String[]{MacAlgorithms.HMAC_SHA1.getURI ()}).setCertificate ("CN=TEST18");
            key.setSymmetricKey (symmetric_key);
            sess.closeSession ();
            assertTrue ("Server must be set", device.sks.getKeyProtectionInfo (key.key_handle).getKeyBackup () == KeyProtectionInfo.KEYBACKUP_SERVER);
          }
      }

    @Test
    public void test40 () throws Exception
      {
        String ok_pin = "1563";
        byte[] symmetric_key = {0,5,3,9,0,23,67,56,8,34,-45,4,2,5,6, 6};
        ProvSess sess = new ProvSess (device);
        PINPol pin_policy = sess.createPINPolicy ("PIN",
                                                  PassphraseFormat.NUMERIC,
                                                  EnumSet.noneOf (PatternRestriction.class),
                                                  Grouping.SHARED,
                                                  4 /* min_length */, 
                                                  8 /* max_length */,
                                                  (short) 3 /* retry_limit*/, 
                                                  null /* puk_policy */);
        GenKey key = sess.createECKey ("Key.1",
                                       ok_pin /* pin_value */,
                                       pin_policy,
                                       AppUsage.AUTHENTICATION,
                                       new String[]{MacAlgorithms.HMAC_SHA1.getURI ()}).setCertificate ("CN=TEST18");
        key.setSymmetricKey (symmetric_key);
        sess.closeSession ();
        assertTrue ("Not symmetric key", device.sks.getKeyAttributes (key.key_handle).isSymmetricKey ());
        byte[] result = key.performHMAC (MacAlgorithms.HMAC_SHA1, ok_pin, TEST_STRING);
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
    public void test41 () throws Exception
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
                                                      Grouping.SHARED,
                                                      4 /* min_length */, 
                                                      8 /* max_length */,
                                                      (short) 3 /* retry_limit*/, 
                                                      null /* puk_policy */);
            GenKey key = null;
            try
              {
                key = sess.createECKey ("Key.1",
                                        ok_pin /* pin_value */,
                                        pin_policy,
                                        AppUsage.AUTHENTICATION,
                                        new String[]{sym_enc.getURI ()}).setCertificate ("CN=TEST18");
                key.setSymmetricKey (symmetric_key);
              }
            catch (SKSException e)
              {
                assertFalse ("Should not throw", sym_enc.isMandatorySKSAlgorithm ());
                checkException (e, "Unsupported algorithm: " + sym_enc.getURI ());
                continue;
              }
            sess.closeSession ();
            byte[] iv_val = new byte[16];
            new SecureRandom ().nextBytes (iv_val);
            byte[] result = key.symmetricKeyEncrypt (sym_enc,
                                                     true,
                                                     sym_enc.needsIV () && !sym_enc.internalIV () ? iv_val : null,
                                                     ok_pin,
                                                     data);
            byte[] res2 = result.clone ();
            Cipher crypt = Cipher.getInstance (sym_enc.getJCEName ());
            if (sym_enc.needsIV ())
              {
                if (sym_enc.internalIV ())
                  {
                    byte[] temp = new byte[result.length - 16];
                    System.arraycopy (res2, 0, iv_val, 0, 16);
                    System.arraycopy (res2, 16, temp, 0, temp.length);
                    res2 = temp;
                  }
                crypt.init (Cipher.ENCRYPT_MODE, new SecretKeySpec (symmetric_key, "AES"), new IvParameterSpec (iv_val));
              }
            else
              {
                crypt.init (Cipher.ENCRYPT_MODE, new SecretKeySpec (symmetric_key, "AES"));
              }
            assertTrue ("encrypt error", ArrayUtil.compare (res2, crypt.doFinal (data)));
            assertTrue ("decrypt error", ArrayUtil.compare (data, key.symmetricKeyEncrypt (sym_enc,
                                                                                           false,
                                                                                           sym_enc.needsIV () && !sym_enc.internalIV () ? iv_val : null,
                                                                                           ok_pin,
                                                                                           result)));
            try
              {
                key.symmetricKeyEncrypt (sym_enc,
                                         true,
                                         sym_enc.needsIV () && !sym_enc.internalIV () ? null : iv_val,
                                         ok_pin,
                                         data);
                fail ("Incorrect IV must fail");
              }
            catch (SKSException e)
              {
                
              }
          }
      }

    @Test
    public void test42 () throws Exception
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
                                                      Grouping.SHARED,
                                                      4 /* min_length */, 
                                                      8 /* max_length */,
                                                      (short) 3 /* retry_limit*/, 
                                                      null /* puk_policy */);
            GenKey key = null;
            try
              {
                key = sess.createECKey ("Key.1",
                                        ok_pin /* pin_value */,
                                        pin_policy,
                                        AppUsage.AUTHENTICATION,
                                        new String[]{hmac.getURI ()}).setCertificate ("CN=TEST18");
                key.setSymmetricKey (symmetric_key);
              }
            catch (SKSException e)
              {
                assertFalse ("Should not throw", hmac.isMandatorySKSAlgorithm ());
                checkException (e, "Unsupported algorithm: " + hmac.getURI ());
                continue;
              }
            sess.closeSession ();
            byte[] result = key.performHMAC (hmac, ok_pin, data);
            assertTrue ("HMAC error", ArrayUtil.compare (result, hmac.digest (symmetric_key, data)));
          }
      }

    @Test
    public void test43 () throws Exception
      {
        String ok_pin = "1563";
        byte[] symmetric_key = {0,5,3,9,0,23,67,56,8,34,-45,4,2,5,6};  // 15 bytes only
        ProvSess sess = new ProvSess (device);
        PINPol pin_policy = sess.createPINPolicy ("PIN",
                                                  PassphraseFormat.NUMERIC,
                                                  EnumSet.noneOf (PatternRestriction.class),
                                                  Grouping.SHARED,
                                                  4 /* min_length */, 
                                                  8 /* max_length */,
                                                  (short) 3 /* retry_limit*/, 
                                                  null /* puk_policy */);
        GenKey key = sess.createECKey ("Key.1",
                                       ok_pin /* pin_value */,
                                       pin_policy,
                                       AppUsage.AUTHENTICATION,
                                       new String[]{SymEncryptionAlgorithms.AES128_CBC.getURI ()}).setCertificate ("CN=TEST18");
        try
          {
            key.setSymmetricKey (symmetric_key);
            sess.closeSession ();
            fail ("Wrong key size");
          }
        catch (SKSException e)
          {
            checkException (e, "Key Key.1 has wrong size (15) for algorithm: http://www.w3.org/2001/04/xmlenc#aes128-cbc");
          }
      }

    @Test
    public void test44 () throws Exception
      {
        byte[] symmetric_key = {0,5,3,9,0,23,67,56,8,34,-45,4,2,5,6, 6, 54,-3};
        String ok_pin = "1563";
        ProvSess sess = new ProvSess (device);
        sess.overrideExportProtection (ExportProtection.PIN.getSKSValue ());
        PINPol pin_policy = sess.createPINPolicy ("PIN",
                                                  PassphraseFormat.NUMERIC,
                                                  4 /* min_length */, 
                                                  8 /* max_length */,
                                                  (short) 3 /* retry_limit*/, 
                                                  null /* puk_policy */);

        GenKey key = sess.createECKey ("Key.1",
                                       ok_pin /* pin_value */,
                                       pin_policy /* pin_policy */,
                                       AppUsage.AUTHENTICATION,
                                       new String[]{KeyGen2URIs.ALGORITHMS.NONE}).setCertificate ("CN=" + name.getMethodName());
        key.setSymmetricKey (symmetric_key);
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
    public void test45 () throws Exception
      {
        String ok_pin = "1563";
        ProvSess sess = new ProvSess (device);
        sess.overrideExportProtection (ExportProtection.PIN.getSKSValue ());
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
                          AppUsage.AUTHENTICATION,
                          new String[]{SymEncryptionAlgorithms.AES128_CBC.getURI ()}).setCertificate ("CN=" + name.getMethodName());
        try
          {
            sess.closeSession ();
            fail ("Wrong alg for key");
          }
        catch (SKSException e)
          {
            checkException (e, "RSA key Key.1 does not match algorithm: http://www.w3.org/2001/04/xmlenc#aes128-cbc");
          }
      }

    @Test
    public void test46 () throws Exception
      {
        String ok_pin = "1563";
        ProvSess sess = new ProvSess (device);
        sess.overrideExportProtection (ExportProtection.PIN.getSKSValue ());
        PINPol pin_policy = sess.createPINPolicy ("PIN",
                                                  PassphraseFormat.NUMERIC,
                                                  4 /* min_length */, 
                                                  8 /* max_length */,
                                                  (short) 3 /* retry_limit*/, 
                                                  null /* puk_policy */);

        sess.createECKey ("Key.1",
                          ok_pin /* pin_value */,
                          pin_policy,
                          AppUsage.ENCRYPTION,
                          new String[]{SymEncryptionAlgorithms.AES128_CBC.getURI ()}).setCertificate ("CN=TEST18");
         try
          {
            sess.closeSession ();
            fail ("Wrong alg for key");
          }
        catch (SKSException e)
          {
            checkException (e, "EC key Key.1 does not match algorithm: http://www.w3.org/2001/04/xmlenc#aes128-cbc");
          }
      }

    @Test
    public void test47 () throws Exception
      {
        sessionLimitTest (5, false, true);
        sessionLimitTest (6, false, false);
        sessionLimitTest (6, true, true);
        sessionLimitTest (7, true, false);
        sessionLimitTest (7, false, false);
        sessionLimitTest (8, true, false);
      }

    @Test
    public void test48 () throws Exception
      {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance ("RSA");
        kpg.initialize (1024);
        KeyPair key_pair = kpg.generateKeyPair ();
        String ok_pin = "1563";
        for (AppUsage key_usage : AppUsage.values ())
          {
            ProvSess sess = new ProvSess (device);
            PINPol pin_policy = sess.createPINPolicy ("PIN",
                                                      PassphraseFormat.NUMERIC,
                                                      EnumSet.noneOf (PatternRestriction.class),
                                                      Grouping.SHARED,
                                                      4 /* min_length */, 
                                                      8 /* max_length */,
                                                      (short) 3 /* retry_limit*/, 
                                                      null /* puk_policy */);
            GenKey key = sess.createECKey ("Key.1",
                                           ok_pin /* pin_value */,
                                           pin_policy,
                                           key_usage).setCertificate ("CN=TEST18", key_pair.getPublic ());
            sess.restorePrivateKey (key, key_pair.getPrivate ());
            sess.closeSession ();
            assertTrue ("Server must be set", device.sks.getKeyProtectionInfo (key.key_handle).getKeyBackup () == KeyProtectionInfo.KEYBACKUP_SERVER);
            Cipher cipher = Cipher.getInstance (AsymEncryptionAlgorithms.RSA_PKCS_1.getJCEName ());
            cipher.init (Cipher.ENCRYPT_MODE, key.getPublicKey ());
            byte[] enc = cipher.doFinal (TEST_STRING);
            assertTrue ("Encryption error", ArrayUtil.compare (key.asymmetricKeyDecrypt (AsymEncryptionAlgorithms.RSA_PKCS_1, 
                                                                                         ok_pin, 
                                                                                         enc), TEST_STRING));
            byte[] result = key.signData (SignatureAlgorithms.RSA_SHA256, ok_pin, TEST_STRING);
            Signature verify = Signature.getInstance (SignatureAlgorithms.RSA_SHA256.getJCEName ());
            verify.initVerify (key.getPublicKey ());
            verify.update (TEST_STRING);
            assertTrue ("Bad signature", verify.verify (result));
            try
              {
                key.performHMAC (MacAlgorithms.HMAC_SHA256, ok_pin, TEST_STRING);
                fail ("Sym key!");
              }
            catch (SKSException e)
              {
                checkException (e, "Asymmetric key # is incompatible with: http://www.w3.org/2001/04/xmldsig-more#hmac-sha256");
              }
          }
      }

    @Test
    public void test49 () throws Exception
      {
        create3Keys ("1111", "1111", "1111");
        create3Keys ("1111", "2222", "3333");
        create3Keys ("1111", "2222", "2222");
        create3Keys ("1111", "1111", "2222");
      }

    @Test
    public void test50 () throws Exception
      {
        byte[] symmetric_key = {0,5,3,9,0,23,67,56,8,34,-45,4,2,5,6, 6};
        String ok_pin = "1563";
        ProvSess sess = new ProvSess (device);
        PINPol pin_policy = sess.createPINPolicy ("PIN",
                                                  PassphraseFormat.NUMERIC,
                                                  EnumSet.noneOf (PatternRestriction.class),
                                                  Grouping.SHARED,
                                                  4 /* min_length */, 
                                                  8 /* max_length */,
                                                  (short) 3 /* retry_limit*/, 
                                                  null /* puk_policy */);
        GenKey key = sess.createECKey ("Key.1",
                                       ok_pin /* pin_value */,
                                       pin_policy,
                                       AppUsage.ENCRYPTION,
                                       new String[]{SymEncryptionAlgorithms.AES192_CBC.getURI ()}).setCertificate ("CN=TEST18");
        try
          {
            key.setSymmetricKey (symmetric_key);
            sess.closeSession ();
            fail ("Wrong length");
          }
        catch (SKSException e)
          {
            checkException (e, "Key Key.1 has wrong size (16) for algorithm: http://www.w3.org/2001/04/xmlenc#aes192-cbc");
          }
      }

    @Test
    public void test51 () throws Exception
      {
        String ok_pin = "1563";
        ProvSess sess = new ProvSess (device);
        PINPol pin_policy = sess.createPINPolicy ("PIN",
                                                  PassphraseFormat.NUMERIC,
                                                  EnumSet.noneOf (PatternRestriction.class),
                                                  Grouping.SHARED,
                                                  4 /* min_length */, 
                                                  8 /* max_length */,
                                                  (short) 3 /* retry_limit*/, 
                                                  null /* puk_policy */);
        GenKey key = sess.createECKey ("Key.1",
                                       ok_pin /* pin_value */,
                                       pin_policy,
                                       AppUsage.ENCRYPTION).setCertificate ("CN=TEST18");
        sess.closeSession ();
        KeyPairGenerator generator = KeyPairGenerator.getInstance ("EC");
        ECGenParameterSpec eccgen = new ECGenParameterSpec ("secp256r1");
        generator.initialize (eccgen, new SecureRandom ());
        KeyPair key_pair = generator.generateKeyPair ();
        byte[] z = device.sks.keyAgreement (key.key_handle,
                                            KeyGen2URIs.ALGORITHMS.ECDH_RAW,
                                            null,
                                            ok_pin.getBytes ("UTF-8"), 
                                            (ECPublicKey)key_pair.getPublic ());
        KeyAgreement key_agreement = KeyAgreement.getInstance ("ECDH");
        key_agreement.init (key_pair.getPrivate ());
        key_agreement.doPhase (key.getPublicKey (), true);
        byte[] Z = key_agreement.generateSecret ();
        assertTrue ("DH fail", ArrayUtil.compare (z, Z));
      }

    @Test
    public void test52 () throws Exception
      {
        String ok_pin = "1563";
        ProvSess sess = new ProvSess (device);
        PINPol pin_policy = sess.createPINPolicy ("PIN",
                                                  PassphraseFormat.NUMERIC,
                                                  EnumSet.noneOf (PatternRestriction.class),
                                                  Grouping.SHARED,
                                                  4 /* min_length */, 
                                                  8 /* max_length */,
                                                  (short) 3 /* retry_limit*/, 
                                                  null /* puk_policy */);
        GenKey key = sess.createECKey ("Key.1",
                                       ok_pin /* pin_value */,
                                       pin_policy,
                                       AppUsage.ENCRYPTION).setCertificate ("CN=TEST18");
        sess.closeSession ();
        new ProvSess (device);
        try
          {
            key.setSymmetricKey (new byte[]{0,1,2,3,4,5,6,7,8,9});
            fail("Not open key");
          }
        catch (SKSException e)
          {
            checkException (e, "Key # not belonging to open session");
          }
      }

    @Test
    public void test53 () throws Exception
      {
        for (int i = 0; i < 2; i++)
          {
            String ok_pin = "1563";
            ProvSess sess = new ProvSess (device, i);
            PINPol pin_policy = sess.createPINPolicy ("PIN",
                                                      PassphraseFormat.NUMERIC,
                                                      EnumSet.noneOf (PatternRestriction.class),
                                                      Grouping.SHARED,
                                                      4 /* min_length */, 
                                                      8 /* max_length */,
                                                      (short) 3 /* retry_limit*/, 
                                                      null /* puk_policy */);
            GenKey key = sess.createECKey ("Key.1",
                                           ok_pin /* pin_value */,
                                           pin_policy,
                                           AppUsage.AUTHENTICATION).setCertificate ("CN=TEST18");
            sess.closeSession ();
            lockECKey (key, ok_pin);
            ProvSess sess2 = new ProvSess (device);
            try
              {
                sess2.postUnlockKey (key);
                assertTrue ("Bad kmk should throw", i == 0);
              }
            catch (SKSException e)
              {
                assertFalse ("Good kmk should not throw", i == 0);
                checkException (e, "\"Authorization\" signature did not verify for key #");
              }
            try
              {
                sess2.closeSession ();
                assertTrue ("Bad kmk should throw", i == 0);
              }
            catch (SKSException e)
              {
                assertFalse ("Good kmk should not throw", i == 0);
              }
            try
              {
                key.signData (SignatureAlgorithms.ECDSA_SHA256, ok_pin, TEST_STRING);
                assertTrue ("Bad kmk should throw", i == 0);
              }
            catch (SKSException e)
              {
                assertFalse ("Good kmk should not throw", i == 0);
                authorizationErrorCheck (e);
              }
          }
      }

    @Test
    public void test54 () throws Exception
      {
        for (int i = 0; i < 2; i++)
          {
            String ok_pin = "1563";
            ProvSess sess = new ProvSess (device, 0);
            PINPol pin_policy = sess.createPINPolicy ("PIN",
                                                      PassphraseFormat.NUMERIC,
                                                      EnumSet.noneOf (PatternRestriction.class),
                                                      Grouping.SHARED,
                                                      4 /* min_length */, 
                                                      8 /* max_length */,
                                                      (short) 3 /* retry_limit*/, 
                                                      null /* puk_policy */);
            GenKey key = sess.createECKey ("Key.1",
                                           ok_pin /* pin_value */,
                                           pin_policy,
                                           AppUsage.AUTHENTICATION).setCertificate ("CN=TEST18");
            sess.closeSession ();
            lockECKey (key, ok_pin);
            ProvSess sess2 = new ProvSess (device);
            GenKey new_key = sess2.createECKey ("Key.1",
                                                null /* pin_value */,
                                                null /* pin_policy */,
                                                AppUsage.AUTHENTICATION).setCertificate ("CN=TEST18");
            if (i == 0) new_key.postUpdateKey (key);
            sess2.postUnlockKey (key);
            if (i == 1) new_key.postUpdateKey (key);
            sess2.closeSession ();
            key.signData (SignatureAlgorithms.ECDSA_SHA256, ok_pin, TEST_STRING);
            assertFalse ("taken", new_key.exists ());
          }
      }

    @Test
    public void test55 () throws Exception
      {
        for (int i = 0; i < 2; i++)
          {
            String ok_pin = "1563";
            ProvSess sess = new ProvSess (device, 0);
            PINPol pin_policy = sess.createPINPolicy ("PIN",
                                                      PassphraseFormat.NUMERIC,
                                                      EnumSet.noneOf (PatternRestriction.class),
                                                      Grouping.SHARED,
                                                      4 /* min_length */, 
                                                      8 /* max_length */,
                                                      (short) 3 /* retry_limit*/, 
                                                      null /* puk_policy */);
            GenKey key = sess.createECKey ("Key.1",
                                           ok_pin /* pin_value */,
                                           pin_policy,
                                           AppUsage.AUTHENTICATION).setCertificate ("CN=TEST18");
            sess.closeSession ();
            lockECKey (key, ok_pin);
            ProvSess sess2 = new ProvSess (device);
            GenKey new_key = sess2.createECKey ("Key.1",
                                                null /* pin_value */,
                                                null /* pin_policy */,
                                                AppUsage.AUTHENTICATION).setCertificate ("CN=TEST18");
            if (i == 0) new_key.postCloneKey (key);
            sess2.postUnlockKey (key);
            if (i == 1) new_key.postCloneKey (key);
            sess2.closeSession ();
            new_key.signData (SignatureAlgorithms.ECDSA_SHA256, ok_pin, TEST_STRING);
            key.signData (SignatureAlgorithms.ECDSA_SHA256, ok_pin, TEST_STRING);
          }
      }

    @Test
    public void test56 () throws Exception
      {
        for (int i = 0; i < 2; i++)
          {
            String ok_pin = "1563";
            ProvSess sess = new ProvSess (device, (short) 50, 0, true);
            PINPol pin_policy = sess.createPINPolicy ("PIN",
                                                      PassphraseFormat.NUMERIC,
                                                      EnumSet.noneOf (PatternRestriction.class),
                                                      Grouping.SHARED,
                                                      4 /* min_length */, 
                                                      8 /* max_length */,
                                                      (short) 3 /* retry_limit*/, 
                                                      null /* puk_policy */);
            GenKey key = sess.createECKey ("Key.1",
                                           ok_pin /* pin_value */,
                                           pin_policy,
                                           AppUsage.AUTHENTICATION).setCertificate ("CN=TEST18");
            sess.closeSession ();
            lockECKey (key, ok_pin);
            ProvSess sess2 = new ProvSess (device, (short) 50, null, true);
            GenKey new_key = sess2.createECKey ("Key.1",
                                                null /* pin_value */,
                                                null /* pin_policy */,
                                                AppUsage.AUTHENTICATION).setCertificate ("CN=TEST18");
            if (i == 0) new_key.postCloneKey (key);
            sess2.postUnlockKey (key);
            if (i == 1) new_key.postCloneKey (key);
            sess2.closeSession ();
            new_key.signData (SignatureAlgorithms.ECDSA_SHA256, ok_pin, TEST_STRING);
            key.signData (SignatureAlgorithms.ECDSA_SHA256, ok_pin, TEST_STRING);
          }
      }

    @Test
    public void test57 () throws Exception
      {
        algOrder (new String[]{SignatureAlgorithms.RSA_SHA1.getURI (),
                               SignatureAlgorithms.RSA_SHA1.getURI ()},
                  SignatureAlgorithms.RSA_SHA1.getURI ());
        algOrder (new String[]{SignatureAlgorithms.RSA_SHA256.getURI (),
                               SignatureAlgorithms.RSA_SHA1.getURI ()},
                  SignatureAlgorithms.RSA_SHA1.getURI ());
        algOrder (new String[]{SignatureAlgorithms.RSA_SHA1.getURI (),
                               SignatureAlgorithms.RSA_SHA256.getURI ()},
                  null);
      }
    @Test
    public void test58 () throws Exception
      {
        KeyPairGenerator generator = KeyPairGenerator.getInstance ("EC");
        ECGenParameterSpec eccgen = new ECGenParameterSpec ("secp256r1");
        generator.initialize (eccgen, new SecureRandom ());
        KeyPair key_pair = generator.generateKeyPair ();
        ProvSess sess = new ProvSess (device);
        GenKey key = sess.createECKey ("Key.1",
                                       null /* pin_value */,
                                       null /* pin_policy */,
                                       AppUsage.AUTHENTICATION).setCertificate ("CN=" + name.getMethodName(), key_pair.getPublic ());
        sess.restorePrivateKey (key, key_pair.getPrivate ());
        GenKey key2 = sess.createECKey ("Key.2",
                                        null /* pin_value */,
                                        null /* pin_policy */,
                                        AppUsage.AUTHENTICATION).setCertificatePath (key.getCertificatePath ());
        sess.restorePrivateKey (key2, key_pair.getPrivate ());
        try
          {
            sess.closeSession ();
            fail ("Not allowed");
           }
        catch (SKSException e)
          {
            checkException (e, "Duplicate certificate in \"setCertificatePath\" for: Key.1");
          }
        sess = new ProvSess (device);
        key = sess.createECKey ("Key.3",
                                null /* pin_value */,
                                null /* pin_policy */,
                                AppUsage.AUTHENTICATION).setCertificate ("CN=" + name.getMethodName(), key_pair.getPublic ());
        sess.restorePrivateKey (key, key_pair.getPrivate ());
        sess.closeSession ();
        sess = new ProvSess (device);
        key2 = sess.createECKey ("Key.4",
                                 null /* pin_value */,
                                 null /* pin_policy */,
                                 AppUsage.AUTHENTICATION).setCertificatePath (key.getCertificatePath ());
        sess.restorePrivateKey (key2, key_pair.getPrivate ());
        try
          {
            sess.closeSession ();
            fail ("Not allowed");
          }
        catch (SKSException e)
          {
            checkException (e, "Duplicate certificate in \"setCertificatePath\" for: Key.4");
          }
        sess = new ProvSess (device, 0);
        key = sess.createECKey ("Key.3",
                                null /* pin_value */,
                                null /* pin_policy */,
                                AppUsage.AUTHENTICATION).setCertificate ("CN=" + name.getMethodName(), key_pair.getPublic ());
        sess.restorePrivateKey (key, key_pair.getPrivate ());
        sess.closeSession ();
        ProvSess sess2 = new ProvSess (device);
        GenKey new_key = sess2.createECKey ("Key.4",
                                            null /* pin_value */,
                                            null /* pin_policy */,
                                            AppUsage.AUTHENTICATION).setCertificatePath (key.getCertificatePath ());
        sess2.restorePrivateKey (new_key, key_pair.getPrivate ());
        new_key.postUpdateKey (key);
        sess2.closeSession ();
        sess = new ProvSess (device, 0);
        key = sess.createECKey ("Key.3",
                                null /* pin_value */,
                                null /* pin_policy */,
                                AppUsage.AUTHENTICATION).setCertificate ("CN=" + name.getMethodName(), key_pair.getPublic ());
        sess.restorePrivateKey (key, key_pair.getPrivate ());
        sess.closeSession ();
        sess2 = new ProvSess (device);
        new_key = sess2.createECKey ("Key.4",
                                     null /* pin_value */,
                                     null /* pin_policy */,
                                     AppUsage.AUTHENTICATION).setCertificatePath (key.getCertificatePath ());
        sess2.restorePrivateKey (new_key, key_pair.getPrivate ());
        sess2.postDeleteKey (key);
        sess2.closeSession ();
      }

    @Test
    public void test59 () throws Exception
      {
        if (tga != null) for (InputMethod input_method : InputMethod.values ())
          {
            String ok_pin = DummyTrustedGUIAuthorization.GOOD_TRUSTED_GUI_PIN;
            ProvSess sess = new ProvSess (device);
            sess.setInputMethod (input_method);
            PINPol pin_policy = sess.createPINPolicy ("PIN",
                                                      PassphraseFormat.NUMERIC,
                                                      EnumSet.noneOf (PatternRestriction.class),
                                                      Grouping.SHARED,
                                                      4 /* min_length */, 
                                                      8 /* max_length */,
                                                      (short) 3 /* retry_limit*/, 
                                                      null /* puk_policy */);
            GenKey key = sess.createECKey ("Key.1",
                                           ok_pin /* pin_value */,
                                           pin_policy,
                                           AppUsage.AUTHENTICATION).setCertificate ("CN=TEST18");
            sess.closeSession ();
            key.signData (SignatureAlgorithms.ECDSA_SHA256, input_method == InputMethod.TRUSTED_GUI ? null : ok_pin, TEST_STRING);
            if (input_method == InputMethod.ANY)
              {
                key.signData (SignatureAlgorithms.ECDSA_SHA256, null, TEST_STRING);
              }
          }
      }
    @Test
    public void test60 () throws Exception
      {
        String ok_pin = "1563";
        byte[] symmetric_key = {0,5,3,9,0,23,67,56,8,34,-45,4,2,5,6, 8};
        ProvSess sess = new ProvSess (device);
        PINPol pin_policy = sess.createPINPolicy ("PIN",
                                                  PassphraseFormat.NUMERIC,
                                                  EnumSet.noneOf (PatternRestriction.class),
                                                  Grouping.SHARED,
                                                  4 /* min_length */, 
                                                  8 /* max_length */,
                                                  (short) 3 /* retry_limit*/, 
                                                  null /* puk_policy */);
        GenKey key = sess.createECKey ("Key.1",
                                       ok_pin /* pin_value */,
                                       pin_policy,
                                       AppUsage.AUTHENTICATION,
                                       new String[]{SymEncryptionAlgorithms.AES128_CBC.getURI ()}).setCertificate ("CN=TEST18");
        key.setSymmetricKey (symmetric_key);
        try
          {
            key.setSymmetricKey (symmetric_key);
            sess.closeSession ();
            fail ("Duplicate import");
          }
        catch (SKSException e)
          {
            checkException (e, "Mutiple key imports for: Key.1");
          }
      }

    @Test
    public void test61 () throws Exception
      {
        String ok_pin = "1563";
        byte[] symmetric_key = { 0, 5, 3, 9, 0, 23, 67, 56, 8, 34, -45, 4, 2, 5, 6, 8 };
        ProvSess sess = new ProvSess (device);
        PINPol pin_policy = sess.createPINPolicy ("PIN",
                                                  PassphraseFormat.NUMERIC,
                                                  EnumSet.noneOf (PatternRestriction.class),
                                                  Grouping.SHARED, 4 /* min_length */,
                                                  8 /* max_length */,
                                                  (short) 3 /* retry_limit */,
                                                  null /* puk_policy */);
        GenKey key = sess.createECKey ("Key.1",
                                       ok_pin /* pin_value */,
                                       pin_policy,
                                       AppUsage.AUTHENTICATION).setCertificate ("CN=TEST18");
        key.setSymmetricKey (symmetric_key);
        try
          {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance ("RSA");
            kpg.initialize (1024);
            KeyPair key_pair = kpg.generateKeyPair ();
            sess.restorePrivateKey (key, key_pair.getPrivate ());
            sess.closeSession ();
            fail ("Duplicate import");
          }
        catch (SKSException e)
          {
            checkException (e, "Mutiple key imports for: Key.1");
          }
      }

    @Test
    public void test62 () throws Exception
      {
        String ok_pin = "1563";
        ProvSess sess = new ProvSess (device);
        PINPol pin_policy = sess.createPINPolicy ("PIN",
                                                  PassphraseFormat.NUMERIC,
                                                  EnumSet.noneOf (PatternRestriction.class),
                                                  Grouping.SHARED, 4 /* min_length */,
                                                  8 /* max_length */,
                                                  (short) 3 /* retry_limit */,
                                                  null /* puk_policy */);
        GenKey key = sess.createECKey ("Key.1",
                                       ok_pin /* pin_value */,
                                       pin_policy,
                                       AppUsage.AUTHENTICATION).setCertificate ("CN=TEST18");
        try
          {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance ("RSA");
            kpg.initialize (1024);
            KeyPair key_pair = kpg.generateKeyPair ();
            sess.restorePrivateKey (key, key_pair.getPrivate ());
            sess.closeSession ();
            fail ("Mixing RSA and EC is not possible");
          }
        catch (SKSException e)
          {
            checkException (e, "RSA/EC mixup between public and private keys for: Key.1");
          }
      }
    @Test
    public void test63 () throws Exception
      {
        String ok_pin = "1563";
        ProvSess sess = new ProvSess (device);
        PINPol pin_policy = sess.createPINPolicy ("PIN",
                                                  PassphraseFormat.NUMERIC,
                                                  EnumSet.noneOf (PatternRestriction.class),
                                                  Grouping.SHARED, 4 /* min_length */,
                                                  8 /* max_length */,
                                                  (short) 3 /* retry_limit */,
                                                  null /* puk_policy */);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance ("RSA");
        kpg.initialize (1024);
        KeyPair key_pair = kpg.generateKeyPair ();
        sess.createECKey ("Key.1",
                          ok_pin /* pin_value */,
                          pin_policy,
                          AppUsage.AUTHENTICATION).setCertificate ("CN=TEST18", key_pair.getPublic ());
        try
          {
            sess.closeSession ();
            fail ("Mismatch");
          }
        catch (SKSException e)
          {
            checkException (e, "RSA/EC mixup between public and private keys for: Key.1");
          }
      }

    @Test
    public void test64 () throws Exception
      {
        String ok_pin = "1563";
        ProvSess sess = new ProvSess (device);
        PINPol pin_policy = sess.createPINPolicy ("PIN",
                                                  PassphraseFormat.NUMERIC,
                                                  EnumSet.noneOf (PatternRestriction.class),
                                                  Grouping.SHARED, 4 /* min_length */,
                                                  8 /* max_length */,
                                                  (short) 3 /* retry_limit */,
                                                  null /* puk_policy */);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance ("RSA");
        kpg.initialize (1024);
        KeyPair key_pair = kpg.generateKeyPair ();
        sess.createRSAKey ("Key.1",
                           1024,
                           ok_pin /* pin_value */,
                           pin_policy,
                           AppUsage.AUTHENTICATION).setCertificate ("CN=TEST18", key_pair.getPublic ());
        try
          {
            sess.closeSession ();
            fail ("Mismatch");
          }
        catch (SKSException e)
          {
            checkException (e, "RSA mismatch between public and private keys for: Key.1");
          }
      }

    @Test
    public void test65 () throws Exception
      {
        String ok_pin = "1563";
        ProvSess sess = new ProvSess (device);
        PINPol pin_policy = sess.createPINPolicy ("PIN",
                                                  PassphraseFormat.NUMERIC,
                                                  EnumSet.noneOf (PatternRestriction.class),
                                                  Grouping.SHARED, 4 /* min_length */,
                                                  8 /* max_length */,
                                                  (short) 3 /* retry_limit */,
                                                  null /* puk_policy */);
        KeyPairGenerator generator = KeyPairGenerator.getInstance ("EC");
        ECGenParameterSpec eccgen = new ECGenParameterSpec ("secp256r1");
        generator.initialize (eccgen, new SecureRandom ());
        KeyPair key_pair = generator.generateKeyPair ();
        sess.createECKey ("Key.1",
                          ok_pin /* pin_value */,
                          pin_policy,
                          AppUsage.AUTHENTICATION).setCertificate ("CN=TEST18", key_pair.getPublic ());
        try
          {
            sess.closeSession ();
            fail ("Mismatch");
          }
        catch (SKSException e)
          {
            checkException (e, "EC mismatch between public and private keys for: Key.1");
          }
      }

    @Test
    public void test66 () throws Exception
      {
        try
          {
            new ProvSess (device, 3);
            fail ("Bad KMK");
          }
        catch (SKSException e)
          {
            checkException (e, "Unsupported RSA key size 512 for: \"KeyManagementKey\"");
          }
      }

    @Test
    public void test67 () throws Exception
      {
        KeyPairGenerator generator = KeyPairGenerator.getInstance ("EC");
        ECGenParameterSpec eccgen = new ECGenParameterSpec ("secp192r1");  // Violating the P-256 requirement
        generator.initialize (eccgen, new SecureRandom ());
        KeyPair key_pair = generator.generateKeyPair ();
        try
          {
            new ProvSess (device, (ECPublicKey)key_pair.getPublic ());
            fail ("Bad server key");
          }
        catch (SKSException e)
          {
            checkException (e, "EC key \"ServerEphemeralKey\" not of P-256/secp256r1 type");
          }
      }
  }
