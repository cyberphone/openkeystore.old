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
import java.util.EnumSet;
import java.util.Set;

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
    static final byte[] TEST_STRING = new byte[]{'S','u','c','c','e','s','s',' ','o','r',' ','n','o','t','?'};
  
    static FileOutputStream fos;
    
    static SecureKeyStore sks;
    
    Device device;
    
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
            PUKPol pin_pol = sess.createPUKPolicy ("PUK",
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
                           KeyUsage.AUTHENTICATION).setCertificate ("CN=TEST8");
        sess.closeSession ();
        
      }
    @Test
    public void test12 () throws Exception
      {
        ProvSess sess = new ProvSess (device);
        GenKey key = sess.createECKey ("Key.1",
                                       null /* pin_value */,
                                       null /* pin_policy */,
                                       KeyUsage.AUTHENTICATION).setCertificate ("CN=TEST12");
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
    public void test13 () throws Exception
      {
        ProvSess sess = new ProvSess (device);
        GenKey key = sess.createRSAKey ("Key.1",
                                        2048,
                                        null /* pin_value */,
                                        null /* pin_policy */,
                                        KeyUsage.AUTHENTICATION).setCertificate ("CN=TEST13");
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
    public void test14 () throws Exception
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
                                        KeyUsage.AUTHENTICATION).setCertificate ("CN=TEST14");
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
    @Test
    public void test15 () throws Exception
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
    public void test16 () throws Exception
      {
        ProvSess sess = new ProvSess (device);
        GenKey key1 = sess.createECKey ("Key.1",
                                        null /* pin_value */,
                                        null /* pin_policy */,
                                        KeyUsage.AUTHENTICATION).setCertificate ("CN=TEST16");
        GenKey key2 = sess.createECKey ("Key.2",
                                        null /* pin_value */,
                                        null /* pin_policy */,
                                        KeyUsage.AUTHENTICATION).setCertificate ("CN=TEST16");
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
      }
    @Test
    public void test17 () throws Exception
      {
        ProvSess sess = new ProvSess (device);
        GenKey key1 = sess.createECKey ("Key.1",
                                        null /* pin_value */,
                                        null /* pin_policy */,
                                        KeyUsage.AUTHENTICATION).setCertificate ("CN=TEST17");
        sess.closeSession ();
        assertTrue (sess.exists ());
        ProvSess sess2 = new ProvSess (device);
        GenKey key2 = sess2.createECKey ("Key.1",
                                         null /* pin_value */,
                                         null /* pin_policy */,
                                         KeyUsage.AUTHENTICATION).setCertificate ("CN=TEST17");
        sess2.postUpdateKey (key2, key1);
        sess2.closeSession ();
        assertTrue ("Key should exist even after update", key1.exists ());
        assertFalse ("Key has been used and should be removed", key2.exists ());
        assertTrue ("Ownership error", key1.getUpdatedKeyInfo ().getProvisioningHandle () == sess2.provisioning_handle);
        assertFalse ("Managed sessions MUST be deleted", sess.exists ());
      }
    @Test
    public void test18 () throws Exception
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
                                        KeyUsage.AUTHENTICATION).setCertificate ("CN=TEST18");
        sess.closeSession ();
        assertTrue (sess.exists ());
        ProvSess sess2 = new ProvSess (device);
        GenKey key2 = sess2.createECKey ("Key.1",
                                         null /* pin_value */,
                                         null /* pin_policy */,
                                         KeyUsage.AUTHENTICATION).setCertificate ("CN=TEST18");
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
    public void test19 () throws Exception
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
    public void test20 () throws Exception
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
    public void test21 () throws Exception
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
  }
