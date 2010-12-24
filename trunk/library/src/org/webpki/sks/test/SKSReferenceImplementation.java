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

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.io.Serializable;

import java.math.BigInteger;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;

import java.security.cert.X509Certificate;

import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;

import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Vector;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.webpki.sks.DeviceInfo;
import org.webpki.sks.EnumeratedKey;
import org.webpki.sks.EnumeratedProvisioningSession;
import org.webpki.sks.Extension;
import org.webpki.sks.KeyAttributes;
import org.webpki.sks.KeyData;
import org.webpki.sks.KeyProtectionInfo;
import org.webpki.sks.ProvisioningSession;
import org.webpki.sks.SKSException;
import org.webpki.sks.SecureKeyStore;

/*
 *                          ###########################
 *                          #  SKS - Secure Key Store #
 *                          ###########################
 *
 *  SKS is a cryptographic module that supports On-line Provisioning and Management
 *  of PKI, Symmetric keys, PINs, PUKs and Extension data.
 *  
 *  VSDs (Virtual Security Domains), E2ES (End To End Security), and Transaction
 *  Oriented Provisioning enable multiple credential providers to securely and
 *  reliable share a key container, something which will become a necessity in
 *  mobile phones with embedded security hardware.
 *
 *  The following SKS Reference Implementation is intended to complement the
 *  specification by showing how the different constructs can be implemented.
 *
 *  In addition to the Reference Implementation there is a set of SKS JUnit tests
 *  that should work identical on a "real" SKS token.
 *
 *  Compared to the SKS specification, the Reference Implementation uses a slightly
 *  more java-centric way of passing parameters, including "null" arguments, but the
 *  content is supposed to be identical.
 *
 *  Author: Anders Rundgren
 */
public class SKSReferenceImplementation implements SKSError, SecureKeyStore, Serializable
  {
    private static final long serialVersionUID = 1L;

    /////////////////////////////////////////////////////////////////////////////////////////////
    // SKS version and configuration data
    /////////////////////////////////////////////////////////////////////////////////////////////
    static final short SKS_API_LEVEL                       = 0x0001;
    static final String SKS_VENDOR_NAME                    = "WebPKI.org";
    static final String SKS_VENDOR_DESCRIPTION             = "SKS Reference - Java Emulator Edition";
    static final String SKS_UPDATE_URL                     = "";
    static final boolean SKS_DEVICE_PIN_SUPPORT            = true;  // Change here to test or disable
    static final boolean SKS_BIOMETRIC_SUPPORT             = true;  // Change here to test or disable
    static final boolean SKS_RSA_EXPONENT_SUPPORT          = true;  // Change here to test or disable

    int next_key_handle = 1;
    HashMap<Integer,KeyEntry> keys = new HashMap<Integer,KeyEntry> ();

    int next_prov_handle = 1;
    HashMap<Integer,Provisioning> provisionings = new HashMap<Integer,Provisioning> ();

    int next_pin_handle = 1;
    HashMap<Integer,PINPolicy> pin_policies = new HashMap<Integer,PINPolicy> ();

    int next_puk_handle = 1;
    HashMap<Integer,PUKPolicy> puk_policies = new HashMap<Integer,PUKPolicy> ();


    public SKSReferenceImplementation ()
      {
        Security.addProvider(new BouncyCastleProvider());
      }


    abstract class NameSpace implements Serializable
      {
        private static final long serialVersionUID = 1L;

        String id;

        Provisioning owner;

        NameSpace (Provisioning owner, String id) throws SKSException
          {
            //////////////////////////////////////////////////////////////////////
            // Keys, PINs and PUKs share virtual ID space during provisioning
            //////////////////////////////////////////////////////////////////////
            if (owner.names.get (id) != null)
              {
                owner.abort ("Duplicate \"ID\" : " + id);
              }
            boolean flag = false;
            if (id.length () == 0 || id.length () > MAX_LENGTH_ID_TYPE)
              {
                flag = true;
              }
            else for (int i = 0; i < id.length (); i++)
              {
                char c = id.charAt (i);
                /////////////////////////////////////////////////
                // The restricted XML NCName
                /////////////////////////////////////////////////
                if ((c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && c != '_')
                  {
                    if (i == 0 || ((c < '0' || c > '9') && c != '-' && c != '.'))
                      {
                        flag = true;
                        break;
                      }
                  }
              }
            if (flag)
              {
                owner.abort ("Malformed \"ID\" : " + id);
              }
            owner.names.put (id, false);
            this.owner = owner;
            this.id = id;
          }
      }


    class KeyEntry extends NameSpace implements Serializable
      {
        private static final long serialVersionUID = 1L;

        int key_handle;

        byte app_usage;

        PublicKey public_key;
        PrivateKey private_key;
        X509Certificate[] certificate_path;

        byte[] symmetric_key;
        LinkedHashSet<String> endorsed_algorithms;

        String friendly_name;

        boolean device_pin_protection;

        byte[] pin_value;
        short error_count;
        PINPolicy pin_policy;
        boolean enable_pin_caching;
        
        byte biometric_protection;
        byte export_protection;
        byte delete_protection;
        
        boolean private_key_backup;


        HashMap<String,ExtObject> extensions = new HashMap<String,ExtObject> ();

        KeyEntry (Provisioning owner, String id) throws SKSException
          {
            super (owner, id);
            key_handle = next_key_handle++;
            keys.put (key_handle, this);
          }

        void authError () throws SKSException
          {
            abort ("Authorization error for key #" + key_handle, SKSException.ERROR_AUTHORIZATION);
          }

        @SuppressWarnings("fallthrough")
        Vector<KeyEntry> getPINSynchronizedKeys ()
          {
            Vector<KeyEntry> group = new Vector<KeyEntry> ();
            if (pin_policy.grouping == PIN_GROUPING_NONE)
              {
                group.add (this);
              }
            else
              {
                /////////////////////////////////////////////////////////////////////////////////////////
                // Multiple keys "sharing" a PIN means that status and values must be distributed
                /////////////////////////////////////////////////////////////////////////////////////////
                for (KeyEntry key_entry : keys.values ())
                  {
                    if (key_entry.pin_policy == pin_policy)
                      {
                        switch (pin_policy.grouping)
                          {
                            case PIN_GROUPING_UNIQUE:
                              if (app_usage != key_entry.app_usage)
                                {
                                  continue;
                                }
                            case PIN_GROUPING_SIGN_PLUS_STD:
                              if ((app_usage == APP_USAGE_SIGNATURE) ^ (key_entry.app_usage == APP_USAGE_SIGNATURE))
                                {
                                  continue;
                                }
                          }
                        group.add (key_entry);
                      }
                  }
              }
            return group;
          }

        void setErrorCounter (short new_error_count)
          {
            for (KeyEntry key_entry : getPINSynchronizedKeys ())
              {
                key_entry.error_count = new_error_count;
              }
          }
        
         void updatePIN (byte[] new_pin)
          {
            for (KeyEntry key_entry : getPINSynchronizedKeys ())
              {
                key_entry.pin_value = new_pin;
              }
          }

        void verifyPIN (byte[] pin) throws SKSException
          {
            ///////////////////////////////////////////////////////////////////////////////////
            // If there is no PIN policy there is nothing to verify...
            ///////////////////////////////////////////////////////////////////////////////////
            if (pin_policy == null)
              {
                if (device_pin_protection)
                  {
                    ///////////////////////////////////////////////////////////////////////////////////
                    // Only for testing purposes.  Device PINs are out-of-scope for the SKS API
                    ///////////////////////////////////////////////////////////////////////////////////
                    if (!Arrays.equals (pin, new byte[]{'1','2','3','4'}))
                      {
                        authError ();
                      }
                  }
                else if (pin != null)
                  {
                    abort ("Redundant authorization information for key #" + key_handle);
                  }
              }
            else
              {
                ///////////////////////////////////////////////////////////////////////////////////
                // Check that we haven't already passed the limit
                ///////////////////////////////////////////////////////////////////////////////////
                if (error_count >= pin_policy.retry_limit)
                  {
                    authError ();
                  }

                ///////////////////////////////////////////////////////////////////////////////////
                // Check the PIN value
                ///////////////////////////////////////////////////////////////////////////////////
                if (!Arrays.equals (this.pin_value, pin))
                  {
                    setErrorCounter (++error_count);
                    authError ();
                  }

                ///////////////////////////////////////////////////////////////////////////////////
                // A success always resets the PIN error counter(s)
                ///////////////////////////////////////////////////////////////////////////////////
                setErrorCounter ((short)0);
              }
          }

        void verifyPUK (byte[] puk) throws SKSException
          {
            ///////////////////////////////////////////////////////////////////////////////////
            // Check that this key really has a PUK...
            ///////////////////////////////////////////////////////////////////////////////////
            if (pin_policy == null || pin_policy.puk_policy == null)
              {
                abort ("Key #" + key_handle + " has no PUK");
              }

            PUKPolicy puk_policy = pin_policy.puk_policy;
            if (puk_policy.retry_limit > 0)
              {
                ///////////////////////////////////////////////////////////////////////////////////
                // The key is using the "standard" retry PUK policy
                ///////////////////////////////////////////////////////////////////////////////////
                if (puk_policy.error_count >= puk_policy.retry_limit)
                  {
                    authError ();
                  }
              }
            else
              {
                ///////////////////////////////////////////////////////////////////////////////////
                // The "liberal" PUK policy never locks up but introduces a mandatory delay...
                ///////////////////////////////////////////////////////////////////////////////////
                try
                  {
                    Thread.sleep (1000);
                  }
                catch (InterruptedException e)
                  {
                  }
              }

            ///////////////////////////////////////////////////////////////////////////////////
            // Check the PUK value
            ///////////////////////////////////////////////////////////////////////////////////
            if (!Arrays.equals (puk_policy.puk_value, puk))
              {
                if (puk_policy.retry_limit > 0)
                  {
                    ++puk_policy.error_count;
                  }
                authError ();
              }

            ///////////////////////////////////////////////////////////////////////////////////
            // A success always resets the PUK error counter
            ///////////////////////////////////////////////////////////////////////////////////
            puk_policy.error_count = 0;
          }

        void authorizeExportOrDeleteOperation (byte policy, byte[] authorization) throws SKSException
          {
            switch (policy)
              {
                case EXPORT_DELETE_PROTECTION_PIN:
                  verifyPIN (authorization);
                  return;
                  
                case EXPORT_DELETE_PROTECTION_PUK:
                  verifyPUK (authorization);
                  return;

                case EXPORT_DELETE_PROTECTION_NOT_ALLOWED:
                  abort ("Operation not allowed on key #" + key_handle, SKSException.ERROR_NOT_ALLOWED);
              }
            if (authorization != null)
              {
                abort ("Redundant authorization information for key #" + key_handle);
              }
          }

        MacBuilder getEECertMacBuilder (byte[] method) throws SKSException
          {
            if (certificate_path == null)
              {
                owner.abort ("End-entity certificate missing. \"setCertificatePath\" performed?");
              }
            MacBuilder mac_builder = owner.getMacBuilderForMethodCall (method);
            try
              {
                mac_builder.addArray (certificate_path[0].getEncoded ());
                return mac_builder;
             }
            catch (GeneralSecurityException e)
              {
                throw new SKSException (e, SKSException.ERROR_INTERNAL);
              }
          }

        void validateTargetKeyReference (MacBuilder verifier,
                                         byte[] mac,
                                         byte[] authorization,
                                         Provisioning provisioning) throws SKSException
          {
            ///////////////////////////////////////////////////////////////////////////////////
            // Verify MAC
            ///////////////////////////////////////////////////////////////////////////////////
            verifier.addArray (authorization);
            provisioning.verifyMac (verifier, mac);
            
            ///////////////////////////////////////////////////////////////////////////////////
            // Verify KM signature
            ///////////////////////////////////////////////////////////////////////////////////
            try
              {
                Signature km_verify = Signature.getInstance (owner.key_management_key instanceof RSAPublicKey ? 
                                                                                              "SHA256WithRSA" : "SHA256WithECDSA", "BC");
                km_verify.initVerify (owner.key_management_key);
                km_verify.update (provisioning.getMacBuilder (getDeviceCertificatePath ()[0].getEncoded ()).addVerbatim (certificate_path[0].getEncoded ()).getResult ());
                if (!km_verify.verify (authorization))
                  {
                    provisioning.abort ("\"Authorization\" signature did not verify for key #" + key_handle);
                  }
              }
            catch (GeneralSecurityException e)
              {
                provisioning.abort (e.getMessage (), SKSException.ERROR_CRYPTO);
              }
          }

        boolean isRSA ()
          {
            return certificate_path[0].getPublicKey () instanceof RSAPublicKey;
          }
        
        boolean isSymmetric ()
          {
            return symmetric_key != null;
          }

        void checkCryptoDataSize (byte[] data) throws SKSException
          {
            if (data.length > MAX_LENGTH_CRYPTO_DATA)
              {
                abort ("Exceeded \"CryptoDataSize\" for key #" + key_handle);
              }
          }
      }


    class ExtObject implements Serializable
      {
        private static final long serialVersionUID = 1L;

        byte[] qualifier;
        byte[] extension_data;
        byte sub_type;
      }


    class PINPolicy extends NameSpace implements Serializable
      {
        private static final long serialVersionUID = 1L;

        int pin_policy_handle;

        PUKPolicy puk_policy;

        short retry_limit;
        byte format;
        boolean user_defined;
        boolean user_modifiable;
        byte input_method;
        byte grouping;
        byte pattern_restrictions;
        short min_length;
        short max_length;

        PINPolicy (Provisioning owner, String id) throws SKSException
          {
            super (owner, id);
            pin_policy_handle = next_pin_handle++;
            pin_policies.put (pin_policy_handle, this);
          }
      }


    class PUKPolicy extends NameSpace implements Serializable
      {
        private static final long serialVersionUID = 1L;

        int puk_policy_handle;

        byte[] puk_value;
        byte format;
        short retry_limit;
        short error_count;

        PUKPolicy (Provisioning owner, String id) throws SKSException
          {
            super (owner, id);
            puk_policy_handle = next_puk_handle++;
            puk_policies.put (puk_policy_handle, this);
          }
      }


    class Provisioning implements SKSError, Serializable
      {
        private static final long serialVersionUID = 1L;

        int provisioning_handle;

        // The virtual/shared name-space
        HashMap<String,Boolean> names = new HashMap<String,Boolean> ();

        // Post provisioning management
        Vector<PostProvisioningObject> post_provisioning_objects = new Vector<PostProvisioningObject> ();

        String client_session_id;
        String server_session_id;
        String issuer_uri;
        byte[] session_key;
        boolean open = true;
        PublicKey key_management_key;
        short mac_sequence_counter;
        int client_time;
        int session_life_time;
        short session_key_limit;

        Provisioning ()
          {
            provisioning_handle = next_prov_handle++;
            provisionings.put (provisioning_handle, this);
          }

        void verifyMac (MacBuilder actual_mac, byte[] claimed_mac) throws SKSException
          {
            if (!Arrays.equals (actual_mac.getResult (),  claimed_mac))
              {
                abort ("MAC error", SKSException.ERROR_MAC);
              }
          }

        void abort (String message, int exception_type) throws SKSException
          {
            abortProvisioningSession (provisioning_handle);
            throw new SKSException (message, exception_type);
          }

        @Override
        public void abort (String message) throws SKSException
          {
            abort (message, SKSException.ERROR_OPTION);
          }

        byte[] encrypt (byte[] data) throws SKSException, GeneralSecurityException
          {
            byte[] key = getMacBuilder (new byte[0]).addVerbatim (KDF_ENCRYPTION_KEY).getResult ();
            Cipher crypt = Cipher.getInstance ("AES/CBC/PKCS5Padding", "BC");
            byte[] iv = new byte[16];
            new SecureRandom ().nextBytes (iv);
            crypt.init (Cipher.ENCRYPT_MODE, new SecretKeySpec (key, "AES"), new IvParameterSpec (iv));
            return addArrays (iv, crypt.doFinal (data));
          }

        byte[] decrypt (byte[] data) throws SKSException
          {
            byte[] key = getMacBuilder (new byte[0]).addVerbatim (KDF_ENCRYPTION_KEY).getResult ();
            try
              {
                Cipher crypt = Cipher.getInstance ("AES/CBC/PKCS5Padding", "BC");
                crypt.init (Cipher.DECRYPT_MODE, new SecretKeySpec (key, "AES"), new IvParameterSpec (data, 0, 16));
                return crypt.doFinal (data, 16, data.length - 16);
              }
            catch (GeneralSecurityException e)
              {
                throw new SKSException (e);
              }
          }
        
        MacBuilder getMacBuilder (byte[] key_modifier) throws SKSException
          {
            if (session_key_limit-- <= 0)
              {
                abort ("\"SessionKeyLimit\" exceeded");
              }
            try
              {
                return new MacBuilder (addArrays (session_key, key_modifier));
              }
            catch (GeneralSecurityException e)
              {
                throw new SKSException (e);
              }
          }

        MacBuilder getMacBuilderForMethodCall (byte[] method) throws SKSException
          {
            short q = mac_sequence_counter++;
            return getMacBuilder (addArrays (method, new byte[]{(byte)(q >>> 8), (byte)q}));
          }

        KeyEntry getTargetKey (int key_handle) throws SKSException
          {
            KeyEntry key_entry = keys.get (key_handle);
            if (key_entry == null)
              {
                abort ("Key not found #" + key_handle, SKSException.ERROR_NO_KEY);
              }
            if (key_entry.owner.open)
              {
                abort ("Key #" + key_handle + " still in provisioning");
              }
            if (key_entry.owner.key_management_key == null)
              {
                abort ("Key #" + key_handle + " belongs to a non-updatable provisioning session");
              }
            return key_entry;
          }

        public void addPostProvisioningObject (KeyEntry target_key_entry, KeyEntry new_key, boolean upd_or_del) throws SKSException
          {
            for (PostProvisioningObject post_op : post_provisioning_objects)
              {
                if (post_op.new_key != null && post_op.new_key == new_key)
                  {
                    abort ("New key used for multiple operations: " + new_key.id);
                  }
                if (post_op.target_key_entry == target_key_entry)
                  {
                    ////////////////////////////////////////////////////////////////////////////////////////////////
                    // Multiple targeting of the same old key is OK but has restrictions
                    ////////////////////////////////////////////////////////////////////////////////////////////////
                    if ((new_key == null && upd_or_del) || (post_op.new_key == null && post_op.upd_or_del)) // pp_deleteKey
                      {
                        abort ("Delete wasn't exclusive for key #" + target_key_entry.key_handle);
                      }
                    else if (new_key == null && post_op.new_key == null) // pp_unlockKey * 2
                      {
                        abort ("Multiple unlocks of key #" + target_key_entry.key_handle);
                      }
                    else if (upd_or_del && post_op.upd_or_del)
                      {
                        abort ("Multiple updates of key #" + target_key_entry.key_handle);
                      }
                  }
              }
            ////////////////////////////////////////////////////////////////////////////////////////////////
            // We want pp_unlockKey keys to be first in the list so that shared PINs get unlocked as well
            ////////////////////////////////////////////////////////////////////////////////////////////////
            post_provisioning_objects.add (new_key == null ? 0 : post_provisioning_objects.size (),
                                           new PostProvisioningObject (target_key_entry, new_key, upd_or_del));
          }

        public void rangeTest (byte value, byte low_limit, byte high_limit, String object_name) throws SKSException
          {
            if (value > high_limit || value < low_limit)
              {
                abort ("Invalid \"" + object_name + "\" value=" + value);
              }
          }
      }


    class MacBuilder implements Serializable
      {
        private static final long serialVersionUID = 1L;

        Mac mac;

        MacBuilder (byte[] key) throws GeneralSecurityException
          {
            mac = Mac.getInstance ("HmacSHA256", "BC");
            mac.init (new SecretKeySpec (key, "RAW"));
          }

        MacBuilder addVerbatim (byte[] data)
          {
            mac.update (data);
            return this;
          }

        void addArray (byte[] data)
          {
            addShort (data.length);
            mac.update (data);
          }

        void addBlob (byte[] data)
          {
            addInt (data.length);
            mac.update (data);
          }

        void addString (String string) throws SKSException
          {
            try
              {
                addArray (string.getBytes ("UTF-8"));
              }
            catch (UnsupportedEncodingException e)
              {
                abort ("Interal UTF-8");
              }
          }

        void addInt (int i)
          {
            mac.update ((byte)(i >>> 24));
            mac.update ((byte)(i >>> 16));
            mac.update ((byte)(i >>> 8));
            mac.update ((byte)i);
          }

        void addShort (int s)
          {
            mac.update ((byte)(s >>> 8));
            mac.update ((byte)s);
          }

        void addByte (byte b)
          {
            mac.update (b);
          }

        void addBool (boolean flag)
          {
            mac.update (flag ? (byte) 0x01 : (byte) 0x00);
          }

        byte[] getResult ()
          {
            return mac.doFinal ();
          }
      }


    class PostProvisioningObject implements Serializable
      {
        private static final long serialVersionUID = 1L;

        KeyEntry target_key_entry;
        KeyEntry new_key;      // null for pp_deleteKey and pp_unlockKey
        boolean upd_or_del;    // true for pp_updateKey and pp_deleteKey

        PostProvisioningObject (KeyEntry target_key_entry, KeyEntry new_key, boolean upd_or_del)
          {
            this.target_key_entry = target_key_entry;
            this.new_key = new_key;
            this.upd_or_del = upd_or_del;
          }
      }


    /////////////////////////////////////////////////////////////////////////////////////////////
    // Algorithm Support
    /////////////////////////////////////////////////////////////////////////////////////////////

    static class Algorithm implements Serializable
      {
        private static final long serialVersionUID = 1L;

        int mask;
        String jce_name;
      }

    static HashMap<String,Algorithm> algorithms = new HashMap<String,Algorithm> ();

    static void addAlgorithm (String uri, String jce_name, int mask)
      {
        Algorithm alg = new Algorithm ();
        alg.mask = mask;
        alg.jce_name = jce_name;
        algorithms.put (uri, alg);
      }

    static final int ALG_SYM_ENC  = 0x000001;
    static final int ALG_IV_REQ   = 0x000002;
    static final int ALG_IV_INT   = 0x000004;
    static final int ALG_SYML_128 = 0x000008;
    static final int ALG_SYML_192 = 0x000010;
    static final int ALG_SYML_256 = 0x000020;
    static final int ALG_HMAC     = 0x000040;
    static final int ALG_ASYM_ENC = 0x000080;
    static final int ALG_ASYM_SGN = 0x000100;
    static final int ALG_RSA_KEY  = 0x000200;
    static final int ALG_ECC_KEY  = 0x000400;
    static final int ALG_ECC_CRV  = 0x000800;
    static final int ALG_HASH_160 = 0x014000;
    static final int ALG_HASH_256 = 0x020000;
    static final int ALG_HASH_DIV = 0x001000;
    static final int ALG_HASH_MSK = 0x00007F;
    static final int ALG_NONE     = 0x080000;
    static final int ALG_ASYM_KA  = 0x100000;
    static final int ALG_AES_PAD  = 0x200000;

    static final String ALGORITHM_KEY_ATTEST_1         = "http://xmlns.webpki.org/keygen2/1.0#algorithm.sks.k1";

    static final String ALGORITHM_SESSION_KEY_ATTEST_1 = "http://xmlns.webpki.org/keygen2/1.0#algorithm.sks.s1";

    static final short[] RSA_KEY_SIZES = {1024, 2048};
    
    static final int AES_CBC_PKCS5_PADDING = 32;
    
    static
      {
        //////////////////////////////////////////////////////////////////////////////////////
        //  Symmetric Key Encryption and Decryption
        //////////////////////////////////////////////////////////////////////////////////////
        addAlgorithm ("http://www.w3.org/2001/04/xmlenc#aes128-cbc",
                      "AES/CBC/PKCS5Padding",
                      ALG_SYM_ENC | ALG_IV_INT | ALG_IV_REQ | ALG_SYML_128);

        addAlgorithm ("http://www.w3.org/2001/04/xmlenc#aes192-cbc",
                      "AES/CBC/PKCS5Padding",
                      ALG_SYM_ENC | ALG_IV_INT | ALG_IV_REQ | ALG_SYML_192);

        addAlgorithm ("http://www.w3.org/2001/04/xmlenc#aes256-cbc",
                      "AES/CBC/PKCS5Padding",
                      ALG_SYM_ENC | ALG_IV_INT | ALG_IV_REQ | ALG_SYML_256);

        addAlgorithm ("http://xmlns.webpki.org/keygen2/1.0#algorithm.aes.ecb.nopad",
                      "AES/ECB/NoPadding",
                      ALG_SYM_ENC | ALG_SYML_128 | ALG_SYML_192 | ALG_SYML_256 | ALG_AES_PAD);

        addAlgorithm ("http://xmlns.webpki.org/keygen2/1.0#algorithm.aes.cbc.pkcs5",
                      "AES/CBC/PKCS5Padding",
                      ALG_SYM_ENC | ALG_IV_REQ | ALG_SYML_128 | ALG_SYML_192 | ALG_SYML_256);

        //////////////////////////////////////////////////////////////////////////////////////
        //  HMAC Operations
        //////////////////////////////////////////////////////////////////////////////////////
        addAlgorithm ("http://www.w3.org/2000/09/xmldsig#hmac-sha1", "HmacSHA1", ALG_HMAC);

        addAlgorithm ("http://www.w3.org/2001/04/xmldsig-more#hmac-sha256", "HmacSHA256", ALG_HMAC);

        //////////////////////////////////////////////////////////////////////////////////////
        //  Asymmetric Key Decryption
        //////////////////////////////////////////////////////////////////////////////////////
        addAlgorithm ("http://www.w3.org/2001/04/xmlenc#rsa-1_5",
                      "RSA/ECB/PKCS1Padding",
                      ALG_ASYM_ENC | ALG_RSA_KEY);

        addAlgorithm ("http://xmlns.webpki.org/keygen2/1.0#algorithm.rsa.raw",
                      "RSA/ECB/NoPadding",
                      ALG_ASYM_ENC | ALG_RSA_KEY);

        //////////////////////////////////////////////////////////////////////////////////////
        //  Diffie-Hellman Key Agreement
        //////////////////////////////////////////////////////////////////////////////////////
        addAlgorithm ("http://xmlns.webpki.org/keygen2/1.0#algorithm.ecdh",
                      "ECDHC",
                      ALG_ASYM_KA | ALG_ECC_KEY);
        
        //////////////////////////////////////////////////////////////////////////////////////
        //  Asymmetric Key Signatures
        //////////////////////////////////////////////////////////////////////////////////////
        addAlgorithm ("http://www.w3.org/2000/09/xmldsig#rsa-sha1",
                      "NONEwithRSA",
                      ALG_ASYM_SGN | ALG_RSA_KEY | ALG_HASH_160);

        addAlgorithm ("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                      "NONEwithRSA",
                      ALG_ASYM_SGN | ALG_RSA_KEY | ALG_HASH_256);

        addAlgorithm ("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
                      "NONEwithECDSA",
                      ALG_ASYM_SGN | ALG_ECC_KEY | ALG_HASH_256);

        addAlgorithm ("http://xmlns.webpki.org/keygen2/1.0#algorithm.rsa.none",
                      "NONEwithRSA",
                      ALG_ASYM_SGN | ALG_RSA_KEY);

        addAlgorithm ("http://xmlns.webpki.org/keygen2/1.0#algorithm.ecdsa.none",
                      "NONEwithECDSA",
                      ALG_ASYM_SGN | ALG_ECC_KEY);

        //////////////////////////////////////////////////////////////////////////////////////
        //  Elliptic Curves
        //////////////////////////////////////////////////////////////////////////////////////
        addAlgorithm ("urn:oid:1.2.840.10045.3.1.7", "secp256r1", ALG_ECC_CRV);

        //////////////////////////////////////////////////////////////////////////////////////
        //  Special Algorithms
        //////////////////////////////////////////////////////////////////////////////////////
        addAlgorithm (ALGORITHM_SESSION_KEY_ATTEST_1, null, 0);

        addAlgorithm (ALGORITHM_KEY_ATTEST_1, null, 0);

        addAlgorithm ("http://xmlns.webpki.org/keygen2/1.0#algorithm.none", null, ALG_NONE);

      }


    /////////////////////////////////////////////////////////////////////////////////////////////
    // Utility Functions
    /////////////////////////////////////////////////////////////////////////////////////////////

    static final char[] ATTESTATION_KEY_PASSWORD =  {'t','e','s','t','i','n','g'};

    static final String ATTESTATION_KEY_ALIAS = "mykey";

    KeyStore getAttestationKeyStore () throws GeneralSecurityException
      {
        try
          {
            KeyStore ks = KeyStore.getInstance ("JKS");
            ks.load (getClass ().getResourceAsStream ("attestationkeystore.jks"), ATTESTATION_KEY_PASSWORD);
            return ks;
          }
        catch (IOException e)
          {
            throw new GeneralSecurityException (e);
          }
      }
    
    X509Certificate[] getDeviceCertificatePath () throws GeneralSecurityException
      {
        return new X509Certificate[]{(X509Certificate)getAttestationKeyStore ().getCertificate (ATTESTATION_KEY_ALIAS)};
      }

    PrivateKey getAttestationKey () throws GeneralSecurityException
      {
        return (PrivateKey) getAttestationKeyStore ().getKey (ATTESTATION_KEY_ALIAS, ATTESTATION_KEY_PASSWORD);        
      }

    Provisioning getOpenProvisioningSession (int provisioning_handle) throws SKSException
      {
        Provisioning provisioning = provisionings.get (provisioning_handle);
        if (provisioning == null)
          {
            abort ("No such provisioning session: " + provisioning_handle, SKSException.ERROR_NO_SESSION);
          }
        if (!provisioning.open)
          {
            abort ("Session not open: " +  provisioning_handle, SKSException.ERROR_NO_SESSION);
          }
        return provisioning;
      }

    int getShort (byte[] buffer, int index)
      {
        return ((buffer[index++] << 8) & 0xFFFF) + (buffer[index] & 0xFF);
      }
    
    KeyEntry getOpenKey (int key_handle) throws SKSException
      {
        KeyEntry key_entry = keys.get (key_handle);
        if (key_entry == null)
          {
            abort ("Key not found #" + key_handle, SKSException.ERROR_NO_KEY);
          }
        if (!key_entry.owner.open)
          {
            abort ("Key #" + key_handle + " not belonging to open session", SKSException.ERROR_NO_KEY);
          }
        return key_entry;
      }

    KeyEntry getStdKey (int key_handle) throws SKSException
      {
        KeyEntry key_entry = keys.get (key_handle);
        if (key_entry == null)
          {
            abort ("Key not found #" + key_handle, SKSException.ERROR_NO_KEY);
          }
        if (key_entry.owner.open)
          {
            abort ("Key #" + key_handle + " still in provisioning", SKSException.ERROR_NO_KEY);
          }
        return key_entry;
      }

    EnumeratedKey getKey (Iterator<KeyEntry> iter)
      {
        while (iter.hasNext ())
          {
            KeyEntry key_entry = iter.next ();
            if (!key_entry.owner.open)
              {
                return new EnumeratedKey (key_entry.key_handle, key_entry.owner.provisioning_handle);
              }
          }
        return new EnumeratedKey ();
      }

    void deleteObject (HashMap<Integer,?> objects, Provisioning provisioning)
      {
        Iterator<?> list = objects.values ().iterator ();
        while (list.hasNext ())
          {
            NameSpace element = (NameSpace)list.next ();
            if (element.owner == provisioning)
              {
                list.remove ();
              }
          }
      }

    EnumeratedProvisioningSession getProvisioning (Iterator<Provisioning> iter, boolean provisioning_state)
      {
        while (iter.hasNext ())
          {
            Provisioning provisioning = iter.next ();
            if (provisioning.open == provisioning_state)
              {
                return new EnumeratedProvisioningSession (provisioning.key_management_key,
                                                          provisioning.client_time,
                                                          provisioning.session_life_time,
                                                          provisioning.provisioning_handle, 
                                                          provisioning.client_session_id,
                                                          provisioning.server_session_id,
                                                          provisioning.issuer_uri);
              }
          }
        return new EnumeratedProvisioningSession ();
      }

    @Override
    public void abort (String message) throws SKSException
      {
        throw new SKSException (message);
      }

    void abort (String message, int option) throws SKSException
      {
        throw new SKSException (message, option);
      }

    @SuppressWarnings("fallthrough")
    void verifyPINPolicyCompliance (boolean forced_setter, byte[] pin_value, PINPolicy pin_policy, byte app_usage, SKSError sks_error) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Check PIN length
        ///////////////////////////////////////////////////////////////////////////////////
        if (pin_value.length > pin_policy.max_length || pin_value.length < pin_policy.min_length)
          {
            sks_error.abort ("PIN length error");
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Check PIN syntax
        ///////////////////////////////////////////////////////////////////////////////////
        boolean upperalpha = false;
        boolean loweralpha = false;
        boolean number = false;
        boolean nonalphanum = false;
        for (int i = 0; i < pin_value.length; i++)
          {
            int c = pin_value[i];
            if (c >= 'A' && c <= 'Z')
              {
                upperalpha = true;
              }
            else if (c >= 'a' && c <= 'z')
              {
                loweralpha = true;
              }
            else if (c >= '0' && c <= '9')
              {
                number = true;
              }
            else
              {
                nonalphanum = true;
              }
          }
        if ((pin_policy.format == PIN_FORMAT_NUMERIC && (loweralpha || nonalphanum || upperalpha)) ||
            (pin_policy.format == PIN_FORMAT_ALPHANUMERIC && (loweralpha || nonalphanum)))
          {
            sks_error.abort ("PIN syntax error");
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Check PIN patterns
        ///////////////////////////////////////////////////////////////////////////////////
        if ((pin_policy.pattern_restrictions & PIN_PATTERN_MISSING_GROUP) != 0)
          {
            if (!upperalpha || !number ||
                (pin_policy.format == PIN_FORMAT_STRING && (!loweralpha || !nonalphanum)))
              {
                sks_error.abort ("Missing character group in PIN");
              }
          }
        if ((pin_policy.pattern_restrictions & PIN_PATTERN_SEQUENCE) != 0)
          {
            byte c = pin_value[0];
            byte f = (byte)(pin_value[1] - c);
            boolean seq = (f == 1) || (f == -1);
            for (int i = 1; i < pin_value.length; i++)
              {
                if ((byte)(c + f) != pin_value[i])
                  {
                    seq = false;
                    break;
                  }
                c = pin_value[i];
              }
            if (seq)
              {
                sks_error.abort ("PIN must not be a sequence");
              }
          }
        if ((pin_policy.pattern_restrictions & PIN_PATTERN_REPEATED) != 0)
          {
            for (int i = 0; i < pin_value.length; i++)
              {
                byte b = pin_value[i];
                for (int j = 0; j < pin_value.length; j++)
                  {
                    if (j != i && b == pin_value[j])
                      {
                        sks_error.abort ("Repeated PIN character");
                      }
                  }
              }
          }
        if ((pin_policy.pattern_restrictions & (PIN_PATTERN_TWO_IN_A_ROW | PIN_PATTERN_THREE_IN_A_ROW)) != 0)
          {
            int max = ((pin_policy.pattern_restrictions & PIN_PATTERN_TWO_IN_A_ROW) == 0) ? 3 : 2;
            byte c = pin_value [0];
            int same_count = 1;
            for (int i = 1; i < pin_value.length; i++)
              {
                if (c == pin_value[i])
                  {
                    if (++same_count == max)
                      {
                        sks_error.abort ("PIN with " + max + " or more of same the character in a row");
                      }
                  }
                else
                  {
                    same_count = 1;
                    c = pin_value[i];
                  }
              }
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Check that PIN grouping rules are followed
        ///////////////////////////////////////////////////////////////////////////////////
        for (KeyEntry key_entry : keys.values ())
          {
            if (key_entry.pin_policy == pin_policy)
              {
                boolean equal = Arrays.equals (key_entry.pin_value, pin_value);
                if (forced_setter && !equal)
                  {
                    continue;
                  }
                switch (pin_policy.grouping)
                  {
                    case PIN_GROUPING_SHARED:
                      if (!equal)
                        {
                          sks_error.abort ("Grouping = \"shared\" requires identical PINs");
                        }
                      continue;

                    case PIN_GROUPING_UNIQUE:
                      if (equal ^ (app_usage == key_entry.app_usage))
                        {
                          sks_error.abort ("Grouping = \"unique\" PIN error");
                        }
                      continue;

                    case PIN_GROUPING_SIGN_PLUS_STD:
                      if (((app_usage == APP_USAGE_SIGNATURE) ^ (key_entry.app_usage == APP_USAGE_SIGNATURE)) ^ !equal)
                        {
                          sks_error.abort ("Grouping = \"signature+standard\" PIN error");
                        }
                  }
              }
          }
      }
    
    void testUpdatablePIN (KeyEntry key_entry, byte[] new_pin) throws SKSException
      {
        if (key_entry.pin_policy == null)
          {
            if (key_entry.device_pin_protection)
              {
                abort ("Key #" + key_entry.key_handle + " is device PIN protected");
              }
            abort ("Key #" + key_entry.key_handle + " is not PIN protected");
          }
        if (!key_entry.pin_policy.user_modifiable)
          {
            abort ("PIN for key #" + key_entry.key_handle + " is not user modifiable", SKSException.ERROR_NOT_ALLOWED);
          }
        verifyPINPolicyCompliance (true, new_pin, key_entry.pin_policy, key_entry.app_usage, this);
      }
    
    void deleteEmptySession (Provisioning provisioning)
      {
        for (KeyEntry key_entry : keys.values ())
          {
            if (key_entry.owner == provisioning)
              {
                return;
              }
          }
        provisionings.remove (provisioning.provisioning_handle);
      }

    void localDeleteKey (KeyEntry key_entry)
      {
        keys.remove (key_entry.key_handle);
        if (key_entry.pin_policy != null)
          {
            int pin_policy_handle = key_entry.pin_policy.pin_policy_handle;
            for (int handle : keys.keySet ())
              {
                if (handle == pin_policy_handle)
                  {
                    return;
                  }
              }
            pin_policies.remove (pin_policy_handle);
            if (key_entry.pin_policy.puk_policy != null)
              {
                int puk_policy_handle = key_entry.pin_policy.puk_policy.puk_policy_handle;
                for (int handle : pin_policies.keySet ())
                  {
                    if (handle == puk_policy_handle)
                      {
                        return;
                      }
                  }
                puk_policies.remove (puk_policy_handle);
              }
          }
      }

    Algorithm checkKeyAndAlgorithm (KeyEntry key_entry, String input_algorithm, int expected_type) throws SKSException
      {
        Algorithm alg = getAlgorithm (input_algorithm);
        if ((alg.mask & expected_type) == 0)
          {
            abort ("Algorithm does not match operation: " + input_algorithm, SKSException.ERROR_ALGORITHM);
          }
        if (((alg.mask & (ALG_SYM_ENC | ALG_HMAC)) != 0) ^ key_entry.isSymmetric ())
          {
            abort ((key_entry.isSymmetric () ? "S" : "As") + "ymmetric key #" + key_entry.key_handle + " is incompatible with: " + input_algorithm, SKSException.ERROR_ALGORITHM);
          }
        if (key_entry.isSymmetric ())
          {
            testAESKey (input_algorithm, key_entry.symmetric_key, "#" + key_entry.key_handle, this);
          }
        else if (key_entry.isRSA () ^ (alg.mask & ALG_RSA_KEY) != 0)
          {
            abort ((key_entry.isRSA () ? "RSA" : "ECC") + " key #" + key_entry.key_handle + " is incompatible with: " + input_algorithm, SKSException.ERROR_ALGORITHM);
          }
        if (key_entry.endorsed_algorithms.isEmpty () || key_entry.endorsed_algorithms.contains (input_algorithm))
          {
            return alg;
          }
        abort ("\"EndorsedAlgorithms\" for key #" + key_entry.key_handle + " does not include: " + input_algorithm, SKSException.ERROR_ALGORITHM);
        return null;    // For the compiler only...
      }

    byte[] addArrays (byte[] a, byte[] b)
      {
        byte[] r = new byte[a.length + b.length];
        System.arraycopy (a, 0, r, 0, a.length);
        System.arraycopy (b, 0, r, a.length, b.length);
        return r;
      }

    void testAESKey (String algorithm, byte[] symmetric_key, String key_id, SKSError sks_error) throws SKSException
      {
        Algorithm alg = getAlgorithm (algorithm);
        if ((alg.mask & ALG_SYM_ENC) != 0)
          {
            int l = symmetric_key.length;
            if (l == 16) l = ALG_SYML_128;
            else if (l == 24) l = ALG_SYML_192;
            else if (l == 32) l = ALG_SYML_256;
            else l = 0;
            if ((l & alg.mask) == 0)
              {
                sks_error.abort ("Key " + key_id + " has wrong size (" + symmetric_key.length + ") for algorithm: " + algorithm);
              }
          }
      }

    Algorithm getAlgorithm (String algorithm_uri) throws SKSException
      {
        Algorithm alg = algorithms.get (algorithm_uri);
        if (alg == null)
          {
            abort ("Unsupported algorithm: " + algorithm_uri, SKSException.ERROR_ALGORITHM);
          }
        return alg;
      }

    void verifyExportDeleteProtection (byte actual_protection, byte min_protection_val, Provisioning provisioning) throws SKSException
      {
        if (actual_protection >= min_protection_val && actual_protection <= EXPORT_DELETE_PROTECTION_PUK)
          {
            provisioning.abort ("Protection object lacks a PIN or PUK object");
          }
      }

    void addUpdateKeyOrCloneKeyProtection (int key_handle,
                                           int target_key_handle,
                                           byte[] authorization,
                                           byte[] mac,
                                           boolean update) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get open key and associated provisioning session
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry new_key = getOpenKey (key_handle);
        Provisioning provisioning = new_key.owner;

        ///////////////////////////////////////////////////////////////////////////////////
        // Get key to be updated/cloned
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry target_key_entry = provisioning.getTargetKey (target_key_handle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Perform some "sanity" tests
        ///////////////////////////////////////////////////////////////////////////////////
        if (new_key.pin_policy != null || new_key.device_pin_protection)
          {
            provisioning.abort ("Update/clone keys cannot have PIN codes");
          }
        if (target_key_entry.app_usage != new_key.app_usage)
          {
            provisioning.abort ("Update/clone keys must have the same \"AppUsage\" as the target key");
          }
        if (!update)
          {
            ///////////////////////////////////////////////////////////////////////////////////
            // Cloned_kp keys are constrained
            ///////////////////////////////////////////////////////////////////////////////////
            if (target_key_entry.pin_policy != null && target_key_entry.pin_policy.grouping == PIN_GROUPING_NONE)
              {
                provisioning.abort ("Cloned key protection must not have PIN grouping=\"none\"");
              }
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify incoming MAC and target key data
        ///////////////////////////////////////////////////////////////////////////////////
        MacBuilder verifier = new_key.getEECertMacBuilder (update ? METHOD_PP_UPDATE_KEY : METHOD_PP_CLONE_KEY_PROTECTION);
        target_key_entry.validateTargetKeyReference (verifier, mac, authorization, provisioning);

        ///////////////////////////////////////////////////////////////////////////////////
        // Put the operation in the pp-op buffer used by "closeProvisioningSession"
        ///////////////////////////////////////////////////////////////////////////////////
        provisioning.addPostProvisioningObject (target_key_entry, new_key, update);
      }

    void addUnlockKeyOrDeleteKey (int provisioning_handle,
                                  int target_key_handle,
                                  byte[] authorization,
                                  byte[] mac,
                                  boolean delete) throws SKSException
      {
        // /////////////////////////////////////////////////////////////////////////////////
        // Get provisioning session
        // /////////////////////////////////////////////////////////////////////////////////
        Provisioning provisioning = getOpenProvisioningSession (provisioning_handle);

        // /////////////////////////////////////////////////////////////////////////////////
        // Get key to be deleted or unlocked
        // /////////////////////////////////////////////////////////////////////////////////
        KeyEntry target_key_entry = provisioning.getTargetKey (target_key_handle);
        if (!delete && target_key_entry.pin_policy == null)
          {
            provisioning.abort ("Key #" + target_key_handle + " is not PIN protected");
          }

        // /////////////////////////////////////////////////////////////////////////////////
        // Verify incoming MAC and target key data
        // /////////////////////////////////////////////////////////////////////////////////
        MacBuilder verifier = provisioning.getMacBuilderForMethodCall (delete ? METHOD_PP_DELETE_KEY : METHOD_PP_UNLOCK_KEY);
        target_key_entry.validateTargetKeyReference (verifier, mac, authorization, provisioning);

        // /////////////////////////////////////////////////////////////////////////////////
        // Put the operation in the pp-op buffer used by
        // "closeProvisioningSession"
        // /////////////////////////////////////////////////////////////////////////////////
        provisioning.addPostProvisioningObject (target_key_entry, null, delete);
      }

    /////////////////////////////////////////////////////////////////////////////////////////////
    // PKCS #1 Signature Support Data
    /////////////////////////////////////////////////////////////////////////////////////////////
    static final byte[] DIGEST_INFO_SHA1   = {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02,
                                              0x1a, 0x05, 0x00, 0x04, 0x14};

    static final byte[] DIGEST_INFO_SHA256 = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte)0x86, 0x48,
                                              0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                               unlockKey                                    //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public void unlockKey (int key_handle, byte[] authorization) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key (which must belong to an already fully provisioned session)
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry key_entry = getStdKey (key_handle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify PUK
        ///////////////////////////////////////////////////////////////////////////////////
        key_entry.verifyPUK (authorization);

        ///////////////////////////////////////////////////////////////////////////////////
        // Success!  Reset PIN error counter(s)
        ///////////////////////////////////////////////////////////////////////////////////
        key_entry.setErrorCounter ((short)0);
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                               changePIN                                    //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public void changePIN (int key_handle, byte[] authorization, byte[] new_pin) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key (which must belong to an already fully provisioned session)
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry key_entry = getStdKey (key_handle);
        
        ///////////////////////////////////////////////////////////////////////////////////
        // Test target PIN
        ///////////////////////////////////////////////////////////////////////////////////
        testUpdatablePIN (key_entry, new_pin);

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify old PIN
        ///////////////////////////////////////////////////////////////////////////////////
        key_entry.verifyPIN (authorization);

        ///////////////////////////////////////////////////////////////////////////////////
        // Success!  Set PIN value(s)
        ///////////////////////////////////////////////////////////////////////////////////
        key_entry.updatePIN (new_pin);
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                                 setPIN                                     //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public void setPIN (int key_handle, byte[] authorization, byte[] new_pin) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key (which must belong to an already fully provisioned session)
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry key_entry = getStdKey (key_handle);
        
        ///////////////////////////////////////////////////////////////////////////////////
        // Test target PIN
        ///////////////////////////////////////////////////////////////////////////////////
        testUpdatablePIN (key_entry, new_pin);

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify PUK
        ///////////////////////////////////////////////////////////////////////////////////
        key_entry.verifyPUK (authorization);

        ///////////////////////////////////////////////////////////////////////////////////
        // Success!  Set PIN value(s) and unlock associated key(s)
        ///////////////////////////////////////////////////////////////////////////////////
        key_entry.updatePIN (new_pin);
        key_entry.setErrorCounter ((short)0);
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                               deleteKey                                    //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public void deleteKey (int key_handle, byte[] authorization) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key (which must belong to an already fully provisioned session)
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry key_entry = getStdKey (key_handle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Check that authorization matches the declaration
        ///////////////////////////////////////////////////////////////////////////////////
        key_entry.authorizeExportOrDeleteOperation (key_entry.delete_protection, authorization);

        ///////////////////////////////////////////////////////////////////////////////////
        // Delete key and optionally the entire provisioning object (if empty)
        ///////////////////////////////////////////////////////////////////////////////////
        localDeleteKey (key_entry);
        deleteEmptySession (key_entry.owner);
      }

    
    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                               exportKey                                    //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public byte[] exportKey (int key_handle, byte[] authorization) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key (which must belong to an already fully provisioned session)
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry key_entry = getStdKey (key_handle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Check that authorization matches the declaration
        ///////////////////////////////////////////////////////////////////////////////////
        key_entry.authorizeExportOrDeleteOperation (key_entry.export_protection, authorization);

        ///////////////////////////////////////////////////////////////////////////////////
        // Export key in raw unencrypted format
        ///////////////////////////////////////////////////////////////////////////////////
        return key_entry.isSymmetric () ? key_entry.symmetric_key : key_entry.private_key.getEncoded ();
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                              setProperty                                   //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public void setProperty (int key_handle,
                             String type,
                             byte[] name,
                             byte[] value) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key (which must belong to an already fully provisioned session)
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry key_entry = getStdKey (key_handle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Lookup the extension(s) bound to the key
        ///////////////////////////////////////////////////////////////////////////////////
        ExtObject ext_obj = key_entry.extensions.get (type);
        if (ext_obj == null || ext_obj.sub_type != SUB_TYPE_PROPERTY_BAG)
          {
            abort ("No such \"PropertyBag\" : " + type);
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Found, now look for the property name and update the associated value
        ///////////////////////////////////////////////////////////////////////////////////
        int i = 0;
        while (i < ext_obj.extension_data.length)
          {
            int nam_len = getShort (ext_obj.extension_data, i);
            i += 2;
            byte[] pname = Arrays.copyOfRange (ext_obj.extension_data, i, nam_len + i);
            i += nam_len;
            int val_len = getShort (ext_obj.extension_data, i + 1);
            if (Arrays.equals (name, pname))
              {
                if (ext_obj.extension_data[i] != 0x01)
                  {
                    abort ("\"Property\" not writable: " + name, SKSException.ERROR_NOT_ALLOWED);
                  }
                ext_obj.extension_data = addArrays (addArrays (Arrays.copyOfRange (ext_obj.extension_data, 0, ++i),
                                                               addArrays (new byte[]{(byte)(value.length >> 8),(byte)value.length}, value)),
                                                    Arrays.copyOfRange (ext_obj.extension_data, i + val_len + 2, ext_obj.extension_data.length));
                return;
              }
            i += val_len + 3;
          }
        abort ("\"Property\" not found: " + name);
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                              getExtension                                  //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public Extension getExtension (int key_handle, String type) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key (which must belong to an already fully provisioned session)
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry key_entry = getStdKey (key_handle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Lookup the extension(s) bound to the key
        ///////////////////////////////////////////////////////////////////////////////////
        ExtObject ext_obj = key_entry.extensions.get (type);
        if (ext_obj == null)
          {
            abort ("No such extension: " + type + " for key #" + key_handle);
          }
        return new Extension (ext_obj.sub_type, ext_obj.qualifier, ext_obj.extension_data);
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                         asymmetricKeyDecrypt                               //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public byte[] asymmetricKeyDecrypt (int key_handle,
                                        String algorithm,
                                        byte[] parameters,
                                        byte[] authorization,
                                        byte[] data) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key (which must belong to an already fully provisioned session)
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry key_entry = getStdKey (key_handle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Check that the encryption algorithm is known and applicable
        ///////////////////////////////////////////////////////////////////////////////////
        Algorithm alg = checkKeyAndAlgorithm (key_entry, algorithm, ALG_ASYM_ENC);
        if (parameters != null)  // Only support basic RSA yet...
          {
            abort ("\"Parameters\" for key #" + key_handle + " do not match algorithm");
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify PIN (in any)
        ///////////////////////////////////////////////////////////////////////////////////
        key_entry.verifyPIN (authorization);

        ///////////////////////////////////////////////////////////////////////////////////
        // Finally, perform operation
        ///////////////////////////////////////////////////////////////////////////////////
        try
          {
            Cipher cipher = Cipher.getInstance (alg.jce_name, "BC");
            cipher.init (Cipher.DECRYPT_MODE, key_entry.private_key);
            return cipher.doFinal (data);
          }
        catch (Exception e)
          {
            throw new SKSException (e, SKSException.ERROR_CRYPTO);
          }
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                             signHashedData                                 //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public byte[] signHashedData (int key_handle,
                                  String algorithm,
                                  byte[] parameters,
                                  byte[] authorization,
                                  byte[] data) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key (which must belong to an already fully provisioned session)
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry key_entry = getStdKey (key_handle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Enforce the data limit
        ///////////////////////////////////////////////////////////////////////////////////
        key_entry.checkCryptoDataSize (data);

        ///////////////////////////////////////////////////////////////////////////////////
        // Check that the signature algorithm is known and applicable
        ///////////////////////////////////////////////////////////////////////////////////
        Algorithm alg = checkKeyAndAlgorithm (key_entry, algorithm, ALG_ASYM_SGN);
        int hash_len = (alg.mask / ALG_HASH_DIV) & ALG_HASH_MSK;
        if (hash_len > 0 && hash_len != data.length)
          {
            abort ("Incorrect length of \"Data\": " + data.length);
          }
        if (parameters != null)  // Only supports non-parameterized operations yet...
          {
            abort ("\"Parameters\" for key #" + key_handle + " do not match algorithm");
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify PIN (in any)
        ///////////////////////////////////////////////////////////////////////////////////
        key_entry.verifyPIN (authorization);

        ///////////////////////////////////////////////////////////////////////////////////
        // Finally, perform operation
        ///////////////////////////////////////////////////////////////////////////////////
        try
          {
            if (key_entry.isRSA () && hash_len > 0)
              {
                data = addArrays (hash_len == 20 ? DIGEST_INFO_SHA1 : DIGEST_INFO_SHA256, data);
              }
            Signature signature = Signature.getInstance (alg.jce_name, "BC");
            signature.initSign (key_entry.private_key);
            signature.update (data);
            return signature.sign ();
          }
        catch (Exception e)
          {
            throw new SKSException (e, SKSException.ERROR_CRYPTO);
          }
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                             keyAgreement                                   //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public byte[] keyAgreement (int key_handle, 
                                String algorithm,
                                byte[] parameters,
                                byte[] authorization,
                                PublicKey public_key) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key (which must belong to an already fully provisioned session)
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry key_entry = getStdKey (key_handle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Check that the key agreement algorithm is known and applicable
        ///////////////////////////////////////////////////////////////////////////////////
        Algorithm alg = checkKeyAndAlgorithm (key_entry, algorithm, ALG_ASYM_KA);
        if (parameters != null)  // Only support external KDFs yet...
          {
            abort ("\"Parameters\" for key #" + key_handle + " do not match algorithm");
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Check that the key type matches the algorithm
        ///////////////////////////////////////////////////////////////////////////////////
        if (!(public_key instanceof ECPublicKey))
          {
            abort ("Incorrect \"PublicKey\" type");
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify PIN (in any)
        ///////////////////////////////////////////////////////////////////////////////////
        key_entry.verifyPIN (authorization);

        ///////////////////////////////////////////////////////////////////////////////////
        // Finally, perform operation
        ///////////////////////////////////////////////////////////////////////////////////
        try
          {
            KeyAgreement key_agreement = KeyAgreement.getInstance (alg.jce_name, "BC");
            key_agreement.init (key_entry.private_key);
            key_agreement.doPhase (public_key, true);
            return key_agreement.generateSecret ();
          }
        catch (Exception e)
          {
            throw new SKSException (e, SKSException.ERROR_CRYPTO);
          }
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                          symmetricKeyEncrypt                               //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public byte[] symmetricKeyEncrypt (int key_handle,
                                       String algorithm,
                                       boolean mode,
                                       byte[] iv,
                                       byte[] authorization,
                                       byte[] data) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key (which must belong to an already fully provisioned session)
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry key_entry = getStdKey (key_handle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Enforce the data limit
        ///////////////////////////////////////////////////////////////////////////////////
        key_entry.checkCryptoDataSize (data);

        ///////////////////////////////////////////////////////////////////////////////////
        // Check the key and then check that the algorithm is known and applicable
        ///////////////////////////////////////////////////////////////////////////////////
        Algorithm alg = checkKeyAndAlgorithm (key_entry, algorithm, ALG_SYM_ENC);
        if ((alg.mask & ALG_IV_REQ) == 0 || (alg.mask & ALG_IV_INT) != 0)
          {
            if (iv != null)
              {
                abort ("IV does not apply to: " + algorithm);
              }
          }
        else if (iv == null || iv.length != 16)
          {
            abort ("IV must be 16 bytes for: " + algorithm);
          }
        if ((!mode || (alg.mask & ALG_AES_PAD) != 0) && data.length % 16 != 0)
          {
            abort ("Data must be a multiple of 16 bytes for: " + algorithm + (mode ? " encryption" : " decryption"));
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify PIN (in any)
        ///////////////////////////////////////////////////////////////////////////////////
        key_entry.verifyPIN (authorization);

        ///////////////////////////////////////////////////////////////////////////////////
        // Finally, perform operation
        ///////////////////////////////////////////////////////////////////////////////////
        try
          {
            Cipher crypt = Cipher.getInstance (alg.jce_name, "BC");
            SecretKeySpec sk = new SecretKeySpec (key_entry.symmetric_key, "AES");
            int jce_mode = mode ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;
            if ((alg.mask & ALG_IV_INT) != 0)
              {
                iv = new byte[16];
                if (mode)
                  {
                    new SecureRandom ().nextBytes (iv);
                  }
                else
                  {
                    byte[] temp = new byte[data.length - 16];
                    System.arraycopy (data, 0, iv, 0, 16);
                    System.arraycopy (data, 16, temp, 0, temp.length);
                    data = temp;
                  }
              }
            if (iv == null)
              {
                crypt.init (jce_mode, sk);
              }
            else
              {
                crypt.init (jce_mode, sk, new IvParameterSpec (iv));
              }
            data = crypt.doFinal (data);
            return (mode && (alg.mask & ALG_IV_INT) != 0) ? addArrays (iv, data) : data;
          }
        catch (Exception e)
          {
            throw new SKSException (e, SKSException.ERROR_CRYPTO);
          }
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                               performHMAC                                  //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public byte[] performHMAC (int key_handle,
                               String algorithm,
                               byte[] authorization,
                               byte[] data) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key (which must belong to an already fully provisioned session)
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry key_entry = getStdKey (key_handle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Enforce the data limit
        ///////////////////////////////////////////////////////////////////////////////////
        key_entry.checkCryptoDataSize (data);

        ///////////////////////////////////////////////////////////////////////////////////
        // Check the key and then check that the algorithm is known and applicable
        ///////////////////////////////////////////////////////////////////////////////////
        Algorithm alg = checkKeyAndAlgorithm (key_entry, algorithm, ALG_HMAC);

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify PIN (in any)
        ///////////////////////////////////////////////////////////////////////////////////
        key_entry.verifyPIN (authorization);

        ///////////////////////////////////////////////////////////////////////////////////
        // Finally, perform operation
        ///////////////////////////////////////////////////////////////////////////////////
        try
          {
            Mac mac = Mac.getInstance (alg.jce_name, "BC");
            mac.init (new SecretKeySpec (key_entry.symmetric_key, "RAW"));
            return mac.doFinal (data);
          }
        catch (Exception e)
          {
            throw new SKSException (e, SKSException.ERROR_CRYPTO);
          }
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                              getDeviceInfo                                 //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public DeviceInfo getDeviceInfo () throws SKSException
      {
        try
          {
            return new DeviceInfo (SKS_API_LEVEL,
                                   SKS_UPDATE_URL,
                                   SKS_VENDOR_NAME,
                                   SKS_VENDOR_DESCRIPTION,
                                   getDeviceCertificatePath (),
                                   new HashSet<String> (algorithms.keySet ()),
                                   SKS_RSA_EXPONENT_SUPPORT,
                                   RSA_KEY_SIZES,
                                   MAX_LENGTH_CRYPTO_DATA,
                                   MAX_LENGTH_EXTENSION_DATA,
                                   SKS_DEVICE_PIN_SUPPORT,
                                   SKS_BIOMETRIC_SUPPORT);
          }
        catch (GeneralSecurityException e)
          {
            throw new SKSException (e, SKSException.ERROR_CRYPTO);
          }
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                              enumerateKeys                                 //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public EnumeratedKey enumerateKeys (EnumeratedKey ek) throws SKSException
      {
        if (!ek.isValid ())
          {
            return getKey (keys.values ().iterator ());
          }
        Iterator<KeyEntry> list = keys.values ().iterator ();
        while (list.hasNext ())
          {
            if (list.next ().key_handle == ek.getKeyHandle ())
              {
                return getKey (list);
              }
          }
        return new EnumeratedKey ();
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                          getKeyProtectionInfo                              //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public KeyProtectionInfo getKeyProtectionInfo (int key_handle) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key (which must belong to an already fully provisioned session)
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry key_entry = getStdKey (key_handle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Find the protection data objects that are not stored in the key entry
        ///////////////////////////////////////////////////////////////////////////////////
        byte protection_status = PROTECTION_STATUS_NO_PIN;
        byte puk_format = 0;
        short puk_retry_limit = 0;
        short puk_error_count = 0;
        boolean user_defined = false;
        boolean user_modifiable = false;
        byte format = 0;
        short retry_limit = 0;
        byte grouping = 0;
        byte pattern_restrictions = 0;
        short min_length = 0;
        short max_length = 0;
        byte input_method = 0;
        if (key_entry.device_pin_protection)
          {
            protection_status = PROTECTION_STATUS_DEVICE_PIN;
          }
        else if (key_entry.pin_policy != null)
          {
            protection_status = PROTECTION_STATUS_PIN_PROTECTED;
            if (key_entry.error_count >= key_entry.pin_policy.retry_limit)
              {
                protection_status |= PROTECTION_STATUS_PIN_BLOCKED;
              }
            if (key_entry.pin_policy.puk_policy != null)
              {
                puk_format = key_entry.pin_policy.puk_policy.format; 
                puk_retry_limit = key_entry.pin_policy.puk_policy.retry_limit;
                puk_error_count = key_entry.pin_policy.puk_policy.error_count;
                protection_status |= PROTECTION_STATUS_PUK_PROTECTED;
                if (key_entry.pin_policy.puk_policy.error_count >= key_entry.pin_policy.puk_policy.retry_limit)
                  {
                    protection_status |= PROTECTION_STATUS_PUK_BLOCKED;
                  }
              }
            user_defined = key_entry.pin_policy.user_defined;
            user_modifiable = key_entry.pin_policy.user_modifiable;
            format = key_entry.pin_policy.format;
            retry_limit = key_entry.pin_policy.retry_limit;
            grouping = key_entry.pin_policy.grouping;
            pattern_restrictions = key_entry.pin_policy.pattern_restrictions;
            min_length = key_entry.pin_policy.min_length;
            max_length = key_entry.pin_policy.max_length;
            input_method = key_entry.pin_policy.input_method;
          }
        return new KeyProtectionInfo (protection_status,
                                      puk_format,
                                      puk_retry_limit,
                                      puk_error_count,
                                      user_defined,
                                      user_modifiable,
                                      format,
                                      retry_limit,
                                      grouping,
                                      pattern_restrictions,
                                      min_length,
                                      max_length,
                                      input_method,
                                      key_entry.error_count,
                                      key_entry.biometric_protection,
                                      key_entry.private_key_backup,
                                      key_entry.export_protection,
                                      key_entry.delete_protection,
                                      key_entry.enable_pin_caching);
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                            getKeyAttributes                                //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public KeyAttributes getKeyAttributes (int key_handle) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key (which must belong to an already fully provisioned session)
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry key_entry = getStdKey (key_handle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Return core key entry metadata
        ///////////////////////////////////////////////////////////////////////////////////
        return new KeyAttributes (key_entry.isSymmetric (),
                                  key_entry.app_usage,
                                  key_entry.friendly_name,
                                  key_entry.certificate_path,
                                  key_entry.endorsed_algorithms,
                                  new HashSet<String> (key_entry.extensions.keySet ()));
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                       enumerateProvisioningSessions                        //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public EnumeratedProvisioningSession enumerateProvisioningSessions (EnumeratedProvisioningSession eps,
                                                                        boolean provisioning_state) throws SKSException
      {
        if (!eps.isValid ())
          {
            return getProvisioning (provisionings.values ().iterator (), provisioning_state);
          }
        Iterator<Provisioning> list = provisionings.values ().iterator ();
        while (list.hasNext ())
          {
            if (list.next ().provisioning_handle == eps.getProvisioningHandle ())
              {
                return getProvisioning (list, provisioning_state);
              }
          }
        return new EnumeratedProvisioningSession ();
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                      signProvisioningSessionData                           //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public byte[] signProvisioningSessionData (int provisioning_handle, byte[] data) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get provisioning session
        ///////////////////////////////////////////////////////////////////////////////////
        Provisioning provisioning = getOpenProvisioningSession (provisioning_handle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Sign (HMAC) data using a derived SessionKey
        ///////////////////////////////////////////////////////////////////////////////////
        return provisioning.getMacBuilder (KDF_EXTERNAL_SIGNATURE).addVerbatim (data).getResult ();
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                              getKeyHandle                                  //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public int getKeyHandle (int provisioning_handle, String id) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get provisioning session
        ///////////////////////////////////////////////////////////////////////////////////
        Provisioning provisioning = getOpenProvisioningSession (provisioning_handle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Look for key with virtual ID
        ///////////////////////////////////////////////////////////////////////////////////
        for (KeyEntry key_entry : keys.values ())
          {
            if (key_entry.owner == provisioning && key_entry.id.equals (id))
              {
                return key_entry.key_handle;
              }
          }
        provisioning.abort ("Key " + id + " missing");
        return 0;    // For the compiler only...
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                             pp_deleteKey                                   //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public void pp_deleteKey (int provisioning_handle,
                              int target_key_handle,
                              byte[] authorization,
                              byte[] mac) throws SKSException
      {
        addUnlockKeyOrDeleteKey (provisioning_handle, target_key_handle, authorization, mac, true);

      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                             pp_unlockKey                                   //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public void pp_unlockKey (int provisioning_handle,
                              int target_key_handle,
                              byte[] authorization,
                              byte[] mac) throws SKSException
      {
        addUnlockKeyOrDeleteKey (provisioning_handle, target_key_handle, authorization, mac, false);
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                          pp_cloneKeyProtection                             //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public void pp_cloneKeyProtection (int key_handle,
                                       int target_key_handle,
                                       byte[] authorization,
                                       byte[] mac) throws SKSException
      {
        addUpdateKeyOrCloneKeyProtection (key_handle, target_key_handle, authorization, mac, false);
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                               pp_updateKey                                 //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public void pp_updateKey (int key_handle,
                              int target_key_handle,
                              byte[] authorization,
                              byte[] mac) throws SKSException
      {
        addUpdateKeyOrCloneKeyProtection (key_handle, target_key_handle, authorization, mac, true);
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                         abortProvisioningSession                           //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public void abortProvisioningSession (int provisioning_handle) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get provisioning session
        ///////////////////////////////////////////////////////////////////////////////////
        Provisioning provisioning = getOpenProvisioningSession (provisioning_handle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Wind it down
        ///////////////////////////////////////////////////////////////////////////////////
        deleteObject (keys, provisioning);
        deleteObject (pin_policies, provisioning);
        deleteObject (puk_policies, provisioning);
        provisionings.remove (provisioning_handle);
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                        closeProvisioningSession                            //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public byte[] closeProvisioningSession (int provisioning_handle, byte[] nonce, byte[] mac) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get provisioning session
        ///////////////////////////////////////////////////////////////////////////////////
        Provisioning provisioning = getOpenProvisioningSession (provisioning_handle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify incoming MAC
        ///////////////////////////////////////////////////////////////////////////////////
        MacBuilder verifier = provisioning.getMacBuilderForMethodCall (METHOD_CLOSE_PROVISIONING_SESSION);
        verifier.addString (provisioning.client_session_id);
        verifier.addString (provisioning.server_session_id);
        verifier.addString (provisioning.issuer_uri);
        verifier.addArray (nonce);
        provisioning.verifyMac (verifier, mac);

        ///////////////////////////////////////////////////////////////////////////////////
        // Generate the attestation in advance => checking SessionKeyLimit before "commit"
        ///////////////////////////////////////////////////////////////////////////////////
        MacBuilder close_attestation = provisioning.getMacBuilderForMethodCall (KDF_DEVICE_ATTESTATION);
        close_attestation.addArray (mac);
        close_attestation.addString (ALGORITHM_SESSION_KEY_ATTEST_1);
        byte[] attestation = close_attestation.getResult ();

        ///////////////////////////////////////////////////////////////////////////////////
        // Perform "sanity" checks on provisioned data
        ///////////////////////////////////////////////////////////////////////////////////
        for (String id : provisioning.names.keySet ())
          {
            if (!provisioning.names.get(id))
              {
                provisioning.abort ("Unreferenced object \"ID\" : " + id);
              }
          }
        for (KeyEntry key_entry : keys.values ())
          {
            if (key_entry.owner == provisioning)
              {
                ///////////////////////////////////////////////////////////////////////////////////
                // A key provisioned in this session
                ///////////////////////////////////////////////////////////////////////////////////
                if (key_entry.certificate_path == null)
                  {
                    provisioning.abort ("Missing \"setCertificatePath\" for key: " + key_entry.id);
                  }

                ///////////////////////////////////////////////////////////////////////////////////
                // Check that possible endorsed algorithms match key material
                ///////////////////////////////////////////////////////////////////////////////////
                for (String algorithm : key_entry.endorsed_algorithms)
                  {
                    Algorithm alg = getAlgorithm (algorithm);
                    if ((alg.mask & ALG_NONE) == 0)
                      {
                        ///////////////////////////////////////////////////////////////////////////////////
                        // A non-null endorsed algorithm found.  Symmetric or asymmetric key?
                        ///////////////////////////////////////////////////////////////////////////////////
                        if (((alg.mask & (ALG_SYM_ENC | ALG_HMAC)) == 0) ^ key_entry.isSymmetric ())
                          {
                            if (key_entry.isSymmetric ())
                              {
                                ///////////////////////////////////////////////////////////////////////////////////
                                // Symmetric. AES algorithms only operates on 128, 192, and 256 bit keys
                                ///////////////////////////////////////////////////////////////////////////////////
                                testAESKey (algorithm, key_entry.symmetric_key, key_entry.id, provisioning);
                                continue;
                              }
                            else
                              {
                                ///////////////////////////////////////////////////////////////////////////////////
                                // Asymmetric.  Check that algorithms match RSA or ECC
                                ///////////////////////////////////////////////////////////////////////////////////
                                if (((alg.mask & ALG_RSA_KEY) == 0) ^ key_entry.isRSA ())
                                  {
                                    continue;
                                  }
                              }
                          }
                        key_entry.owner.abort ((key_entry.isSymmetric () ? "Symmetric" : key_entry.isRSA () ? "RSA" : "ECC") + 
                                               " key " + key_entry.id + " does not match algorithm: " + algorithm);
                      }
                  }
              }
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Post provisioning 1: Check that all the target keys are still there...
        ///////////////////////////////////////////////////////////////////////////////////
        for (PostProvisioningObject post_op : provisioning.post_provisioning_objects)
          {
            provisioning.getTargetKey (post_op.target_key_entry.key_handle);
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Post provisioning 2: Perform operations
        ///////////////////////////////////////////////////////////////////////////////////
        for (PostProvisioningObject post_op : provisioning.post_provisioning_objects)
          {
            KeyEntry key_entry = post_op.target_key_entry;
            if (post_op.new_key == null)
              {
                if (post_op.upd_or_del)
                  {
                    ///////////////////////////////////////////////////////////////////////////////////
                    // pp_deleteKey
                    ///////////////////////////////////////////////////////////////////////////////////
                    localDeleteKey (key_entry);
                  }
                else
                  {
                    ///////////////////////////////////////////////////////////////////////////////////
                    // pp_unlockKey.  Performed before pp_updateKey and pp_cloneKeyProtection 
                    ///////////////////////////////////////////////////////////////////////////////////
                    key_entry.setErrorCounter ((short) 0);
                    if (key_entry.pin_policy.puk_policy != null)
                      {
                        key_entry.pin_policy.puk_policy.error_count = 0;
                      }
                  }
              }
            else
              {
                if (post_op.upd_or_del)
                  {
                    ///////////////////////////////////////////////////////////////////////////////////
                    // Store new key in the place of the old (keeping the handle intact after update)
                    ///////////////////////////////////////////////////////////////////////////////////
                    keys.put (key_entry.key_handle, post_op.new_key);

                    ///////////////////////////////////////////////////////////////////////////////////
                    // Remove space occupied by the new key and restore old key handle
                    ///////////////////////////////////////////////////////////////////////////////////
                    keys.remove (post_op.new_key.key_handle);
                    post_op.new_key.key_handle = key_entry.key_handle;
                  }

                ///////////////////////////////////////////////////////////////////////////////////
                // Inherit protection data from the old key but nothing else
                ///////////////////////////////////////////////////////////////////////////////////
                post_op.new_key.pin_policy = key_entry.pin_policy;
                post_op.new_key.pin_value = key_entry.pin_value;
                post_op.new_key.error_count = key_entry.error_count;
                post_op.new_key.device_pin_protection = key_entry.device_pin_protection;
              }
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Post provisioning 3: Take ownership of managed keys and their associates
        ///////////////////////////////////////////////////////////////////////////////////
        for (PostProvisioningObject post_op : provisioning.post_provisioning_objects)
          {
            Provisioning old_owner = post_op.target_key_entry.owner;
            if (old_owner == provisioning)
              {
                continue;
              }
            for (KeyEntry key_entry : keys.values ())
              {
                if (key_entry.owner == old_owner)
                  {
                    ///////////////////////////////////////////////////////////////////////////////////
                    // There was a key that required changed ownership
                    ///////////////////////////////////////////////////////////////////////////////////
                    key_entry.owner = provisioning;
                    if (key_entry.pin_policy != null)
                      {
                        ///////////////////////////////////////////////////////////////////////////////
                        // Which also had a PIN policy...
                        ///////////////////////////////////////////////////////////////////////////////
                        key_entry.pin_policy.owner = provisioning;
                        if (key_entry.pin_policy.puk_policy != null)
                          {
                            ///////////////////////////////////////////////////////////////////////////
                            // Which in turn had a PUK policy...
                            ///////////////////////////////////////////////////////////////////////////
                            key_entry.pin_policy.puk_policy.owner = provisioning;
                          }
                      }
                  }
              }
            provisionings.remove (old_owner.provisioning_handle);  // OK to perform also if already done
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // If there are no keys associated with the session we just delete it
        ///////////////////////////////////////////////////////////////////////////////////
        deleteEmptySession (provisioning);

        ///////////////////////////////////////////////////////////////////////////////////
        // We are done, close the show for this time
        ///////////////////////////////////////////////////////////////////////////////////
        provisioning.open = false;
        return attestation;
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                        createProvisioningSession                           //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public ProvisioningSession createProvisioningSession (String algorithm,
                                                          String server_session_id,
                                                          ECPublicKey server_ephemeral_key,
                                                          String issuer_uri,
                                                          PublicKey key_management_key, // May be null
                                                          int client_time,
                                                          int session_life_time,
                                                          short session_key_limit) throws SKSException
      {
        if (!algorithm.equals (ALGORITHM_SESSION_KEY_ATTEST_1))
          {
            abort ("Unknown \"Algorithm\" : " + algorithm);
          }
        if (issuer_uri.length () == 0 || issuer_uri.length () >  MAX_LENGTH_URI)
          {
            abort ("URI length error: " + issuer_uri.length ());
          }
        byte[] attestation = null;
        byte[] session_key = null;
        ECPublicKey client_ephemeral_key = null;
        String client_session_id = "C-" + Long.toHexString (new Date().getTime()) + Long.toHexString(new SecureRandom().nextLong());
        try
          {
            ///////////////////////////////////////////////////////////////////////////////////
            // Create client ephemeral key
            ///////////////////////////////////////////////////////////////////////////////////
            KeyPairGenerator generator = KeyPairGenerator.getInstance ("EC", "BC");
            ECGenParameterSpec eccgen = new ECGenParameterSpec ("secp256r1");
            generator.initialize (eccgen, new SecureRandom ());
            java.security.KeyPair kp = generator.generateKeyPair ();

            ///////////////////////////////////////////////////////////////////////////////////
            // Check that the server and client ECDH keys are compatible
            ///////////////////////////////////////////////////////////////////////////////////
            client_ephemeral_key = (ECPublicKey) kp.getPublic ();
            if (!client_ephemeral_key.getParams ().getCurve ().equals (server_ephemeral_key.getParams ().getCurve ()) ||
                (client_ephemeral_key.getParams ().getCofactor () != server_ephemeral_key.getParams ().getCofactor ()))
              {
                throw new GeneralSecurityException ("Non-matching ephemeral keys");
              }

            ///////////////////////////////////////////////////////////////////////////////////
            // Apply the SP800-56A ECC CDH primitive
            ///////////////////////////////////////////////////////////////////////////////////
            KeyAgreement key_agreement = KeyAgreement.getInstance ("ECDHC", "BC");
            key_agreement.init (kp.getPrivate ());
            key_agreement.doPhase (server_ephemeral_key, true);
            byte[] Z = key_agreement.generateSecret ();

            ///////////////////////////////////////////////////////////////////////////////////
            // Use a custom KDF
            ///////////////////////////////////////////////////////////////////////////////////
            MacBuilder kdf = new MacBuilder (Z);
            kdf.addString (client_session_id);
            kdf.addString (server_session_id);
            kdf.addString (issuer_uri);
            kdf.addArray (getDeviceCertificatePath ()[0].getEncoded ());
            session_key = kdf.getResult ();

            ///////////////////////////////////////////////////////////////////////////////////
            // SessionKey attested data
            ///////////////////////////////////////////////////////////////////////////////////
            MacBuilder ska = new MacBuilder (session_key);
            ska.addString (algorithm);
            ska.addArray (server_ephemeral_key.getEncoded ());
            ska.addArray (client_ephemeral_key.getEncoded ());
            ska.addArray (key_management_key == null ? new byte[0] : key_management_key.getEncoded ());
            ska.addInt (client_time);
            ska.addInt (session_life_time);
            ska.addShort (session_key_limit);
            byte[] session_key_attest = ska.getResult ();

            ///////////////////////////////////////////////////////////////////////////////////
            // Sign attestation
            ///////////////////////////////////////////////////////////////////////////////////
            Signature signer = Signature.getInstance ("SHA256withRSA", "BC");
            signer.initSign (getAttestationKey ());
            signer.update (session_key_attest);
            attestation = signer.sign ();
          }
        catch (Exception e)
          {
            throw new SKSException (e);
          }
        Provisioning p = new Provisioning ();
        p.server_session_id = server_session_id;
        p.client_session_id = client_session_id;
        p.issuer_uri = issuer_uri;
        p.session_key = session_key;
        p.key_management_key = key_management_key;
        p.client_time = client_time;
        p.session_life_time = session_life_time;
        p.session_key_limit = session_key_limit;
        return new ProvisioningSession (p.provisioning_handle,
                                        client_session_id,
                                        attestation,
                                        client_ephemeral_key);
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                              addExtension                                  //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public void addExtension (int key_handle,
                              String type,
                              byte sub_type,
                              byte[] qualifier,
                              byte[] extension_data,
                              byte[] mac) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key and associated provisioning session
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry key_entry = getOpenKey (key_handle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Check for duplicates and length errors
        ///////////////////////////////////////////////////////////////////////////////////
        if (type.length () == 0 || type.length () >  MAX_LENGTH_URI)
          {
            key_entry.owner.abort ("URI length error: " + type.length ());
          }
        if (key_entry.extensions.get (type) != null)
          {
            key_entry.owner.abort ("Duplicate \"Type\" : " + type);
          }
        if (extension_data.length > (sub_type == SUB_TYPE_ENCRYPTED_EXTENSION ? 
                                      MAX_LENGTH_EXTENSION_DATA + AES_CBC_PKCS5_PADDING : MAX_LENGTH_EXTENSION_DATA))
          {
            key_entry.owner.abort ("Extension data exceeds " + MAX_LENGTH_EXTENSION_DATA + " bytes");
          }
        if (((sub_type == SUB_TYPE_LOGOTYPE) ^ (qualifier.length != 0)) || qualifier.length > MAX_LENGTH_QUALIFIER)
          {
            key_entry.owner.abort ("\"Qualifier\" length error");
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Property bags are checked for not being empty or incorrectly formatted
        ///////////////////////////////////////////////////////////////////////////////////
        if (sub_type == SUB_TYPE_PROPERTY_BAG)
          {
            int i = 0;
            do
              {
                if (i > extension_data.length - 5 || getShort (extension_data, i) == 0 ||
                    (i += getShort (extension_data, i) + 2) >  extension_data.length - 3 ||
                    ((extension_data[i++] & 0xFE) != 0) ||
                    (i += getShort (extension_data, i) + 2) > extension_data.length)
                  {
                    key_entry.owner.abort ("\"PropertyBag\" format error: " + type);
                  }
              }
            while (i != extension_data.length);
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify incoming MAC
        ///////////////////////////////////////////////////////////////////////////////////
        MacBuilder verifier = key_entry.getEECertMacBuilder (METHOD_ADD_EXTENSION);
        verifier.addString (type);
        verifier.addByte (sub_type);
        verifier.addArray (qualifier);
        verifier.addBlob (extension_data);
        key_entry.owner.verifyMac (verifier, mac);

        ///////////////////////////////////////////////////////////////////////////////////
        // Succeeded, create object
        ///////////////////////////////////////////////////////////////////////////////////
        ExtObject extension = new ExtObject ();
        extension.sub_type = sub_type;
        extension.qualifier = qualifier;
        extension.extension_data = (sub_type == SUB_TYPE_ENCRYPTED_EXTENSION) ?
                                     key_entry.owner.decrypt (extension_data) : extension_data;
        key_entry.extensions.put (type, extension);
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                           restorePrivateKey                                //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public void restorePrivateKey (int key_handle, byte[] private_key, byte[] mac) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key and associated provisioning session
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry key_entry = getOpenKey (key_handle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Check for key length errors
        ///////////////////////////////////////////////////////////////////////////////////
        if (private_key.length > (MAX_LENGTH_CRYPTO_DATA + AES_CBC_PKCS5_PADDING))
          {
            key_entry.owner.abort ("Private key: " + key_entry.id + " exceeds " + MAX_LENGTH_SYMMETRIC_KEY + " bytes");
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify incoming MAC
        ///////////////////////////////////////////////////////////////////////////////////
        MacBuilder verifier = key_entry.getEECertMacBuilder (METHOD_RESTORE_PRIVATE_KEY);
        verifier.addArray (private_key);
        key_entry.owner.verifyMac (verifier, mac);

        ///////////////////////////////////////////////////////////////////////////////////
        // Decrypt and store private key.  Note: this SKS accepts multiple restores...
        ///////////////////////////////////////////////////////////////////////////////////
        try
          {
            PKCS8EncodedKeySpec key_spec = new PKCS8EncodedKeySpec (key_entry.owner.decrypt (private_key));
            key_entry.private_key = KeyFactory.getInstance (key_entry.isRSA () ? "RSA" : "EC", "BC").generatePrivate (key_spec);
            key_entry.private_key_backup = true;
          }
        catch (GeneralSecurityException e)
          {
            key_entry.owner.abort (e.getMessage (), SKSException.ERROR_CRYPTO);
          }
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                            setSymmetricKey                                 //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public void setSymmetricKey (int key_handle,
                                 byte[] symmetric_key,
                                 byte[] mac) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key and associated provisioning session
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry key_entry = getOpenKey (key_handle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Check for various input errors
        ///////////////////////////////////////////////////////////////////////////////////
        if (symmetric_key.length > (MAX_LENGTH_SYMMETRIC_KEY + AES_CBC_PKCS5_PADDING))
          {
            key_entry.owner.abort ("Symmetric key: " + key_entry.id + " exceeds " + MAX_LENGTH_SYMMETRIC_KEY + " bytes");
          }
        if (key_entry.symmetric_key != null)
          {
            key_entry.owner.abort ("Multiple calls to \"setSymmetricKey\" for: " + key_entry.id);
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify incoming MAC
        ///////////////////////////////////////////////////////////////////////////////////
        MacBuilder verifier = key_entry.getEECertMacBuilder (METHOD_SET_SYMMETRIC_KEY);
        verifier.addArray (symmetric_key);
        key_entry.owner.verifyMac (verifier, mac);

        ///////////////////////////////////////////////////////////////////////////////////
        // Decrypt and store symmetric key
        ///////////////////////////////////////////////////////////////////////////////////
        key_entry.symmetric_key = key_entry.owner.decrypt (symmetric_key);
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                           setCertificatePath                               //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public void setCertificatePath (int key_handle,
                                    X509Certificate[] certificate_path,
                                    byte[] mac) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key and associated provisioning session
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry key_entry = getOpenKey (key_handle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify incoming MAC
        ///////////////////////////////////////////////////////////////////////////////////
        MacBuilder verifier = key_entry.owner.getMacBuilderForMethodCall (METHOD_SET_CERTIFICATE_PATH);
        try
          {
            verifier.addArray (key_entry.public_key.getEncoded ());
            verifier.addString (key_entry.id);
            for (X509Certificate certificate : certificate_path)
              {
                byte[] der = certificate.getEncoded ();
                if (der.length > MAX_LENGTH_CRYPTO_DATA)
                  {
                    key_entry.owner.abort ("Certificate for: " + key_entry.id + " exceeds " + MAX_LENGTH_CRYPTO_DATA + " bytes");
                  }
                verifier.addArray (der);
              }
          }
        catch (GeneralSecurityException e)
          {
            key_entry.owner.abort (e.getMessage (), SKSException.ERROR_INTERNAL);
          }
        key_entry.owner.verifyMac (verifier, mac);

        ///////////////////////////////////////////////////////////////////////////////////
        // Check key material for SKS compliance
        ///////////////////////////////////////////////////////////////////////////////////
        PublicKey public_key = certificate_path[0].getPublicKey ();
        if (public_key instanceof RSAPublicKey)
          {
            byte[] modulus = ((RSAPublicKey) public_key).getModulus ().toByteArray ();
            int rsa_key_size = (modulus[0] == 0 ? modulus.length - 1 : modulus.length) * 8;
            for (int size : RSA_KEY_SIZES)
              {
                if (size == rsa_key_size)
                  {
                    modulus = null;
                    break;
                  }
              }
            if (modulus != null)
              {
                key_entry.owner.abort ("Unsupported RSA key size " + rsa_key_size + " for: " + key_entry.id);
              }
          }
        else
          {
            byte[] asn1 = ((ECPublicKey) public_key).getEncoded ();
            //TODO ECC
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Store certificate path
        ///////////////////////////////////////////////////////////////////////////////////
        if (key_entry.certificate_path != null)
          {
            key_entry.owner.abort ("Multiple calls to \"setCertificatePath\" for: " + key_entry.id);
          }
        key_entry.certificate_path = certificate_path.clone ();
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                              createKeyEntry                                //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public KeyData createKeyEntry (int provisioning_handle,
                                   String id,
                                   String algorithm,
                                   byte[] server_seed,
                                   boolean device_pin_protection,
                                   int pin_policy_handle,
                                   byte[] pin_value,
                                   byte biometric_protection,
                                   boolean private_key_backup,
                                   byte export_protection,
                                   byte delete_protection,
                                   boolean enable_pin_caching,
                                   byte app_usage,
                                   String friendly_name,
                                   byte[] key_specifier,
                                   String[] endorsed_algorithms,
                                   byte[] mac) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get provisioning session
        ///////////////////////////////////////////////////////////////////////////////////
        Provisioning provisioning = getOpenProvisioningSession (provisioning_handle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Validate input as much as possible
        ///////////////////////////////////////////////////////////////////////////////////
        if (!algorithm.equals (ALGORITHM_KEY_ATTEST_1))
          {
            provisioning.abort ("Unsupported \"Algorithm\" : " + algorithm, SKSException.ERROR_ALGORITHM);
          }
        if (server_seed.length != 32)
          {
            provisioning.abort ("\"ServerSeed\" length error: " + server_seed.length);
          }
        provisioning.rangeTest (export_protection, EXPORT_DELETE_PROTECTION_NONE, EXPORT_DELETE_PROTECTION_NOT_ALLOWED, "ExportProtection");
        provisioning.rangeTest (delete_protection, EXPORT_DELETE_PROTECTION_NONE, EXPORT_DELETE_PROTECTION_NOT_ALLOWED, "DeleteProtection");
        provisioning.rangeTest (app_usage, APP_USAGE_SIGNATURE, APP_USAGE_UNIVERSAL, "AppUsage");
        provisioning.rangeTest (biometric_protection, BIOMETRIC_PROTECTION_NONE, BIOMETRIC_PROTECTION_EXCLUSIVE, "BiometricProtection");

        ///////////////////////////////////////////////////////////////////////////////////
        // Get proper PIN policy ID
        ///////////////////////////////////////////////////////////////////////////////////
        PINPolicy pin_policy = null;
        boolean decrypt_pin = false;
        String pin_policy_id = CRYPTO_STRING_NOT_AVAILABLE;
        boolean pin_protection = true;
        if (device_pin_protection)
          {
            pin_policy_id = CRYPTO_STRING_DEVICE_PIN;
            if (pin_policy_handle != 0)
              {
                provisioning.abort ("Device PIN mixed with PIN policy ojbect");
              }
          }
        else if (pin_policy_handle != 0)
          {
            pin_policy = pin_policies.get (pin_policy_handle);
            if (pin_policy == null || pin_policy.owner != provisioning)
              {
                provisioning.abort ("Referenced PIN policy object not found");
              }
            pin_policy_id = pin_policy.id;
            provisioning.names.put (pin_policy_id, true); // Referenced
            decrypt_pin = !pin_policy.user_defined;
          }
        else
          {
            pin_protection = false;
            if (enable_pin_caching)
              {
                provisioning.abort ("\"EnablePINCaching\" without PIN");
              }
          }
        if (biometric_protection != BIOMETRIC_PROTECTION_NONE &&
            ((biometric_protection != BIOMETRIC_PROTECTION_EXCLUSIVE) ^ pin_protection))
          {
            provisioning.abort ("Invalid \"BiometricProtection\" and PIN combination" + pin_protection + biometric_protection);
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify incoming MAC
        ///////////////////////////////////////////////////////////////////////////////////
        MacBuilder verifier = provisioning.getMacBuilderForMethodCall (METHOD_CREATE_KEY_ENTRY);
        verifier.addString (id);
        verifier.addString (algorithm);
        verifier.addArray (server_seed);
        verifier.addString (pin_policy_id);
        if (decrypt_pin)
          {
            verifier.addArray (pin_value);
            pin_value = provisioning.decrypt (pin_value);
          }
        else
          {
            if (pin_value != null)
              {
                pin_value = pin_value.clone ();
              }
            verifier.addString (CRYPTO_STRING_NOT_AVAILABLE);
          }
        verifier.addByte (biometric_protection);
        verifier.addBool (private_key_backup);
        verifier.addByte (export_protection);
        verifier.addByte (delete_protection);
        verifier.addBool (enable_pin_caching);
        verifier.addByte (app_usage);
        verifier.addString (friendly_name);
        verifier.addVerbatim (key_specifier);  // Already properly set w.r.t. SKS data types
        LinkedHashSet<String> temp_endorsed = new LinkedHashSet<String> ();
        for (String endorsed_algorithm : endorsed_algorithms)
          {
            ///////////////////////////////////////////////////////////////////////////////////
            // Check that the algorithms are known
            ///////////////////////////////////////////////////////////////////////////////////
            if (!temp_endorsed.add (endorsed_algorithm))
              {
                provisioning.abort ("Duplicate algorithm: " + endorsed_algorithm);
              }
            Algorithm alg = algorithms.get (endorsed_algorithm);
            if (alg == null)
              {
                provisioning.abort ("Unsupported algorithm: " + endorsed_algorithm);
              }
            if ((alg.mask & ALG_NONE) == 0 && endorsed_algorithms.length > 1)
              {
                provisioning.abort ("Algorithm must be alone: " + endorsed_algorithm);
              }
            verifier.addString (endorsed_algorithm);
          }
        provisioning.verifyMac (verifier, mac);

        ///////////////////////////////////////////////////////////////////////////////////
        // Perform a gazillion tests on PINs if applicable
        ///////////////////////////////////////////////////////////////////////////////////
        if (pin_policy == null)
          {
            ///////////////////////////////////////////////////////////////////////////////////
            // PIN value requires a defined PIN policy object
            ///////////////////////////////////////////////////////////////////////////////////
            if (pin_value != null)
              {
                provisioning.abort ("\"PINValue\" expected to be empty");
              }

            ///////////////////////////////////////////////////////////////////////////////////
            // Certain protection attributes require PIN objects
            ///////////////////////////////////////////////////////////////////////////////////
            verifyExportDeleteProtection (delete_protection, EXPORT_DELETE_PROTECTION_PIN, provisioning);
            verifyExportDeleteProtection (export_protection, EXPORT_DELETE_PROTECTION_PIN, provisioning);
          }
        else
          {
            ///////////////////////////////////////////////////////////////////////////////////
            // Certain protection attributes require PUK objects
            ///////////////////////////////////////////////////////////////////////////////////
            if (pin_policy.puk_policy == null)
              {
                verifyExportDeleteProtection (delete_protection, EXPORT_DELETE_PROTECTION_PUK, provisioning);
                verifyExportDeleteProtection (export_protection, EXPORT_DELETE_PROTECTION_PUK, provisioning);
              }

            ///////////////////////////////////////////////////////////////////////////////////
            // Testing the actual PIN value
            ///////////////////////////////////////////////////////////////////////////////////
            verifyPINPolicyCompliance (false, pin_value, pin_policy, app_usage, provisioning);
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Decode key algorithm specifier
        ///////////////////////////////////////////////////////////////////////////////////
        AlgorithmParameterSpec alg_par_spec = null;
        if (key_specifier.length == 7 && key_specifier[0] == KEY_ALGORITHM_TYPE_RSA)
          {
            int size = getShort (key_specifier, 1);
            boolean found = false;
            for (short rsa_key_size : RSA_KEY_SIZES)
              {
                if (size == rsa_key_size)
                  {
                    found = true;
                    break;
                  }
              }
            if (!found)
              {
                provisioning.abort ("RSA size unsupported: " + size);
              }
            int exponent = (getShort (key_specifier, 3) << 16) + getShort (key_specifier, 5);
            alg_par_spec = new RSAKeyGenParameterSpec (size,
                                                       exponent == 0 ? RSAKeyGenParameterSpec.F4 : BigInteger.valueOf (exponent));
          }
        else
          {
            if (key_specifier.length < 10 || key_specifier[0] != KEY_ALGORITHM_TYPE_ECC ||
                getShort (key_specifier, 1) != (key_specifier.length - 3))
              {
                provisioning.abort ("Incorrect \"KeyAlgorithm\" format");
              }
            StringBuffer ec_uri = new StringBuffer ();
            for (int i = 3; i < key_specifier.length; i++)
              {
                ec_uri.append ((char) key_specifier[i]);
              }
            Algorithm alg = algorithms.get (ec_uri.toString ());
            if (alg == null || (alg.mask & ALG_ECC_CRV) == 0)
              {
                provisioning.abort ("Unsupported eliptic curve: " + ec_uri);
              }
            alg_par_spec = new ECGenParameterSpec (alg.jce_name);
          }

        try
          {
            ///////////////////////////////////////////////////////////////////////////////////
            // At last, generate the desired key-pair
            ///////////////////////////////////////////////////////////////////////////////////
            SecureRandom secure_random = new SecureRandom (server_seed);
            KeyPairGenerator kpg = KeyPairGenerator.getInstance (alg_par_spec instanceof RSAKeyGenParameterSpec ? "RSA" : "EC", "BC");
            kpg.initialize (alg_par_spec, secure_random);
            java.security.KeyPair key_pair = kpg.generateKeyPair ();
            PublicKey public_key = key_pair.getPublic ();
            PrivateKey private_key = key_pair.getPrivate ();

            ///////////////////////////////////////////////////////////////////////////////////
            // If private key backup was requested, wrap a copy of the private key
            ///////////////////////////////////////////////////////////////////////////////////
            byte[] encrypted_private_key = private_key_backup ? provisioning.encrypt (private_key.getEncoded ()) : null;

            ///////////////////////////////////////////////////////////////////////////////////
            // Create key attestation data
            ///////////////////////////////////////////////////////////////////////////////////
            MacBuilder attestation = provisioning.getMacBuilderForMethodCall (KDF_DEVICE_ATTESTATION);
            attestation.addString (id);
            attestation.addArray (public_key.getEncoded ());
            if (private_key_backup)
              {
                attestation.addArray (encrypted_private_key);
              }

            ///////////////////////////////////////////////////////////////////////////////////
            // Finally, create a key entry
            ///////////////////////////////////////////////////////////////////////////////////
            KeyEntry key_entry = new KeyEntry (provisioning, id);
            provisioning.names.put (id, true); // Referenced (for "closeProvisioningSession")
            key_entry.pin_policy = pin_policy;
            key_entry.friendly_name = friendly_name;
            key_entry.pin_value = pin_value;
            key_entry.public_key = public_key;
            key_entry.private_key = private_key;
            key_entry.app_usage = app_usage;
            key_entry.device_pin_protection = device_pin_protection;
            key_entry.enable_pin_caching = enable_pin_caching;
            key_entry.biometric_protection = biometric_protection;
            key_entry.export_protection = export_protection;
            key_entry.delete_protection = delete_protection;
            key_entry.endorsed_algorithms = temp_endorsed;
            key_entry.private_key_backup = private_key_backup;
            return new KeyData (key_entry.key_handle,
                                public_key,
                                attestation.getResult (),
                                encrypted_private_key);
          }
        catch (GeneralSecurityException e)
          {
            provisioning.abort (e.getMessage (), SKSException.ERROR_INTERNAL);
          }
        return null;    // For the compiler only...
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                            createPINPolicy                                 //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public int createPINPolicy (int provisioning_handle,
                                String id,
                                int puk_policy_handle,
                                boolean user_defined,
                                boolean user_modifiable,
                                byte format,
                                short retry_limit,
                                byte grouping,
                                byte pattern_restrictions,
                                short min_length,
                                short max_length,
                                byte input_method,
                                byte[] mac) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get provisioning session
        ///////////////////////////////////////////////////////////////////////////////////
        Provisioning provisioning = getOpenProvisioningSession (provisioning_handle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Perform PIN "sanity" checks
        ///////////////////////////////////////////////////////////////////////////////////
        provisioning.rangeTest (grouping, PIN_GROUPING_NONE, PIN_GROUPING_UNIQUE, "Grouping");
        provisioning.rangeTest (input_method, INPUT_METHOD_PROGRAMMATIC, INPUT_METHOD_ANY, "InputMethod");
        provisioning.rangeTest (format, PIN_FORMAT_NUMERIC, PIN_FORMAT_BINARY, "Format");
        if ((pattern_restrictions & ~(PIN_PATTERN_TWO_IN_A_ROW | 
                                      PIN_PATTERN_THREE_IN_A_ROW |
                                      PIN_PATTERN_SEQUENCE |
                                      PIN_PATTERN_REPEATED |
                                      PIN_PATTERN_MISSING_GROUP)) != 0)
          {
            provisioning.abort ("Invalid \"PatternRestrictions\" value=" + pattern_restrictions);
          }
        String puk_policy_id = CRYPTO_STRING_NOT_AVAILABLE;
        PUKPolicy puk_policy = null;
        if (puk_policy_handle != 0)
          {
            puk_policy = puk_policies.get (puk_policy_handle);
            if (puk_policy == null || puk_policy.owner != provisioning)
              {
                provisioning.abort ("Referenced PUK policy object not found");
              }
            puk_policy_id = puk_policy.id;
            provisioning.names.put (puk_policy_id, true); // Referenced
          }
        if ((pattern_restrictions & PIN_PATTERN_MISSING_GROUP) != 0 &&
            format != PIN_FORMAT_ALPHANUMERIC && format != PIN_FORMAT_STRING)
          {
            provisioning.abort ("Incorrect \"Format\" for the \"missing-group\" PIN pattern policy");
          }
        if (min_length < 1 || max_length > MAX_LENGTH_PIN_PUK || max_length < min_length)
          {
            provisioning.abort ("PIN policy length error");
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify incoming MAC
        ///////////////////////////////////////////////////////////////////////////////////
        MacBuilder verifier = provisioning.getMacBuilderForMethodCall (METHOD_CREATE_PIN_POLICY);
        verifier.addString (id);
        verifier.addString (puk_policy_id);
        verifier.addBool (user_defined);
        verifier.addBool (user_modifiable);
        verifier.addByte (format);
        verifier.addShort (retry_limit);
        verifier.addByte (grouping);
        verifier.addByte (pattern_restrictions);
        verifier.addShort (min_length);
        verifier.addShort (max_length);
        verifier.addByte (input_method);
        provisioning.verifyMac (verifier, mac);

        ///////////////////////////////////////////////////////////////////////////////////
        // Success, create object
        ///////////////////////////////////////////////////////////////////////////////////
        PINPolicy pin_policy = new PINPolicy (provisioning, id);
        pin_policy.puk_policy = puk_policy;
        pin_policy.user_defined = user_defined;
        pin_policy.user_modifiable = user_modifiable;
        pin_policy.format = format;
        pin_policy.retry_limit = retry_limit;
        pin_policy.grouping = grouping;
        pin_policy.pattern_restrictions = pattern_restrictions;
        pin_policy.min_length = min_length;
        pin_policy.max_length = max_length;
        pin_policy.input_method = input_method;
        return pin_policy.pin_policy_handle;
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                            createPUKPolicy                                 //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public int createPUKPolicy (int provisioning_handle,
                                String id,
                                byte[] value,
                                byte format,
                                short retry_limit,
                                byte[] mac) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get provisioning session
        ///////////////////////////////////////////////////////////////////////////////////
        Provisioning provisioning = getOpenProvisioningSession (provisioning_handle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify incoming MAC
        ///////////////////////////////////////////////////////////////////////////////////
        MacBuilder verifier = provisioning.getMacBuilderForMethodCall (METHOD_CREATE_PUK_POLICY);
        verifier.addString (id);
        verifier.addArray (value);
        verifier.addByte (format);
        verifier.addShort (retry_limit);
        provisioning.verifyMac (verifier, mac);

        ///////////////////////////////////////////////////////////////////////////////////
        // Perform PUK "sanity" checks
        ///////////////////////////////////////////////////////////////////////////////////
        provisioning.rangeTest (format, PIN_FORMAT_NUMERIC, PIN_FORMAT_BINARY, "Format");
        byte[] puk_value = provisioning.decrypt (value);
        if (puk_value.length == 0 || puk_value.length > MAX_LENGTH_PIN_PUK)
          {
            provisioning.abort ("PUK length error");
          }
        for (int i = 0; i < puk_value.length; i++)
          {
            byte c = puk_value[i];
            if ((c < '0' || c > '9') && (format == PIN_FORMAT_NUMERIC ||
                                        ((c < 'A' || c > 'Z') && format == PIN_FORMAT_ALPHANUMERIC)))
              {
                provisioning.abort ("PUK syntax error");
              }
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Success, create object
        ///////////////////////////////////////////////////////////////////////////////////
        PUKPolicy puk_policy = new PUKPolicy (provisioning, id);
        puk_policy.puk_value = puk_value;
        puk_policy.format = format;
        puk_policy.retry_limit = retry_limit;
        return puk_policy.puk_policy_handle;
      }
  }
