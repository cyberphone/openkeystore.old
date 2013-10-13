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
package org.webpki.sks.test;

import java.io.IOException;
import java.io.Serializable;

import java.math.BigInteger;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;

import java.security.cert.X509Certificate;

import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.EllipticCurve;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;

import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Vector;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

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
 *  that should work identical when performed on a "real" SKS token.
 *
 *  Compared to the SKS specification, the Reference Implementation uses a slightly
 *  more java-centric way of passing parameters, including "null" arguments, but the
 *  content is supposed to be identical.
 *  
 *  Note that persistence is not supported by the Reference Implementation.
 *
 *  Author: Anders Rundgren
 */
public class SKSReferenceImplementation implements SKSError, SecureKeyStore, Serializable
  {
    private static final long serialVersionUID = 1L;

    /////////////////////////////////////////////////////////////////////////////////////////////
    // SKS version and configuration data
    /////////////////////////////////////////////////////////////////////////////////////////////
    static final String SKS_VENDOR_NAME                    = "WebPKI.org";
    static final String SKS_VENDOR_DESCRIPTION             = "SKS Reference - Java Emulator Edition";
    static final String SKS_UPDATE_URL                     = null;  // Change here to test or disable
    static final boolean SKS_DEVICE_PIN_SUPPORT            = true;  // Change here to test or disable
    static final boolean SKS_BIOMETRIC_SUPPORT             = true;  // Change here to test or disable
    static final boolean SKS_RSA_EXPONENT_SUPPORT          = true;  // Change here to test or disable

    static final char[] MODIFIED_BASE64 = {'A','B','C','D','E','F','G','H',
                                           'I','J','K','L','M','N','O','P',
                                           'Q','R','S','T','U','V','W','X',
                                           'Y','Z','a','b','c','d','e','f',
                                           'g','h','i','j','k','l','m','n',
                                           'o','p','q','r','s','t','u','v',
                                           'w','x','y','z','0','1','2','3',
                                           '4','5','6','7','8','9','-','_'};

    int next_key_handle = 1;
    LinkedHashMap<Integer,KeyEntry> keys = new LinkedHashMap<Integer,KeyEntry> ();

    int next_prov_handle = 1;
    LinkedHashMap<Integer,Provisioning> provisionings = new LinkedHashMap<Integer,Provisioning> ();

    int next_pin_handle = 1;
    LinkedHashMap<Integer,PINPolicy> pin_policies = new LinkedHashMap<Integer,PINPolicy> ();

    int next_puk_handle = 1;
    LinkedHashMap<Integer,PUKPolicy> puk_policies = new LinkedHashMap<Integer,PUKPolicy> ();


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
            checkIDSyntax (id, "ID", owner);
            owner.names.put (id, false);
            this.owner = owner;
            this.id = id;
          }
      }


    static void checkIDSyntax (String identifier, String symbolic_name, SKSError sks_error) throws SKSException
      {
        boolean flag = false;
        if (identifier.length () == 0 || identifier.length () > MAX_LENGTH_ID_TYPE)
          {
            flag = true;
          }
        else for (char c : identifier.toCharArray ())
          {
            /////////////////////////////////////////////////
            // The restricted ID
            /////////////////////////////////////////////////
            if (c < '!' || c > '~')
              {
                flag = true;
                break;
              }
          }
        if (flag)
          {
            sks_error.abort ("Malformed \"" + symbolic_name + "\" : " + identifier);
          }
      }


    class KeyEntry extends NameSpace implements Serializable
      {
        private static final long serialVersionUID = 1L;

        int key_handle;

        byte app_usage;

        PublicKey public_key;     // In this implementation overwritten by "setCertificatePath"
        PrivateKey private_key;   // Overwritten if "restorePivateKey" is called
        X509Certificate[] certificate_path;

        byte[] symmetric_key;     // Defined by "importSymmetricKey"

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
        
        byte key_backup;


        LinkedHashMap<String,ExtObject> extensions = new LinkedHashMap<String,ExtObject> ();

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

        void checkEECerificateAvailablity () throws SKSException
          {
            if (certificate_path == null)
              {
                owner.abort ("Missing \"setCertificatePath\" for: " + id);
              }
          }
        
        MacBuilder getEECertMacBuilder (byte[] method) throws SKSException
          {
            checkEECerificateAvailablity ();
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
            // "Sanity check"
            ///////////////////////////////////////////////////////////////////////////////////
            if (provisioning.privacy_enabled ^ owner.privacy_enabled)
              {
                provisioning.abort ("Inconsistent use of the \"PrivacyEnabled\" attribute for key #" + key_handle);
              }

            ///////////////////////////////////////////////////////////////////////////////////
            // Verify MAC
            ///////////////////////////////////////////////////////////////////////////////////
            verifier.addArray (authorization);
            provisioning.verifyMac (verifier, mac);
            
            ///////////////////////////////////////////////////////////////////////////////////
            // Verify KMK signature
            ///////////////////////////////////////////////////////////////////////////////////
            try
              {
                if (!owner.verifyKeyManagementKeyAuthorization (KMK_TARGET_KEY_REFERENCE,
                                                                provisioning.getMacBuilder (getDeviceID (provisioning.privacy_enabled)).addVerbatim (certificate_path[0].getEncoded ()).getResult (),
                                                                authorization))
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
            return public_key instanceof RSAPublicKey;
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

        void setAndVerifyServerBackupFlag () throws SKSException
          {
            if ((key_backup & KeyProtectionInfo.KEYBACKUP_IMPORTED) != 0)
              {
                owner.abort ("Mutiple key imports for: " + id);
              }
            key_backup |= KeyProtectionInfo.KEYBACKUP_IMPORTED;
          }

        BigInteger getPublicRSAExponentFromPrivateKey ()
          {
            return ((RSAPrivateCrtKey)private_key).getPublicExponent ();
          }
      }


    class ExtObject implements Serializable
      {
        private static final long serialVersionUID = 1L;

        String qualifier;
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
        LinkedHashMap<String,Boolean> names = new LinkedHashMap<String,Boolean> ();

        // Post provisioning management
        Vector<PostProvisioningObject> post_provisioning_objects = new Vector<PostProvisioningObject> ();

        boolean privacy_enabled;
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

        byte[] decrypt (byte[] data) throws SKSException
          {
            byte[] key = getMacBuilder (ZERO_LENGTH_ARRAY).addVerbatim (KDF_ENCRYPTION_KEY).getResult ();
            try
              {
                Cipher crypt = Cipher.getInstance ("AES/CBC/PKCS5Padding");
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

        void addPostProvisioningObject (KeyEntry target_key_entry, KeyEntry new_key, boolean upd_or_del) throws SKSException
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
                    if ((new_key == null && upd_or_del) || (post_op.new_key == null && post_op.upd_or_del)) // postDeleteKey
                      {
                        abort ("Delete wasn't exclusive for key #" + target_key_entry.key_handle);
                      }
                    else if (new_key == null && post_op.new_key == null) // postUnlockKey * 2
                      {
                        abort ("Multiple unlocks of key #" + target_key_entry.key_handle);
                      }
                    else if (upd_or_del && post_op.upd_or_del)
                      {
                        abort ("Multiple updates of key #" + target_key_entry.key_handle);
                      }
                  }
              }
            post_provisioning_objects.add (new PostProvisioningObject (target_key_entry, new_key, upd_or_del));
          }

        void rangeTest (byte value, byte low_limit, byte high_limit, String object_name) throws SKSException
          {
            if (value > high_limit || value < low_limit)
              {
                abort ("Invalid \"" + object_name + "\" value=" + value);
              }
          }

        void passphraseFormatTest (byte format) throws SKSException
          {
            rangeTest (format, PASSPHRASE_FORMAT_NUMERIC, PASSPHRASE_FORMAT_BINARY, "Format");
          }

        void retryLimitTest (short retry_limit, short min) throws SKSException
          {
            if (retry_limit < min || retry_limit > MAX_RETRY_LIMIT)
              {
                abort ("Invalid \"RetryLimit\" value=" + retry_limit);
              }
          }

        boolean verifyKeyManagementKeyAuthorization (byte[] kmk_kdf,
                                                     byte[] argument,
                                                     byte[] authorization) throws GeneralSecurityException
          {
            Signature kmk_verify = Signature.getInstance (key_management_key instanceof RSAPublicKey ? 
                                                                                     "SHA256WithRSA" : "SHA256WithECDSA");
            kmk_verify.initVerify (key_management_key);
            kmk_verify.update (kmk_kdf);
            kmk_verify.update (argument);
            return kmk_verify.verify (authorization);
          }
      }


    class MacBuilder implements Serializable
      {
        private static final long serialVersionUID = 1L;

        Mac mac;

        MacBuilder (byte[] key) throws GeneralSecurityException
          {
            mac = Mac.getInstance ("HmacSHA256");
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
            addArray (getBinary (string));
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


    class AttestationSignatureGenerator
      {
        Signature signer;
        
        AttestationSignatureGenerator () throws GeneralSecurityException
          {
            PrivateKey attester = getAttestationKey ();
            signer = Signature.getInstance (attester instanceof RSAPrivateKey ? "SHA256withRSA" : "SHA256withECDSA");
            signer.initSign (attester);
          }
  
        private byte[] short2bytes (int s)
          {
            return new byte[] { (byte) (s >>> 8), (byte) s };
          }
  
        private byte[] int2bytes (int i)
          {
            return new byte[] { (byte) (i >>> 24), (byte) (i >>> 16), (byte) (i >>> 8), (byte) i };
          }
  
        void addBlob (byte[] data) throws GeneralSecurityException
          {
            signer.update (int2bytes (data.length));
            signer.update (data);
          }
  
        void addArray (byte[] data) throws GeneralSecurityException
          {
            signer.update (short2bytes (data.length));
            signer.update (data);
          }
  
        void addString (String string) throws IOException, GeneralSecurityException
          {
            addArray (string.getBytes ("UTF-8"));
          }
  
        void addInt (int i) throws GeneralSecurityException
          {
            signer.update (int2bytes (i));
          }
  
        void addShort (int s) throws GeneralSecurityException
          {
            signer.update (short2bytes (s));
          }
  
        void addByte (byte b) throws GeneralSecurityException
          {
            signer.update (b);
          }
  
        void addBool (boolean flag) throws GeneralSecurityException
          {
            signer.update (flag ? (byte) 0x01 : (byte) 0x00);
          }
  
        byte[] getResult () throws GeneralSecurityException
          {
            return signer.sign ();
          }
      }

    class PostProvisioningObject implements Serializable
      {
        private static final long serialVersionUID = 1L;

        KeyEntry target_key_entry;
        KeyEntry new_key;      // null for postDeleteKey and postUnlockKey
        boolean upd_or_del;    // true for postUpdateKey and postDeleteKey

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

    static LinkedHashMap<String,Algorithm> supported_algorithms = new LinkedHashMap<String,Algorithm> ();

    static void addAlgorithm (String uri, String jce_name, int mask)
      {
        Algorithm alg = new Algorithm ();
        alg.mask = mask;
        alg.jce_name = jce_name;
        supported_algorithms.put (uri, alg);
      }

    static final int ALG_SYM_ENC  = 0x00000001;
    static final int ALG_IV_REQ   = 0x00000002;
    static final int ALG_IV_INT   = 0x00000004;
    static final int ALG_SYML_128 = 0x00000008;
    static final int ALG_SYML_192 = 0x00000010;
    static final int ALG_SYML_256 = 0x00000020;
    static final int ALG_HMAC     = 0x00000040;
    static final int ALG_ASYM_ENC = 0x00000080;
    static final int ALG_ASYM_SGN = 0x00000100;
    static final int ALG_RSA_KEY  = 0x00004000;
    static final int ALG_RSA_GMSK = 0x00003FFF;
    static final int ALG_RSA_EXP  = 0x00008000;
    static final int ALG_HASH_160 = 0x00140000;
    static final int ALG_HASH_256 = 0x00200000;
    static final int ALG_HASH_DIV = 0x00010000;
    static final int ALG_HASH_MSK = 0x0000007F;
    static final int ALG_NONE     = 0x00800000;
    static final int ALG_ASYM_KA  = 0x01000000;
    static final int ALG_AES_PAD  = 0x02000000;
    static final int ALG_EC_KEY   = 0x04000000;
    static final int ALG_KEY_GEN  = 0x08000000;
    static final int ALG_KEY_PARM = 0x10000000;

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

        addAlgorithm ("http://xmlns.webpki.org/sks/algorithm#aes.ecb.nopad",
                      "AES/ECB/NoPadding",
                      ALG_SYM_ENC | ALG_SYML_128 | ALG_SYML_192 | ALG_SYML_256 | ALG_AES_PAD);

        addAlgorithm ("http://xmlns.webpki.org/sks/algorithm#aes.cbc.pkcs5",
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
        addAlgorithm ("http://xmlns.webpki.org/sks/algorithm#rsa.pkcs1_5",
                      "RSA/ECB/PKCS1Padding",
                      ALG_ASYM_ENC | ALG_RSA_KEY);

        addAlgorithm ("http://xmlns.webpki.org/sks/algorithm#rsa.oaep.sha1.mgf1p",
                      "RSA/ECB/OAEPWithSHA1AndMGF1Padding",
                      ALG_ASYM_ENC | ALG_RSA_KEY);

        addAlgorithm ("http://xmlns.webpki.org/sks/algorithm#rsa.oaep.sha256.mgf1p",
                      "RSA/ECB/OAEPWithSHA256AndMGF1Padding",
                      ALG_ASYM_ENC | ALG_RSA_KEY);

        addAlgorithm ("http://xmlns.webpki.org/sks/algorithm#rsa.raw",
                      "RSA/ECB/NoPadding",
                      ALG_ASYM_ENC | ALG_RSA_KEY);

        //////////////////////////////////////////////////////////////////////////////////////
        //  Diffie-Hellman Key Agreement
        //////////////////////////////////////////////////////////////////////////////////////
        addAlgorithm ("http://xmlns.webpki.org/sks/algorithm#ecdh.raw",
                      "ECDH",
                      ALG_ASYM_KA | ALG_EC_KEY);
        
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
                      ALG_ASYM_SGN | ALG_EC_KEY | ALG_HASH_256);

        addAlgorithm ("http://xmlns.webpki.org/sks/algorithm#rsa.pkcs1.none",
                      "NONEwithRSA",
                      ALG_ASYM_SGN | ALG_RSA_KEY);

        addAlgorithm ("http://xmlns.webpki.org/sks/algorithm#ecdsa.none",
                      "NONEwithECDSA",
                      ALG_ASYM_SGN | ALG_EC_KEY);

        //////////////////////////////////////////////////////////////////////////////////////
        //  Asymmetric Key Generation
        //////////////////////////////////////////////////////////////////////////////////////
        addAlgorithm ("http://xmlns.webpki.org/sks/algorithm#ec.nist.p256",
                      "secp256r1",
                      ALG_EC_KEY | ALG_KEY_GEN);

        addAlgorithm ("http://xmlns.webpki.org/sks/algorithm#ec.brainpool.p256r1",
                      "brainpoolP256r1",
                      ALG_EC_KEY | ALG_KEY_GEN);
        
        for (short rsa_size : SKS_DEFAULT_RSA_SUPPORT)
          {
            addAlgorithm ("http://xmlns.webpki.org/sks/algorithm#rsa" + rsa_size,
                          null, ALG_RSA_KEY | ALG_KEY_GEN | rsa_size);
            if (SKS_RSA_EXPONENT_SUPPORT)
              {
                addAlgorithm ("http://xmlns.webpki.org/sks/algorithm#rsa" + rsa_size + ".exp",
                              null, ALG_KEY_PARM | ALG_RSA_KEY | ALG_KEY_GEN | rsa_size);
              }
          }

        //////////////////////////////////////////////////////////////////////////////////////
        //  Special Algorithms
        //////////////////////////////////////////////////////////////////////////////////////
        addAlgorithm (ALGORITHM_SESSION_ATTEST_1, null, 0);

        addAlgorithm (ALGORITHM_KEY_ATTEST_1, null, 0);

        addAlgorithm ("http://xmlns.webpki.org/sks/algorithm#none", null, ALG_NONE);

      }

    static final byte[] RSA_ENCRYPTION_OID = {0x06, 0x09, 0x2A, (byte)0x86, 0x48, (byte)0x86, (byte)0xF7, 0x0D, 0x01, 0x01, 0x01};

    /////////////////////////////////////////////////////////////////////////////////////////////
    // Supported EC algorithms
    /////////////////////////////////////////////////////////////////////////////////////////////
    static LinkedHashMap<String,EllipticCurve> supported_ec_key_algorithms = new LinkedHashMap<String,EllipticCurve> ();
    
    static void addECKeyAlgorithm (String jce_name, byte[] sample_public_key)
      {
        try
          {
            supported_ec_key_algorithms.put (jce_name,
                                             ((ECPublicKey) KeyFactory.getInstance ("EC").generatePublic (
                new X509EncodedKeySpec (sample_public_key))).getParams ().getCurve ());
          }
        catch (Exception e)
          {
            new RuntimeException (e);
          }
      }

    static
      {
        addECKeyAlgorithm ("secp256r1",
            new byte[]
               {(byte)0x30, (byte)0x59, (byte)0x30, (byte)0x13, (byte)0x06, (byte)0x07, (byte)0x2A, (byte)0x86,
                (byte)0x48, (byte)0xCE, (byte)0x3D, (byte)0x02, (byte)0x01, (byte)0x06, (byte)0x08, (byte)0x2A,
                (byte)0x86, (byte)0x48, (byte)0xCE, (byte)0x3D, (byte)0x03, (byte)0x01, (byte)0x07, (byte)0x03,
                (byte)0x42, (byte)0x00, (byte)0x04, (byte)0x8B, (byte)0xDF, (byte)0x5D, (byte)0xA2, (byte)0xBE,
                (byte)0x57, (byte)0x73, (byte)0xAC, (byte)0x78, (byte)0x86, (byte)0xD3, (byte)0xE5, (byte)0xE6,
                (byte)0xC4, (byte)0xA5, (byte)0x6C, (byte)0x32, (byte)0xE2, (byte)0x28, (byte)0xBE, (byte)0xA0,
                (byte)0x0F, (byte)0x8F, (byte)0xBF, (byte)0x29, (byte)0x1E, (byte)0xC6, (byte)0x67, (byte)0xB3,
                (byte)0x51, (byte)0x99, (byte)0xB7, (byte)0xAD, (byte)0x13, (byte)0x0C, (byte)0x5A, (byte)0x7C,
                (byte)0x66, (byte)0x4B, (byte)0x47, (byte)0xF6, (byte)0x1F, (byte)0x41, (byte)0xE9, (byte)0xB3,
                (byte)0xB2, (byte)0x40, (byte)0xC0, (byte)0x65, (byte)0xF8, (byte)0x8F, (byte)0x30, (byte)0x0A,
                (byte)0xCA, (byte)0x5F, (byte)0xB5, (byte)0x09, (byte)0x6E, (byte)0x95, (byte)0xCF, (byte)0x78,
                (byte)0x7C, (byte)0x0D, (byte)0xB2});

        addECKeyAlgorithm ("brainpoolP256r1",
            new byte[]
               {(byte)0x30, (byte)0x5A, (byte)0x30, (byte)0x14, (byte)0x06, (byte)0x07, (byte)0x2A, (byte)0x86,
                (byte)0x48, (byte)0xCE, (byte)0x3D, (byte)0x02, (byte)0x01, (byte)0x06, (byte)0x09, (byte)0x2B,
                (byte)0x24, (byte)0x03, (byte)0x03, (byte)0x02, (byte)0x08, (byte)0x01, (byte)0x01, (byte)0x07,
                (byte)0x03, (byte)0x42, (byte)0x00, (byte)0x04, (byte)0x26, (byte)0x3C, (byte)0x91, (byte)0x3F,
                (byte)0x6B, (byte)0x91, (byte)0x10, (byte)0x6F, (byte)0xE4, (byte)0xA2, (byte)0x2D, (byte)0xA4,
                (byte)0xBB, (byte)0xAB, (byte)0xCE, (byte)0x9E, (byte)0x41, (byte)0x01, (byte)0x0B, (byte)0xB0,
                (byte)0xC3, (byte)0x84, (byte)0xEF, (byte)0x35, (byte)0x0D, (byte)0x66, (byte)0xEE, (byte)0x0C,
                (byte)0xEC, (byte)0x60, (byte)0xB6, (byte)0xF5, (byte)0x54, (byte)0x54, (byte)0x27, (byte)0x2A,
                (byte)0x1D, (byte)0x07, (byte)0x61, (byte)0xB0, (byte)0xC3, (byte)0x01, (byte)0xE8, (byte)0xCB,
                (byte)0x52, (byte)0xF5, (byte)0x03, (byte)0xC1, (byte)0x0C, (byte)0x3F, (byte)0xF0, (byte)0x97,
                (byte)0xCD, (byte)0xC9, (byte)0x45, (byte)0xF3, (byte)0x21, (byte)0xC5, (byte)0xCF, (byte)0x41,
                (byte)0x17, (byte)0xF3, (byte)0x3A, (byte)0xB4});
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
    
    byte[] getDeviceID (boolean privacy_enabled) throws GeneralSecurityException
      {
        return privacy_enabled ? KDF_ANONYMOUS : getDeviceCertificatePath ()[0].getEncoded ();
      }

    PrivateKey getAttestationKey () throws GeneralSecurityException
      {
        return (PrivateKey) getAttestationKeyStore ().getKey (ATTESTATION_KEY_ALIAS, ATTESTATION_KEY_PASSWORD);        
      }

    Provisioning getProvisioningSession (int provisioning_handle) throws SKSException
      {
        Provisioning provisioning = provisionings.get (provisioning_handle);
        if (provisioning == null)
          {
            abort ("No such provisioning session: " + provisioning_handle, SKSException.ERROR_NO_SESSION);
          }
        return provisioning;
      }

    Provisioning getOpenProvisioningSession (int provisioning_handle) throws SKSException
      {
        Provisioning provisioning = getProvisioningSession (provisioning_handle);
        if (!provisioning.open)
          {
            abort ("Session not open: " +  provisioning_handle, SKSException.ERROR_NO_SESSION);
          }
        return provisioning;
      }

    Provisioning getClosedProvisioningSession (int provisioning_handle) throws SKSException
      {
        Provisioning provisioning = getProvisioningSession (provisioning_handle);
        if (provisioning.open)
          {
            abort ("Session is open: " +  provisioning_handle, SKSException.ERROR_NOT_ALLOWED);
          }
        return provisioning;
      }

    byte[] getBinary (String string) throws SKSException
      {
        try
          {
            return string.getBytes ("UTF-8");
          }
        catch (IOException e)
          {
            abort ("Interal UTF-8");
            return null;
          }
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
        return null;
      }

    void deleteObject (LinkedHashMap<Integer,?> objects, Provisioning provisioning)
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
                return new EnumeratedProvisioningSession (provisioning.provisioning_handle,
                                                          ALGORITHM_SESSION_ATTEST_1,
                                                          provisioning.privacy_enabled,
                                                          provisioning.key_management_key,
                                                          provisioning.client_time,
                                                          provisioning.session_life_time,
                                                          provisioning.server_session_id,
                                                          provisioning.client_session_id,
                                                          provisioning.issuer_uri);
              }
          }
        return null;
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

    String checkECKeyCompatibility (ECKey ec_key, SKSError sks_error, String key_id) throws SKSException
      {
        for (String jce_name : supported_ec_key_algorithms.keySet ())
          {
            if (ec_key.getParams ().getCurve ().equals (supported_ec_key_algorithms.get (jce_name)))
              {
                return jce_name;
              }
          }
        sks_error.abort ("Unsupported EC key algorithm for: " + key_id);
        return null;
      }

    void checkRSAKeyCompatibility (int rsa_key_size, BigInteger exponent, SKSError sks_error, String key_id) throws SKSException
      {
        if (!SKS_RSA_EXPONENT_SUPPORT && !exponent.equals (RSAKeyGenParameterSpec.F4))
          {
            sks_error.abort ("Unsupported RSA exponent value for: " + key_id);
          }
        boolean found = false;
        for (short key_size : SKS_DEFAULT_RSA_SUPPORT)
          {
            if (key_size == rsa_key_size)
              {
                found = true;
                break;
              }
          }
        if (!found)
          {
            sks_error.abort ("Unsupported RSA key size " + rsa_key_size + " for: " + key_id);
          }
      }

    int getRSAKeySize (RSAKey rsa_key)
      {
        byte[] modblob = rsa_key.getModulus ().toByteArray ();
        return (modblob[0] == 0 ? modblob.length - 1 : modblob.length) * 8;
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
        if ((pin_policy.format == PASSPHRASE_FORMAT_NUMERIC && (loweralpha || nonalphanum || upperalpha)) ||
            (pin_policy.format == PASSPHRASE_FORMAT_ALPHANUMERIC && (loweralpha || nonalphanum)))
          {
            sks_error.abort ("PIN syntax error");
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Check PIN patterns
        ///////////////////////////////////////////////////////////////////////////////////
        if ((pin_policy.pattern_restrictions & PIN_PATTERN_MISSING_GROUP) != 0)
          {
            if (!upperalpha || !number ||
                (pin_policy.format == PASSPHRASE_FORMAT_STRING && (!loweralpha || !nonalphanum)))
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
            abort ((key_entry.isRSA () ? "RSA" : "EC") + " key #" + key_entry.key_handle + " is incompatible with: " + input_algorithm, SKSException.ERROR_ALGORITHM);
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
        Algorithm alg = supported_algorithms.get (algorithm_uri);
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
            provisioning.abort ("Updated/cloned keys must not define PIN protection");
          }
        if (update)
          {
            if (target_key_entry.app_usage != new_key.app_usage)
              {
                provisioning.abort ("Updated keys must have the same \"AppUsage\" as the target key");
              }
          }
        else
          {
            ///////////////////////////////////////////////////////////////////////////////////
            // Cloned keys must share the PIN of its parent
            ///////////////////////////////////////////////////////////////////////////////////
            if (target_key_entry.pin_policy != null && target_key_entry.pin_policy.grouping != PIN_GROUPING_SHARED)
              {
                provisioning.abort ("A cloned key protection must have PIN grouping=\"shared\"");
              }
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify incoming MAC and target key data
        ///////////////////////////////////////////////////////////////////////////////////
        MacBuilder verifier = new_key.getEECertMacBuilder (update ? METHOD_POST_UPDATE_KEY : METHOD_POST_CLONE_KEY_PROTECTION);
        target_key_entry.validateTargetKeyReference (verifier, mac, authorization, provisioning);

        ///////////////////////////////////////////////////////////////////////////////////
        // Put the operation in the post-op buffer used by "closeProvisioningSession"
        ///////////////////////////////////////////////////////////////////////////////////
        provisioning.addPostProvisioningObject (target_key_entry, new_key, update);
      }

    void addUnlockKeyOrDeleteKey (int provisioning_handle,
                                  int target_key_handle,
                                  byte[] authorization,
                                  byte[] mac,
                                  boolean delete) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get provisioning session
        ///////////////////////////////////////////////////////////////////////////////////
        Provisioning provisioning = getOpenProvisioningSession (provisioning_handle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Get key to be deleted or unlocked
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry target_key_entry = provisioning.getTargetKey (target_key_handle);
        if (!delete && target_key_entry.pin_policy == null)
          {
            provisioning.abort ("Key #" + target_key_handle + " is not PIN protected");
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify incoming MAC and target key data
        ///////////////////////////////////////////////////////////////////////////////////
        MacBuilder verifier = provisioning.getMacBuilderForMethodCall (delete ? METHOD_POST_DELETE_KEY : METHOD_POST_UNLOCK_KEY);
        target_key_entry.validateTargetKeyReference (verifier, mac, authorization, provisioning);

        ///////////////////////////////////////////////////////////////////////////////////
        // Put the operation in the post-op buffer used by "closeProvisioningSession"
        ///////////////////////////////////////////////////////////////////////////////////
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
    public synchronized void unlockKey (int key_handle, byte[] authorization) throws SKSException
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
    public synchronized void changePIN (int key_handle, 
                                        byte[] authorization,
                                        byte[] new_pin) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key (which must belong to an already fully provisioned session)
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry key_entry = getStdKey (key_handle);
        
        ///////////////////////////////////////////////////////////////////////////////////
        // Verify old PIN
        ///////////////////////////////////////////////////////////////////////////////////
        key_entry.verifyPIN (authorization);

        ///////////////////////////////////////////////////////////////////////////////////
        // Test new PIN
        ///////////////////////////////////////////////////////////////////////////////////
        testUpdatablePIN (key_entry, new_pin);

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
    public synchronized void setPIN (int key_handle,
                                     byte[] authorization,
                                     byte[] new_pin) throws SKSException
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
        // Test new PIN
        ///////////////////////////////////////////////////////////////////////////////////
        testUpdatablePIN (key_entry, new_pin);

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
    public synchronized void deleteKey (int key_handle, byte[] authorization) throws SKSException
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
    public synchronized byte[] exportKey (int key_handle, byte[] authorization) throws SKSException
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
        // Mark as "copied" locally
        ///////////////////////////////////////////////////////////////////////////////////
        key_entry.key_backup |= KeyProtectionInfo.KEYBACKUP_EXPORTED;

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
    public synchronized void setProperty (int key_handle,
                                          String type,
                                          String name,
                                          String value) throws SKSException
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
        byte[] bin_name = getBinary (name);
        byte[] bin_value = getBinary (value);
        int i = 0;
        while (i < ext_obj.extension_data.length)
          {
            int nam_len = getShort (ext_obj.extension_data, i);
            i += 2;
            byte[] pname = Arrays.copyOfRange (ext_obj.extension_data, i, nam_len + i);
            i += nam_len;
            int val_len = getShort (ext_obj.extension_data, i + 1);
            if (Arrays.equals (bin_name, pname))
              {
                if (ext_obj.extension_data[i] != 0x01)
                  {
                    abort ("\"Property\" not writable: " + name, SKSException.ERROR_NOT_ALLOWED);
                  }
                ext_obj.extension_data = addArrays (addArrays (Arrays.copyOfRange (ext_obj.extension_data, 0, ++i),
                                                               addArrays (new byte[]{(byte)(bin_value.length >> 8),(byte)bin_value.length}, bin_value)),
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
    public synchronized Extension getExtension (int key_handle, String type) throws SKSException
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
    public synchronized byte[] asymmetricKeyDecrypt (int key_handle,
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
        // Verify PIN (in any)
        ///////////////////////////////////////////////////////////////////////////////////
        key_entry.verifyPIN (authorization);

        ///////////////////////////////////////////////////////////////////////////////////
        // Check that the encryption algorithm is known and applicable
        ///////////////////////////////////////////////////////////////////////////////////
        Algorithm alg = checkKeyAndAlgorithm (key_entry, algorithm, ALG_ASYM_ENC);
        if (parameters != null)  // Only support basic RSA yet...
          {
            abort ("\"Parameters\" for key #" + key_handle + " do not match algorithm");
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Finally, perform operation
        ///////////////////////////////////////////////////////////////////////////////////
        try
          {
            Cipher cipher = Cipher.getInstance (alg.jce_name);
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
    public synchronized byte[] signHashedData (int key_handle,
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
        // Verify PIN (in any)
        ///////////////////////////////////////////////////////////////////////////////////
        key_entry.verifyPIN (authorization);

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
        // Finally, perform operation
        ///////////////////////////////////////////////////////////////////////////////////
        try
          {
            if (key_entry.isRSA () && hash_len > 0)
              {
                data = addArrays (hash_len == 20 ? DIGEST_INFO_SHA1 : DIGEST_INFO_SHA256, data);
              }
            Signature signature = Signature.getInstance (alg.jce_name);
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
    public synchronized byte[] keyAgreement (int key_handle, 
                                             String algorithm,
                                             byte[] parameters,
                                             byte[] authorization,
                                             ECPublicKey public_key) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key (which must belong to an already fully provisioned session)
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry key_entry = getStdKey (key_handle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify PIN (in any)
        ///////////////////////////////////////////////////////////////////////////////////
        key_entry.verifyPIN (authorization);

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
        checkECKeyCompatibility (public_key, this, "\"PublicKey\"");

        ///////////////////////////////////////////////////////////////////////////////////
        // Finally, perform operation
        ///////////////////////////////////////////////////////////////////////////////////
        try
          {
            KeyAgreement key_agreement = KeyAgreement.getInstance (alg.jce_name);
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
    public synchronized byte[] symmetricKeyEncrypt (int key_handle,
                                                    String algorithm,
                                                    boolean mode,
                                                    byte[] parameters,
                                                    byte[] authorization,
                                                    byte[] data) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key (which must belong to an already fully provisioned session)
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry key_entry = getStdKey (key_handle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify PIN (in any)
        ///////////////////////////////////////////////////////////////////////////////////
        key_entry.verifyPIN (authorization);

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
            if (parameters != null)
              {
                abort ("\"Parameters\" does not apply to: " + algorithm);
              }
          }
        else if (parameters == null || parameters.length != 16)
          {
            abort ("\"Parameters\" must be 16 bytes for: " + algorithm);
          }
        if ((!mode || (alg.mask & ALG_AES_PAD) != 0) && data.length % 16 != 0)
          {
            abort ("Data must be a multiple of 16 bytes for: " + algorithm + (mode ? " encryption" : " decryption"));
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Finally, perform operation
        ///////////////////////////////////////////////////////////////////////////////////
        try
          {
            Cipher crypt = Cipher.getInstance (alg.jce_name);
            SecretKeySpec sk = new SecretKeySpec (key_entry.symmetric_key, "AES");
            int jce_mode = mode ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;
            if ((alg.mask & ALG_IV_INT) != 0)
              {
                parameters = new byte[16];
                if (mode)
                  {
                    new SecureRandom ().nextBytes (parameters);
                  }
                else
                  {
                    byte[] temp = new byte[data.length - 16];
                    System.arraycopy (data, 0, parameters, 0, 16);
                    System.arraycopy (data, 16, temp, 0, temp.length);
                    data = temp;
                  }
              }
            if (parameters == null)
              {
                crypt.init (jce_mode, sk);
              }
            else
              {
                crypt.init (jce_mode, sk, new IvParameterSpec (parameters));
              }
            data = crypt.doFinal (data);
            return (mode && (alg.mask & ALG_IV_INT) != 0) ? addArrays (parameters, data) : data;
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
    public synchronized byte[] performHMAC (int key_handle,
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
        // Verify PIN (in any)
        ///////////////////////////////////////////////////////////////////////////////////
        key_entry.verifyPIN (authorization);

        ///////////////////////////////////////////////////////////////////////////////////
        // Enforce the data limit
        ///////////////////////////////////////////////////////////////////////////////////
        key_entry.checkCryptoDataSize (data);

        ///////////////////////////////////////////////////////////////////////////////////
        // Check the key and then check that the algorithm is known and applicable
        ///////////////////////////////////////////////////////////////////////////////////
        Algorithm alg = checkKeyAndAlgorithm (key_entry, algorithm, ALG_HMAC);
        if (parameters != null)
          {
            abort ("\"Parameters\" does not apply to: " + algorithm);
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Finally, perform operation
        ///////////////////////////////////////////////////////////////////////////////////
        try
          {
            Mac mac = Mac.getInstance (alg.jce_name);
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
    public synchronized DeviceInfo getDeviceInfo () throws SKSException
      {
        try
          {
            return new DeviceInfo (SKS_API_LEVEL,
                                   (byte)(DeviceInfo.LOCATION_EMBEDDED | DeviceInfo.TYPE_SOFTWARE),
                                   SKS_UPDATE_URL,
                                   SKS_VENDOR_NAME,
                                   SKS_VENDOR_DESCRIPTION,
                                   getDeviceCertificatePath (),
                                   supported_algorithms.keySet ().toArray (new String[0]),
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
    //                             updateFirmware                                 //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public String updateFirmware (byte[] chunk) throws SKSException
      {
        throw new SKSException ("Updates are not supported", SKSException.ERROR_NOT_ALLOWED);
      }

    
    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                              enumerateKeys                                 //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized EnumeratedKey enumerateKeys (int key_handle) throws SKSException
      {
        if (key_handle == EnumeratedKey.INIT_ENUMERATION)
          {
            return getKey (keys.values ().iterator ());
          }
        Iterator<KeyEntry> list = keys.values ().iterator ();
        while (list.hasNext ())
          {
            if (list.next ().key_handle == key_handle)
              {
                return getKey (list);
              }
          }
        return null;
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                          getKeyProtectionInfo                              //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized KeyProtectionInfo getKeyProtectionInfo (int key_handle) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key (which must belong to an already fully provisioned session)
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry key_entry = getStdKey (key_handle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Find the protection data objects that are not stored in the key entry
        ///////////////////////////////////////////////////////////////////////////////////
        byte protection_status = KeyProtectionInfo.PROTSTAT_NO_PIN;
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
            protection_status = KeyProtectionInfo.PROTSTAT_DEVICE_PIN;
          }
        else if (key_entry.pin_policy != null)
          {
            protection_status = KeyProtectionInfo.PROTSTAT_PIN_PROTECTED;
            if (key_entry.error_count >= key_entry.pin_policy.retry_limit)
              {
                protection_status |= KeyProtectionInfo.PROTSTAT_PIN_BLOCKED;
              }
            if (key_entry.pin_policy.puk_policy != null)
              {
                puk_format = key_entry.pin_policy.puk_policy.format; 
                puk_retry_limit = key_entry.pin_policy.puk_policy.retry_limit;
                puk_error_count = key_entry.pin_policy.puk_policy.error_count;
                protection_status |= KeyProtectionInfo.PROTSTAT_PUK_PROTECTED;
                if (key_entry.pin_policy.puk_policy.error_count >= key_entry.pin_policy.puk_policy.retry_limit &&
                    key_entry.pin_policy.puk_policy.retry_limit > 0)
                  {
                    protection_status |= KeyProtectionInfo.PROTSTAT_PUK_BLOCKED;
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
                                      key_entry.enable_pin_caching,
                                      key_entry.biometric_protection,
                                      key_entry.export_protection,
                                      key_entry.delete_protection,
                                      key_entry.key_backup);
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                            getKeyAttributes                                //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized KeyAttributes getKeyAttributes (int key_handle) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key (which must belong to an already fully provisioned session)
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry key_entry = getStdKey (key_handle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Return core key entry metadata
        ///////////////////////////////////////////////////////////////////////////////////
        return new KeyAttributes ((short)(key_entry.isSymmetric () ? key_entry.symmetric_key.length : 0),
                                  key_entry.certificate_path,
                                  key_entry.app_usage,
                                  key_entry.friendly_name,
                                  key_entry.endorsed_algorithms.toArray (new String[0]),
                                  key_entry.extensions.keySet ().toArray (new String[0]));
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                           updateKeyManagementKey                           //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public void updateKeyManagementKey (int provisioning_handle,
                                        PublicKey key_management_key,
                                        byte[] authorization) throws SKSException
      {
        Provisioning provisioning = getClosedProvisioningSession (provisioning_handle);
        if (provisioning.key_management_key == null)
          {
            abort ("Session is not updatable: " +  provisioning_handle, SKSException.ERROR_NOT_ALLOWED);
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify KMK signature
        ///////////////////////////////////////////////////////////////////////////////////
        try
          {
            if (!provisioning.verifyKeyManagementKeyAuthorization (KMK_ROLL_OVER_AUTHORIZATION,
                                                                   key_management_key.getEncoded (),
                                                                   authorization))
              {
                abort ("\"Authorization\" signature did not verify for session: " + provisioning_handle);
              }

            ///////////////////////////////////////////////////////////////////////////////////
            // Success, update KeyManagementKey
            ///////////////////////////////////////////////////////////////////////////////////
            provisioning.key_management_key = key_management_key;
          }
        catch (GeneralSecurityException e)
          {
            abort (e.getMessage (), SKSException.ERROR_CRYPTO);
          }
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                       enumerateProvisioningSessions                        //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized EnumeratedProvisioningSession enumerateProvisioningSessions (int provisioning_handle,
                                                                                     boolean provisioning_state) throws SKSException
      {
        if (provisioning_handle == EnumeratedProvisioningSession.INIT_ENUMERATION)
          {
            return getProvisioning (provisionings.values ().iterator (), provisioning_state);
          }
        Iterator<Provisioning> list = provisionings.values ().iterator ();
        while (list.hasNext ())
          {
            if (list.next ().provisioning_handle == provisioning_handle)
              {
                return getProvisioning (list, provisioning_state);
              }
          }
        return null;
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                      signProvisioningSessionData                           //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized byte[] signProvisioningSessionData (int provisioning_handle, byte[] data) throws SKSException
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
    public synchronized int getKeyHandle (int provisioning_handle, String id) throws SKSException
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
    //                             postDeleteKey                                  //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized void postDeleteKey (int provisioning_handle,
                                            int target_key_handle,
                                            byte[] authorization,
                                            byte[] mac) throws SKSException
      {
        addUnlockKeyOrDeleteKey (provisioning_handle, target_key_handle, authorization, mac, true);
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                             postUnlockKey                                  //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized void postUnlockKey (int provisioning_handle,
                                            int target_key_handle,
                                            byte[] authorization,
                                            byte[] mac) throws SKSException
      {
        addUnlockKeyOrDeleteKey (provisioning_handle, target_key_handle, authorization, mac, false);
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                          postCloneKeyProtection                            //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized void postCloneKeyProtection (int key_handle,
                                                     int target_key_handle,
                                                     byte[] authorization,
                                                     byte[] mac) throws SKSException
      {
        addUpdateKeyOrCloneKeyProtection (key_handle, target_key_handle, authorization, mac, false);
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                              postUpdateKey                                 //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized void postUpdateKey (int key_handle,
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
    public synchronized void abortProvisioningSession (int provisioning_handle) throws SKSException
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
    public synchronized byte[] closeProvisioningSession (int provisioning_handle,
                                                         byte[] challenge,
                                                         byte[] mac) throws SKSException
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
        verifier.addArray (challenge);
        provisioning.verifyMac (verifier, mac);

        ///////////////////////////////////////////////////////////////////////////////////
        // Generate the attestation in advance => checking SessionKeyLimit before "commit"
        ///////////////////////////////////////////////////////////////////////////////////
        MacBuilder close_attestation = provisioning.getMacBuilderForMethodCall (KDF_DEVICE_ATTESTATION);
        close_attestation.addArray (challenge);
        close_attestation.addString (ALGORITHM_SESSION_ATTEST_1);
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
        provisioning.names.clear ();
        for (KeyEntry key_entry : keys.values ())
          {
            if (key_entry.owner == provisioning)
              {
                ///////////////////////////////////////////////////////////////////////////////////
                // A key provisioned in this session
                ///////////////////////////////////////////////////////////////////////////////////
                key_entry.checkEECerificateAvailablity ();

                ///////////////////////////////////////////////////////////////////////////////////
                // Check public versus private key match
                ///////////////////////////////////////////////////////////////////////////////////
                if (key_entry.isRSA () ^ key_entry.private_key instanceof RSAPrivateKey)
                  {
                    provisioning.abort ("RSA/EC mixup between public and private keys for: " + key_entry.id);
                  }
                if (key_entry.isRSA ())
                  {
                    if (!((RSAPublicKey)key_entry.public_key).getPublicExponent ().equals (key_entry.getPublicRSAExponentFromPrivateKey ()) ||
                        !((RSAPublicKey)key_entry.public_key).getModulus ().equals (((RSAPrivateKey)key_entry.private_key).getModulus ()))
                      {
                        provisioning.abort ("RSA mismatch between public and private keys for: " + key_entry.id);
                      }
                  }
                else
                  {
                    try
                      {
                        Signature ec_signer = Signature.getInstance ("SHA256withECDSA");
                        ec_signer.initSign (key_entry.private_key);
                        ec_signer.update (RSA_ENCRYPTION_OID);  // Any data could be used...
                        byte[] ec_sign_data = ec_signer.sign ();
                        Signature ec_verifier = Signature.getInstance ("SHA256withECDSA");
                        ec_verifier.initVerify (key_entry.public_key);
                        ec_verifier.update (RSA_ENCRYPTION_OID);
                        if (!ec_verifier.verify (ec_sign_data))
                          {
                            provisioning.abort ("EC mismatch between public and private keys for: " + key_entry.id);
                          }
                      }
                    catch (GeneralSecurityException e)
                      {
                        provisioning.abort (e.getMessage ());
                      }
                  }

                ///////////////////////////////////////////////////////////////////////////////////
                // Test that there are no collisions
                ///////////////////////////////////////////////////////////////////////////////////
                for (KeyEntry key_entry_temp : keys.values ())
                  {
                    if (key_entry_temp.key_handle != key_entry.key_handle && key_entry_temp.certificate_path != null &&
                        key_entry_temp.certificate_path[0].equals (key_entry.certificate_path[0]))
                      {
                        ///////////////////////////////////////////////////////////////////////////////////
                        // There was a conflict, ignore updates/deletes
                        ///////////////////////////////////////////////////////////////////////////////////
                        boolean collision = true;
                        for (PostProvisioningObject post_op : provisioning.post_provisioning_objects)
                          {
                            if (post_op.target_key_entry == key_entry_temp && post_op.upd_or_del)
                              {
                                collision = false;
                              }
                          }
                        if (collision)
                          {
                            provisioning.abort ("Duplicate certificate in \"setCertificatePath\" for: " + key_entry.id);
                          }
                      }
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
                                // Asymmetric.  Check that algorithms match RSA or EC
                                ///////////////////////////////////////////////////////////////////////////////////
                                if (((alg.mask & ALG_RSA_KEY) == 0) ^ key_entry.isRSA ())
                                  {
                                    continue;
                                  }
                              }
                          }
                        provisioning.abort ((key_entry.isSymmetric () ? "Symmetric" : key_entry.isRSA () ? "RSA" : "EC") + 
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
                    // postDeleteKey
                    ///////////////////////////////////////////////////////////////////////////////////
                    localDeleteKey (key_entry);
                  }
                else
                  {
                    ///////////////////////////////////////////////////////////////////////////////////
                    // postUnlockKey 
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
                ///////////////////////////////////////////////////////////////////////////////////
                // Inherit protection data from the old key but nothing else
                ///////////////////////////////////////////////////////////////////////////////////
                post_op.new_key.pin_policy = key_entry.pin_policy;
                post_op.new_key.pin_value = key_entry.pin_value;
                post_op.new_key.error_count = key_entry.error_count;
                post_op.new_key.device_pin_protection = key_entry.device_pin_protection;

                if (post_op.upd_or_del)
                  {
                    ///////////////////////////////////////////////////////////////////////////////////
                    // postUpdateKey. Store new key in the place of the old
                    ///////////////////////////////////////////////////////////////////////////////////
                    keys.put (key_entry.key_handle, post_op.new_key);

                    ///////////////////////////////////////////////////////////////////////////////////
                    // Remove space occupied by the new key and restore old key handle
                    ///////////////////////////////////////////////////////////////////////////////////
                    keys.remove (post_op.new_key.key_handle);
                    post_op.new_key.key_handle = key_entry.key_handle;
                  }
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
        provisioning.post_provisioning_objects.clear ();  // No need to save

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
    public synchronized ProvisioningSession createProvisioningSession (String session_key_algorithm,
                                                                       boolean privacy_enabled,
                                                                       String server_session_id,
                                                                       ECPublicKey server_ephemeral_key,
                                                                       String issuer_uri,
                                                                       PublicKey key_management_key, // May be null
                                                                       int client_time,
                                                                       int session_life_time,
                                                                       short session_key_limit) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Check provisioning session algorithm compatibility
        ///////////////////////////////////////////////////////////////////////////////////
        if (!session_key_algorithm.equals (ALGORITHM_SESSION_ATTEST_1))
          {
            abort ("Unknown \"SessionKeyAlgorithm\" : " + session_key_algorithm);
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Check IssuerURI
        ///////////////////////////////////////////////////////////////////////////////////
        if (issuer_uri.length () == 0 || issuer_uri.length () >  MAX_LENGTH_URI)
          {
            abort ("\"IssuerURI\" length error: " + issuer_uri.length ());
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Check server ECDH key compatibility
        ///////////////////////////////////////////////////////////////////////////////////
        String jce_name = checkECKeyCompatibility (server_ephemeral_key, this, "\"ServerEphemeralKey\"");

        ///////////////////////////////////////////////////////////////////////////////////
        // Check optional key management key compatibility
        ///////////////////////////////////////////////////////////////////////////////////
        if (key_management_key != null)
          {
            if (key_management_key instanceof RSAPublicKey)
              {
                checkRSAKeyCompatibility (getRSAKeySize ((RSAPublicKey)key_management_key),
                                          ((RSAPublicKey)key_management_key).getPublicExponent (), this, "\"KeyManagementKey\"");
              }
            else
              {
                checkECKeyCompatibility ((ECPublicKey)key_management_key, this, "\"KeyManagementKey\"");
              }
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Check ServerSessionID
        ///////////////////////////////////////////////////////////////////////////////////
        checkIDSyntax (server_session_id, "ServerSessionID", this);

        ///////////////////////////////////////////////////////////////////////////////////
        // Create ClientSessionID
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] random = new byte[MAX_LENGTH_ID_TYPE];
        new SecureRandom ().nextBytes (random);
        StringBuffer client_session_id_buffer = new StringBuffer ();
        for (byte b : random)
          {
            client_session_id_buffer.append (MODIFIED_BASE64[b & 0x3F]);
          }
        String client_session_id = client_session_id_buffer.toString ();

        ///////////////////////////////////////////////////////////////////////////////////
        // Prepare for the big crypto...
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] attestation = null;
        byte[] session_key = null;
        ECPublicKey client_ephemeral_key = null;
        try
          {
            ///////////////////////////////////////////////////////////////////////////////////
            // Create client ephemeral key
            ///////////////////////////////////////////////////////////////////////////////////
            KeyPairGenerator generator = KeyPairGenerator.getInstance ("EC");
            ECGenParameterSpec eccgen = new ECGenParameterSpec (jce_name);
            generator.initialize (eccgen, new SecureRandom ());
            KeyPair kp = generator.generateKeyPair ();
            client_ephemeral_key = (ECPublicKey) kp.getPublic ();

            ///////////////////////////////////////////////////////////////////////////////////
            // Apply the SP800-56A ECC CDH primitive
            ///////////////////////////////////////////////////////////////////////////////////
            KeyAgreement key_agreement = KeyAgreement.getInstance ("ECDH");
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
            kdf.addArray (getDeviceID (privacy_enabled));
            session_key = kdf.getResult ();

            ///////////////////////////////////////////////////////////////////////////////////
            // Finally, create the Attestation
            ///////////////////////////////////////////////////////////////////////////////////
            if (privacy_enabled)
              {
                ///////////////////////////////////////////////////////////////////////////////////
                // SessionKey attest
                ///////////////////////////////////////////////////////////////////////////////////
                MacBuilder ska = new MacBuilder (session_key);
                ska.addString (client_session_id);
                ska.addString (server_session_id);
                ska.addString (issuer_uri);
                ska.addArray (getDeviceID (privacy_enabled));
                ska.addString (session_key_algorithm);
                ska.addBool (privacy_enabled);
                ska.addArray (server_ephemeral_key.getEncoded ());
                ska.addArray (client_ephemeral_key.getEncoded ());
                ska.addArray (key_management_key == null ? ZERO_LENGTH_ARRAY : key_management_key.getEncoded ());
                ska.addInt (client_time);
                ska.addInt (session_life_time);
                ska.addShort (session_key_limit);
                attestation = ska.getResult ();
              }
            else
              {
                ///////////////////////////////////////////////////////////////////////////////////
                // Device private key attest
                ///////////////////////////////////////////////////////////////////////////////////
                AttestationSignatureGenerator pka = new AttestationSignatureGenerator ();
                pka.addString (client_session_id);
                pka.addString (server_session_id);
                pka.addString (issuer_uri);
                pka.addArray (getDeviceID (privacy_enabled));
                pka.addString (session_key_algorithm);
                pka.addBool (privacy_enabled);
                pka.addArray (server_ephemeral_key.getEncoded ());
                pka.addArray (client_ephemeral_key.getEncoded ());
                pka.addArray (key_management_key == null ? ZERO_LENGTH_ARRAY : key_management_key.getEncoded ());
                pka.addInt (client_time);
                pka.addInt (session_life_time);
                pka.addShort (session_key_limit);
                attestation = pka.getResult ();
              }
          }
        catch (Exception e)
          {
            throw new SKSException (e);
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // We did it!
        ///////////////////////////////////////////////////////////////////////////////////
        Provisioning p = new Provisioning ();
        p.privacy_enabled = privacy_enabled;
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
    public synchronized void addExtension (int key_handle,
                                           String type,
                                           byte sub_type,
                                           String qualifier,
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
        key_entry.owner.rangeTest (sub_type, SUB_TYPE_EXTENSION, SUB_TYPE_LOGOTYPE, "SubType");
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
        byte[] bin_qualifier = getBinary (qualifier);
        if (((sub_type == SUB_TYPE_LOGOTYPE) ^ (bin_qualifier.length != 0)) || bin_qualifier.length > MAX_LENGTH_QUALIFIER)
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
        verifier.addArray (bin_qualifier);
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
    //                            importPrivateKey                                //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized void importPrivateKey (int key_handle,
                                               byte[] private_key,
                                               byte[] mac) throws SKSException
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
            key_entry.owner.abort ("Private key: " + key_entry.id + " exceeds " + MAX_LENGTH_CRYPTO_DATA + " bytes");
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify incoming MAC
        ///////////////////////////////////////////////////////////////////////////////////
        MacBuilder verifier = key_entry.getEECertMacBuilder (METHOD_IMPORT_PRIVATE_KEY);
        verifier.addArray (private_key);
        key_entry.owner.verifyMac (verifier, mac);


        ///////////////////////////////////////////////////////////////////////////////////
        // Mark as "copied" by the server
        ///////////////////////////////////////////////////////////////////////////////////
        key_entry.setAndVerifyServerBackupFlag ();

        ///////////////////////////////////////////////////////////////////////////////////
        // Decrypt and store private key
        ///////////////////////////////////////////////////////////////////////////////////
        try
          {
            byte[] pkcs8_private_key = key_entry.owner.decrypt (private_key);
            PKCS8EncodedKeySpec key_spec = new PKCS8EncodedKeySpec (pkcs8_private_key);

            ///////////////////////////////////////////////////////////////////////////////////
            // Bare-bones ASN.1 decoding to find out if it is RSA or EC 
            ///////////////////////////////////////////////////////////////////////////////////
            boolean rsa_flag = false;
            for (int j = 8; j < 11; j++)
              {
                rsa_flag = true;
                for (int i = 0; i < RSA_ENCRYPTION_OID.length; i++)
                  {
                    if (pkcs8_private_key[j + i] != RSA_ENCRYPTION_OID[i])
                      {
                        rsa_flag = false;
                      }
                  }
                if (rsa_flag) break;
              }
            key_entry.private_key = KeyFactory.getInstance (rsa_flag ? "RSA" : "EC").generatePrivate (key_spec);
            if (rsa_flag)
              {
                checkRSAKeyCompatibility (getRSAKeySize((RSAPrivateKey) key_entry.private_key),
                                          key_entry.getPublicRSAExponentFromPrivateKey (),
                                          key_entry.owner, key_entry.id);
              }
            else
              {
                checkECKeyCompatibility ((ECPrivateKey)key_entry.private_key, key_entry.owner, key_entry.id);
              }
          }
        catch (GeneralSecurityException e)
          {
            key_entry.owner.abort (e.getMessage (), SKSException.ERROR_CRYPTO);
          }
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                           importSymmetricKey                               //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized void importSymmetricKey (int key_handle,
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

        ///////////////////////////////////////////////////////////////////////////////////
        // Mark as "copied" by the server
        ///////////////////////////////////////////////////////////////////////////////////
        key_entry.setAndVerifyServerBackupFlag ();

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify incoming MAC
        ///////////////////////////////////////////////////////////////////////////////////
        MacBuilder verifier = key_entry.getEECertMacBuilder (METHOD_IMPORT_SYMMETRIC_KEY);
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
    public synchronized void setCertificatePath (int key_handle,
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
        // Update public key value.  It has no use after "setCertificatePath" anyway...
        ///////////////////////////////////////////////////////////////////////////////////
        key_entry.public_key = certificate_path[0].getPublicKey ();

        ///////////////////////////////////////////////////////////////////////////////////
        // Check key material for SKS compliance
        ///////////////////////////////////////////////////////////////////////////////////
        if (key_entry.public_key instanceof RSAPublicKey)
          {
            checkRSAKeyCompatibility (getRSAKeySize((RSAPublicKey) key_entry.public_key),
                                      ((RSAPublicKey) key_entry.public_key).getPublicExponent (),
                                      key_entry.owner, key_entry.id);
          }
        else
          {
            checkECKeyCompatibility ((ECPublicKey) key_entry.public_key, key_entry.owner, key_entry.id);
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
    public synchronized KeyData createKeyEntry (int provisioning_handle,
                                                String id,
                                                String key_entry_algorithm,
                                                byte[] server_seed,
                                                boolean device_pin_protection,
                                                int pin_policy_handle,
                                                byte[] pin_value,
                                                boolean enable_pin_caching,
                                                byte biometric_protection,
                                                byte export_protection,
                                                byte delete_protection,
                                                byte app_usage,
                                                String friendly_name,
                                                String key_algorithm,
                                                byte[] key_parameters,
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
        if (!key_entry_algorithm.equals (ALGORITHM_KEY_ATTEST_1))
          {
            provisioning.abort ("Unknown \"KeyEntryAlgorithm\" : " + key_entry_algorithm, SKSException.ERROR_ALGORITHM);
          }
        Algorithm kalg = supported_algorithms.get (key_algorithm);
        if (kalg == null || (kalg.mask & ALG_KEY_GEN) == 0)
          {
            provisioning.abort ("Unsupported \"KeyAlgorithm\": " + key_algorithm);
          }
        if ((kalg.mask & ALG_KEY_PARM) == 0 ^ key_parameters == null)
          {
            provisioning.abort ((key_parameters == null ? "Missing" : "Unexpected") + " \"KeyParameters\"");
          }
        if (server_seed != null && (server_seed.length == 0 || server_seed.length > MAX_LENGTH_SERVER_SEED))
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
            if (enable_pin_caching && pin_policy.input_method != INPUT_METHOD_TRUSTED_GUI)
              {
                provisioning.abort ("\"EnablePINCaching\" must be combined with \"trusted-gui\"");
              }
            pin_policy_id = pin_policy.id;
            provisioning.names.put (pin_policy_id, true); // Referenced
            decrypt_pin = !pin_policy.user_defined;
          }
        else
          {
            verifyExportDeleteProtection (delete_protection, EXPORT_DELETE_PROTECTION_PIN, provisioning);
            verifyExportDeleteProtection (export_protection, EXPORT_DELETE_PROTECTION_PIN, provisioning);
            pin_protection = false;
            if (enable_pin_caching)
              {
                provisioning.abort ("\"EnablePINCaching\" without PIN");
              }
            if (pin_value != null)
              {
                provisioning.abort ("\"PINValue\" expected to be empty");
              }
          }
        if (biometric_protection != BIOMETRIC_PROTECTION_NONE &&
            ((biometric_protection != BIOMETRIC_PROTECTION_EXCLUSIVE) ^ pin_protection))
          {
            provisioning.abort ("Invalid \"BiometricProtection\" and PIN combination");
          }
        if (pin_policy == null || pin_policy.puk_policy == null)
          {
            verifyExportDeleteProtection (delete_protection, EXPORT_DELETE_PROTECTION_PUK, provisioning);
            verifyExportDeleteProtection (export_protection, EXPORT_DELETE_PROTECTION_PUK, provisioning);
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify incoming MAC
        ///////////////////////////////////////////////////////////////////////////////////
        MacBuilder verifier = provisioning.getMacBuilderForMethodCall (METHOD_CREATE_KEY_ENTRY);
        verifier.addString (id);
        verifier.addString (key_entry_algorithm);
        verifier.addArray (server_seed == null ? ZERO_LENGTH_ARRAY : server_seed);
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
        verifier.addBool (enable_pin_caching);
        verifier.addByte (biometric_protection);
        verifier.addByte (export_protection);
        verifier.addByte (delete_protection);
        verifier.addByte (app_usage);
        verifier.addString (friendly_name == null ? "" : friendly_name);
        verifier.addString (key_algorithm);
        verifier.addArray (key_parameters == null ? ZERO_LENGTH_ARRAY : key_parameters);
        LinkedHashSet<String> temp_endorsed = new LinkedHashSet<String> ();
        String prev_alg = "\0";
        for (String endorsed_algorithm : endorsed_algorithms)
          {
            ///////////////////////////////////////////////////////////////////////////////////
            // Check that the algorithms are sorted and known
            ///////////////////////////////////////////////////////////////////////////////////
            if (prev_alg.compareTo (endorsed_algorithm) >= 0)
              {
                provisioning.abort ("Duplicate or incorrectly sorted algorithm: " + endorsed_algorithm);
              }
            Algorithm alg = supported_algorithms.get (endorsed_algorithm);
            if (alg == null || alg.mask == 0)
              {
                provisioning.abort ("Unsupported algorithm: " + endorsed_algorithm);
              }
            if ((alg.mask & ALG_NONE) != 0 && endorsed_algorithms.length > 1)
              {
                provisioning.abort ("Algorithm must be alone: " + endorsed_algorithm);
              }
            temp_endorsed.add (prev_alg = endorsed_algorithm);
            verifier.addString (endorsed_algorithm);
          }
        provisioning.verifyMac (verifier, mac);

        ///////////////////////////////////////////////////////////////////////////////////
        // Perform a gazillion tests on PINs if applicable
        ///////////////////////////////////////////////////////////////////////////////////
        if (pin_policy != null)
          {
            ///////////////////////////////////////////////////////////////////////////////////
            // Testing the actual PIN value
            ///////////////////////////////////////////////////////////////////////////////////
            verifyPINPolicyCompliance (false, pin_value, pin_policy, app_usage, provisioning);
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Decode key algorithm specifier
        ///////////////////////////////////////////////////////////////////////////////////
        AlgorithmParameterSpec alg_par_spec = null;
        if ((kalg.mask & ALG_RSA_KEY) == ALG_RSA_KEY)
          {
            int rsa_key_size = kalg.mask & ALG_RSA_GMSK;
            BigInteger exponent = RSAKeyGenParameterSpec.F4;
            if (key_parameters != null)
              {
                if (key_parameters.length == 0 || key_parameters.length > 8)
                  {
                    provisioning.abort ("\"KeyParameters\" length error: " + key_parameters.length);
                  }
                exponent = new BigInteger (key_parameters);
              }
            alg_par_spec = new RSAKeyGenParameterSpec (rsa_key_size, exponent);
          }
        else
          {
            alg_par_spec = new ECGenParameterSpec (kalg.jce_name);
          }
        try
          {
            ///////////////////////////////////////////////////////////////////////////////////
            // At last, generate the desired key-pair
            ///////////////////////////////////////////////////////////////////////////////////
            SecureRandom secure_random = server_seed == null ? new SecureRandom () : new SecureRandom (server_seed);
            KeyPairGenerator kpg = KeyPairGenerator.getInstance (alg_par_spec instanceof RSAKeyGenParameterSpec ? "RSA" : "EC");
            kpg.initialize (alg_par_spec, secure_random);
            KeyPair key_pair = kpg.generateKeyPair ();
            PublicKey public_key = key_pair.getPublic ();
            PrivateKey private_key = key_pair.getPrivate ();

            ///////////////////////////////////////////////////////////////////////////////////
            // Create key attest
            ///////////////////////////////////////////////////////////////////////////////////
            MacBuilder cka = provisioning.getMacBuilderForMethodCall (KDF_DEVICE_ATTESTATION);
            cka.addString (id);
            cka.addArray (public_key.getEncoded ());
            byte[] attestation = cka.getResult ();

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
            return new KeyData (key_entry.key_handle, public_key, attestation);
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
    public synchronized int createPINPolicy (int provisioning_handle,
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
        provisioning.rangeTest (input_method, INPUT_METHOD_ANY, INPUT_METHOD_TRUSTED_GUI, "InputMethod");
        provisioning.passphraseFormatTest (format);
        provisioning.retryLimitTest (retry_limit, (short)1);
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
            format != PASSPHRASE_FORMAT_ALPHANUMERIC && format != PASSPHRASE_FORMAT_STRING)
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
    public synchronized int createPUKPolicy (int provisioning_handle,
                                             String id,
                                             byte[] puk_value,
                                             byte format,
                                             short retry_limit,
                                             byte[] mac) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get provisioning session
        ///////////////////////////////////////////////////////////////////////////////////
        Provisioning provisioning = getOpenProvisioningSession (provisioning_handle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Perform PUK "sanity" checks
        ///////////////////////////////////////////////////////////////////////////////////
        provisioning.passphraseFormatTest (format);
        provisioning.retryLimitTest (retry_limit, (short)0);
        byte[] decrypted_puk_value = provisioning.decrypt (puk_value);
        if (decrypted_puk_value.length == 0 || decrypted_puk_value.length > MAX_LENGTH_PIN_PUK)
          {
            provisioning.abort ("PUK length error");
          }
        for (int i = 0; i < decrypted_puk_value.length; i++)
          {
            byte c = decrypted_puk_value[i];
            if ((c < '0' || c > '9') && (format == PASSPHRASE_FORMAT_NUMERIC ||
                                        ((c < 'A' || c > 'Z') && format == PASSPHRASE_FORMAT_ALPHANUMERIC)))
              {
                provisioning.abort ("PUK syntax error");
              }
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify incoming MAC
        ///////////////////////////////////////////////////////////////////////////////////
        MacBuilder verifier = provisioning.getMacBuilderForMethodCall (METHOD_CREATE_PUK_POLICY);
        verifier.addString (id);
        verifier.addArray (puk_value);
        verifier.addByte (format);
        verifier.addShort (retry_limit);
        provisioning.verifyMac (verifier, mac);

        ///////////////////////////////////////////////////////////////////////////////////
        // Success, create object
        ///////////////////////////////////////////////////////////////////////////////////
        PUKPolicy puk_policy = new PUKPolicy (provisioning, id);
        puk_policy.puk_value = decrypted_puk_value;
        puk_policy.format = format;
        puk_policy.retry_limit = retry_limit;
        return puk_policy.puk_policy_handle;
      }
  }
