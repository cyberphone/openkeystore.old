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
package org.webpki.sks.twolayer.tee;

import java.io.IOException;
import java.io.Serializable;

import java.math.BigInteger;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import java.security.cert.X509Certificate;

import java.security.interfaces.ECKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPublicKey;

import java.security.spec.ECParameterSpec;

import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Vector;

import javax.crypto.Cipher;
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

import org.webpki.sks.twolayer.se.SEKeyData;
import org.webpki.sks.twolayer.se.SEKeyState;
import org.webpki.sks.twolayer.se.SEProvisioningData;
import org.webpki.sks.twolayer.se.SEProvisioningState;
import org.webpki.sks.twolayer.se.SEReferenceImplementation;

/*
 *                          ################################################
 *                          #  SKS - Secure Key Store - Two Layer Version  #
 *                          #   TEE - Trusted Execution Environment Part   #
 *                          ################################################
 *
 *  SKS is a cryptographic module that supports On-line Provisioning and Management
 *  of PKI, Symmetric keys, PINs, PUKs and Extension data.
 *  
 *  Note that persistence is not supported by the Reference Implementation.
 *
 *  Author: Anders Rundgren
 */
public class TEEReferenceImplementation implements TEEError, SecureKeyStore, Serializable
  {
    private static final long serialVersionUID = 1L;

    /////////////////////////////////////////////////////////////////////////////////////////////
    // SKS version and configuration data
    /////////////////////////////////////////////////////////////////////////////////////////////
    static final String SKS_VENDOR_NAME                    = "WebPKI.org";
    static final String SKS_VENDOR_DESCRIPTION             = "SKS Reference - Java TEE/SE Edition";
    static final String SKS_UPDATE_URL                     = null;  // Change here to test or disable
    static final boolean SKS_DEVICE_PIN_SUPPORT            = true;  // Change here to test or disable
    static final boolean SKS_BIOMETRIC_SUPPORT             = true;  // Change here to test or disable
    static final boolean SKS_RSA_EXPONENT_SUPPORT          = true;  // Change here to test or disable

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


    static void checkIDSyntax (String identifier, String symbolic_name, TEEError sks_error) throws SKSException
      {
        boolean flag = false;
        if (identifier.length () == 0 || identifier.length () > MAX_LENGTH_ID_TYPE)
          {
            flag = true;
          }
        else for (int i = 0; i < identifier.length (); i++)
          {
            char c = identifier.charAt (i);
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
            sks_error.abort ("Malformed \"" + symbolic_name + "\" : " + identifier);
          }
      }


    class KeyEntry extends NameSpace implements Serializable
      {
        private static final long serialVersionUID = 1L;

        int key_handle;

        byte app_usage;

        PublicKey public_key;     // In this implementation overwritten by "setCertificatePath"

        SEKeyState se_key_state;
/* TODO
        PrivateKey private_key;   // Overwritten if "restorePivateKey" is called
        byte[] symmetric_key;     // Defined by "importSymmetricKey"
*/
        X509Certificate[] certificate_path;

// TODO
        boolean is_symmetric_key;

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
        
        boolean isRSA ()
          {
            return public_key instanceof RSAPublicKey;
          }
        
        boolean isSymmetric ()
          {
            return is_symmetric_key;
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
            if ((key_backup & KeyProtectionInfo.KEYBACKUP_SERVER) != 0)
              {
                owner.abort ("Mutiple key imports for: " + id);
              }
            key_backup |= KeyProtectionInfo.KEYBACKUP_SERVER;
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


    class Provisioning implements TEEError, Serializable
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

        SEProvisioningState se_provisioning_state;

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

        public void abort (SKSException e) throws SKSException
          {
            abort (e.getMessage (), e.getError ());
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
            try
              {
                addArray (string.getBytes ("UTF-8"));
              }
            catch (IOException e)
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
    static final int ALG_EC_KEY   = 0x000400;
    static final int ALG_EC_CRV   = 0x000800;
    static final int ALG_HASH_160 = 0x014000;
    static final int ALG_HASH_256 = 0x020000;
    static final int ALG_HASH_DIV = 0x001000;
    static final int ALG_HASH_MSK = 0x00007F;
    static final int ALG_NONE     = 0x080000;
    static final int ALG_ASYM_KA  = 0x100000;
    static final int ALG_AES_PAD  = 0x200000;

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
        addAlgorithm ("http://xmlns.webpki.org/keygen2/1.0#algorithm.ecdh.raw",
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

        addAlgorithm ("http://xmlns.webpki.org/keygen2/1.0#algorithm.rsa.none",
                      "NONEwithRSA",
                      ALG_ASYM_SGN | ALG_RSA_KEY);

        addAlgorithm ("http://xmlns.webpki.org/keygen2/1.0#algorithm.ecdsa.none",
                      "NONEwithECDSA",
                      ALG_ASYM_SGN | ALG_EC_KEY);

        //////////////////////////////////////////////////////////////////////////////////////
        //  Elliptic Curves
        //////////////////////////////////////////////////////////////////////////////////////
        addAlgorithm ("urn:oid:1.2.840.10045.3.1.7", "secp256r1", ALG_EC_CRV);

        //////////////////////////////////////////////////////////////////////////////////////
        //  Special Algorithms
        //////////////////////////////////////////////////////////////////////////////////////
        addAlgorithm (ALGORITHM_SESSION_ATTEST_1, null, 0);

        addAlgorithm (ALGORITHM_KEY_ATTEST_1, null, 0);

        addAlgorithm ("http://xmlns.webpki.org/keygen2/1.0#algorithm.none", null, ALG_NONE);

      }

    static final byte[] RSA_ENCRYPTION_OID = {0x06, 0x09, 0x2A, (byte)0x86, 0x48, (byte)0x86, (byte)0xF7, 0x0D, 0x01, 0x01, 0x01};

    /////////////////////////////////////////////////////////////////////////////////////////////
    // P-256 / secp256r1
    /////////////////////////////////////////////////////////////////////////////////////////////
    static final BigInteger secp256r1_AffineX   = new BigInteger ("48439561293906451759052585252797914202762949526041747995844080717082404635286");
    static final BigInteger secp256r1_AffineY   = new BigInteger ("36134250956749795798585127919587881956611106672985015071877198253568414405109");
    static final BigInteger secp256r1_A         = new BigInteger ("115792089210356248762697446949407573530086143415290314195533631308867097853948");
    static final BigInteger secp256r1_B         = new BigInteger ("41058363725152142129326129780047268409114441015993725554835256314039467401291");
    static final BigInteger secp256r1_Order     = new BigInteger ("115792089210356248762697446949407573529996955224135760342422259061068512044369");
    static final int        secp256r1_Cofactor  = 1;

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

    void checkECKeyCompatibility (ECKey ec_key, TEEError sks_error, String key_id) throws SKSException
      {
        ECParameterSpec ec = ec_key.getParams ();
        if (!ec.getCurve ().getA ().equals (secp256r1_A) ||
            !ec.getCurve ().getB ().equals (secp256r1_B) ||
            !ec.getGenerator ().getAffineX ().equals (secp256r1_AffineX) ||
            !ec.getGenerator ().getAffineY ().equals (secp256r1_AffineY) ||
            !ec.getOrder ().equals (secp256r1_Order) ||
            ec.getCofactor () != secp256r1_Cofactor)
          {
            sks_error.abort ("EC key " + key_id + " not of P-256/secp256r1 type");
          }
      }

    void checkRSAKeyCompatibility (int rsa_key_size, BigInteger  exponent, TEEError sks_error, String key_id) throws SKSException
      {
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
    void verifyPINPolicyCompliance (boolean forced_setter, byte[] pin_value, PINPolicy pin_policy, byte app_usage, TEEError sks_error) throws SKSException
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

    byte[] addArrays (byte[] a, byte[] b)
      {
        byte[] r = new byte[a.length + b.length];
        System.arraycopy (a, 0, r, 0, a.length);
        System.arraycopy (b, 0, r, a.length, b.length);
        return r;
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
/* TODO
        MacBuilder verifier = new_key.getEECertMacBuilder (update ? METHOD_POST_UPDATE_KEY : METHOD_POST_CLONE_KEY_PROTECTION);
        target_key_entry.validateTargetKeyReference (verifier, mac, authorization, provisioning);
*/

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
/* TODO
        MacBuilder verifier = provisioning.getMacBuilderForMethodCall (delete ? METHOD_POST_DELETE_KEY : METHOD_POST_UNLOCK_KEY);
        target_key_entry.validateTargetKeyReference (verifier, mac, authorization, provisioning);
*/

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
        key_entry.key_backup |= KeyProtectionInfo.KEYBACKUP_LOCAL;

        ///////////////////////////////////////////////////////////////////////////////////
        // Export key in raw unencrypted format
        ///////////////////////////////////////////////////////////////////////////////////
/* TODO
        return key_entry.isSymmetric () ? key_entry.symmetric_key : key_entry.private_key.getEncoded ();
*/
        return null;
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                              setProperty                                   //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized void setProperty (int key_handle,
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
/* TODO
        Algorithm alg = checkKeyAndAlgorithm (key_entry, algorithm, ALG_ASYM_ENC);
*/
        if (parameters != null)  // Only support basic RSA yet...
          {
            abort ("\"Parameters\" for key #" + key_handle + " do not match algorithm");
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Finally, perform operation
        ///////////////////////////////////////////////////////////////////////////////////
/* TODO
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
*/
        return null;
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
/* TODO
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
*/

        ///////////////////////////////////////////////////////////////////////////////////
        // Finally, perform operation
        ///////////////////////////////////////////////////////////////////////////////////
/* TODO
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
*/
        return null;
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
/* TODO
        Algorithm alg = checkKeyAndAlgorithm (key_entry, algorithm, ALG_ASYM_KA);
        if (parameters != null)  // Only support external KDFs yet...
          {
            abort ("\"Parameters\" for key #" + key_handle + " do not match algorithm");
          }
*/

        ///////////////////////////////////////////////////////////////////////////////////
        // Check that the key type matches the algorithm
        ///////////////////////////////////////////////////////////////////////////////////
        checkECKeyCompatibility (public_key, this, "\"PublicKey\"");

        ///////////////////////////////////////////////////////////////////////////////////
        // Finally, perform operation
        ///////////////////////////////////////////////////////////////////////////////////
/* TODO
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
*/
        return null;
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
                                                    byte[] iv,
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
/* TODO
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
*/

        ///////////////////////////////////////////////////////////////////////////////////
        // Finally, perform operation
        ///////////////////////////////////////////////////////////////////////////////////
 /*
        try
          {
            Cipher crypt = Cipher.getInstance (alg.jce_name);
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
*/
        return null;
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                               performHMAC                                  //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized byte[] performHMAC (int key_handle,
                                            String algorithm,
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
/* TODO
        Algorithm alg = checkKeyAndAlgorithm (key_entry, algorithm, ALG_HMAC);
*/

        ///////////////////////////////////////////////////////////////////////////////////
        // Finally, perform operation
        ///////////////////////////////////////////////////////////////////////////////////
/* TODO
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
*/
        return null;
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                              getDeviceInfo                                 //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized DeviceInfo getDeviceInfo () throws SKSException
      {
        return SEReferenceImplementation.getDeviceInfo ();
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
        return new KeyAttributes (key_entry.isSymmetric (),
                                  key_entry.certificate_path,
                                  key_entry.app_usage,
                                  key_entry.friendly_name,
                                  key_entry.endorsed_algorithms.toArray (new String[0]),
                                  key_entry.extensions.keySet ().toArray (new String[0]));
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
                                                         byte[] nonce,
                                                         byte[] mac) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get provisioning session
        ///////////////////////////////////////////////////////////////////////////////////
        Provisioning provisioning = getOpenProvisioningSession (provisioning_handle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Generate the attestation in advance => checking SessionKeyLimit before "commit"
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] attestation = null;
        try
          {
            attestation = SEReferenceImplementation.closeProvisioningAttest (provisioning.se_provisioning_state,
                                                                             provisioning.server_session_id,
                                                                             provisioning.client_session_id,
                                                                             provisioning.issuer_uri, 
                                                                             nonce, 
                                                                             mac);
          }
        catch (SKSException e)
          {
            provisioning.abort (e);
          }

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
                key_entry.checkEECerificateAvailablity ();

                ///////////////////////////////////////////////////////////////////////////////////
                // Check public versus private key match
                ///////////////////////////////////////////////////////////////////////////////////
/* TODO
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
*/

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
/* TODO
                                testAESKey (algorithm, key_entry.symmetric_key, key_entry.id, provisioning);
*/
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
                        key_entry.owner.abort ((key_entry.isSymmetric () ? "Symmetric" : key_entry.isRSA () ? "RSA" : "EC") + 
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
    public synchronized ProvisioningSession createProvisioningSession (String algorithm,
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
        // The assumption here is that the SE can do parameter validation...
        ///////////////////////////////////////////////////////////////////////////////////
        SEProvisioningData se_pd = SEReferenceImplementation.createProvisioningData (algorithm,
                                                                                     privacy_enabled,
                                                                                     server_session_id,
                                                                                     server_ephemeral_key,
                                                                                     issuer_uri,
                                                                                     key_management_key,
                                                                                     client_time,
                                                                                     session_life_time,
                                                                                     session_key_limit);
        
        ///////////////////////////////////////////////////////////////////////////////////
        // We did it!
        ///////////////////////////////////////////////////////////////////////////////////
        Provisioning provisioning = new Provisioning ();
        provisioning.privacy_enabled = privacy_enabled;
        provisioning.server_session_id = server_session_id;
        provisioning.client_session_id = se_pd.client_session_id;
        provisioning.issuer_uri = issuer_uri;
        provisioning.key_management_key = key_management_key;
        provisioning.client_time = client_time;
        provisioning.session_life_time = session_life_time;
        provisioning.se_provisioning_state = se_pd.se_provisioning_state;
        return new ProvisioningSession (provisioning.provisioning_handle,
                                        se_pd.client_session_id,
                                        se_pd.attestation,
                                        se_pd.client_ephemeral_key);
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
/* TODO
        MacBuilder verifier = key_entry.getEECertMacBuilder (METHOD_ADD_EXTENSION);
        verifier.addString (type);
        verifier.addByte (sub_type);
        verifier.addArray (qualifier);
        verifier.addBlob (extension_data);
        key_entry.owner.verifyMac (verifier, mac);
*/

        ///////////////////////////////////////////////////////////////////////////////////
        // Succeeded, create object
        ///////////////////////////////////////////////////////////////////////////////////
        ExtObject extension = new ExtObject ();
/* TODO
        extension.sub_type = sub_type;
        extension.qualifier = qualifier;
        extension.extension_data = (sub_type == SUB_TYPE_ENCRYPTED_EXTENSION) ?
                                     key_entry.owner.decrypt (extension_data) : extension_data;
*/
        key_entry.extensions.put (type, extension);
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                           restorePrivateKey                                //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized void restorePrivateKey (int key_handle,
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
            key_entry.owner.abort ("Private key: " + key_entry.id + " exceeds " + MAX_LENGTH_SYMMETRIC_KEY + " bytes");
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify incoming MAC
        ///////////////////////////////////////////////////////////////////////////////////
/* TODO
        MacBuilder verifier = key_entry.getEECertMacBuilder (METHOD_RESTORE_PRIVATE_KEY);
        verifier.addArray (private_key);
        key_entry.owner.verifyMac (verifier, mac);
*/


        ///////////////////////////////////////////////////////////////////////////////////
        // Mark as "copied" by the server
        ///////////////////////////////////////////////////////////////////////////////////
        key_entry.setAndVerifyServerBackupFlag ();

        ///////////////////////////////////////////////////////////////////////////////////
        // Decrypt and store private key
        ///////////////////////////////////////////////////////////////////////////////////
  /* TODO
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
*/
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
/* TODO
        MacBuilder verifier = key_entry.getEECertMacBuilder (METHOD_IMPORT_SYMMETRIC_KEY);
        verifier.addArray (symmetric_key);
        key_entry.owner.verifyMac (verifier, mac);

        ///////////////////////////////////////////////////////////////////////////////////
        // Decrypt and store symmetric key
        ///////////////////////////////////////////////////////////////////////////////////
        key_entry.symmetric_key = key_entry.owner.decrypt (symmetric_key);
*/
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
        // Verify MAC through the SE
        ///////////////////////////////////////////////////////////////////////////////////
        try
          {
            SEReferenceImplementation.setAndVerifyCertificatePath (key_entry.owner.se_provisioning_state,
                                                                   key_entry.se_key_state,
                                                                   key_entry.id,
                                                                   key_entry.public_key,
                                                                   certificate_path,
                                                                   mac);
          }
        catch (SKSException e)
          {
            key_entry.owner.abort (e);
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Update public key value.  It has no use after "setCertificatePath" anyway...
        ///////////////////////////////////////////////////////////////////////////////////
        key_entry.public_key = certificate_path[0].getPublicKey ();

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
                                                String algorithm,
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
        if (server_seed != null && (server_seed.length == 0 || server_seed.length > 32))
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
        // Verify MAC and get keys through the SE
        ///////////////////////////////////////////////////////////////////////////////////
        SEKeyData se_key_data = null;
        try
          {
            se_key_data = SEReferenceImplementation.createKeyPair (provisioning.se_provisioning_state,
                                                                   id,
                                                                   algorithm,
                                                                   server_seed,
                                                                   device_pin_protection,
                                                                   pin_policy_id,
                                                                   decrypt_pin ? pin_value : null,
                                                                   enable_pin_caching,
                                                                   biometric_protection,
                                                                   export_protection,
                                                                   delete_protection,
                                                                   app_usage,
                                                                   friendly_name,
                                                                   key_specifier,
                                                                   endorsed_algorithms,
                                                                   mac);
          }
        catch (SKSException e)
          {
            provisioning.abort (e);
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Perform a gazillion tests on PINs if applicable
        ///////////////////////////////////////////////////////////////////////////////////
        if (decrypt_pin)
          {
            pin_value = se_key_data.decrypted_pin_value;
          }
        else if (pin_value != null)
          {
            pin_value = pin_value.clone ();
          }
        if (pin_policy != null)
          {
            ///////////////////////////////////////////////////////////////////////////////////
            // Testing the actual PIN value
            ///////////////////////////////////////////////////////////////////////////////////
            verifyPINPolicyCompliance (false, pin_value, pin_policy, app_usage, provisioning);
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Finally, create a key entry
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry key_entry = new KeyEntry (provisioning, id);
        provisioning.names.put (id, true); // Referenced (for "closeProvisioningSession")
        key_entry.pin_policy = pin_policy;
        key_entry.friendly_name = friendly_name;
        key_entry.pin_value = pin_value;
        key_entry.public_key = se_key_data.public_key;
        key_entry.se_key_state = se_key_data.se_key_state;
        key_entry.app_usage = app_usage;
        key_entry.device_pin_protection = device_pin_protection;
        key_entry.enable_pin_caching = enable_pin_caching;
        key_entry.biometric_protection = biometric_protection;
        key_entry.export_protection = export_protection;
        key_entry.delete_protection = delete_protection;
        LinkedHashSet<String> temp_endorsed = new LinkedHashSet<String> ();
        for (String endorsed_algorithm : endorsed_algorithms)
          {
            temp_endorsed.add (endorsed_algorithm);
          }
        key_entry.endorsed_algorithms = temp_endorsed;
        return new KeyData (key_entry.key_handle, se_key_data.public_key, se_key_data.attestation);
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
        provisioning.rangeTest (input_method, INPUT_METHOD_PROGRAMMATIC, INPUT_METHOD_ANY, "InputMethod");
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
        // Verify MAC through the SE
        ///////////////////////////////////////////////////////////////////////////////////
        try
          {
            SEReferenceImplementation.verifyPINPolicy (provisioning.se_provisioning_state,
                                                       id,
                                                       puk_policy_id,
                                                       user_defined,
                                                       user_modifiable,
                                                       format,
                                                       retry_limit,
                                                       grouping,
                                                       pattern_restrictions,
                                                       min_length,
                                                       max_length,
                                                       input_method,
                                                       mac);
          }
        catch (SKSException e)
          {
            provisioning.abort (e);
          }

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

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify MAC and get the decrypted value through the SE
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] decrypted_puk_value = null;
        try
          {
            decrypted_puk_value = SEReferenceImplementation.getPUKValue (provisioning.se_provisioning_state,
                                                                         id,
                                                                         puk_value,
                                                                         format,
                                                                         retry_limit,
                                                                         mac);
          }
        catch (SKSException e)
          {
            provisioning.abort (e);
          }
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
        // Success, create object
        ///////////////////////////////////////////////////////////////////////////////////
        PUKPolicy puk_policy = new PUKPolicy (provisioning, id);
        puk_policy.puk_value = decrypted_puk_value;
        puk_policy.format = format;
        puk_policy.retry_limit = retry_limit;
        return puk_policy.puk_policy_handle;
      }
  }
