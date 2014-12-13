/*
 *  Copyright 2006-2014 WebPKI.org (http://webpki.org).
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

import java.io.IOException;
import java.io.Serializable;

import java.math.BigInteger;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
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

import android.util.Log;

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
 *  Compared to the SKS specification, the Android implementation uses a slightly
 *  more java-centric way of passing parameters, including "null" arguments, but the
 *  content is supposed to be identical.
 *  
 *  Author: Anders Rundgren
 */
public class SKSImplementation implements SKSError, SecureKeyStore, Serializable, GrantInterface
  {
    private static final long serialVersionUID = 4L;

    /////////////////////////////////////////////////////////////////////////////////////////////
    // SKS version and configuration data
    /////////////////////////////////////////////////////////////////////////////////////////////
    static final String SKS_VENDOR_NAME                    = "WebPKI.org";
    static final String SKS_VENDOR_DESCRIPTION             = "SKS for Android";
    static final String SKS_UPDATE_URL                     = null;  // Change here to test or disable
    static final boolean SKS_DEVICE_PIN_SUPPORT            = true;  // Change here to test or disable
    static final boolean SKS_BIOMETRIC_SUPPORT             = false;  // Change here to test or disable
    static final boolean SKS_RSA_EXPONENT_SUPPORT          = true;  // Change here to test or disable

    private static final String SKS_DEBUG                  = "SKS";  // Android SKS debug constant
    
    static final char[] MODIFIED_BASE64 = {'A','B','C','D','E','F','G','H',
                                           'I','J','K','L','M','N','O','P',
                                           'Q','R','S','T','U','V','W','X',
                                           'Y','Z','a','b','c','d','e','f',
                                           'g','h','i','j','k','l','m','n',
                                           'o','p','q','r','s','t','u','v',
                                           'w','x','y','z','0','1','2','3',
                                           '4','5','6','7','8','9','-','_'};

    int nextKeyHandle = 1;
    LinkedHashMap<Integer,KeyEntry> keys = new LinkedHashMap<Integer,KeyEntry> ();

    int nextProvHandle = 1;
    LinkedHashMap<Integer,Provisioning> provisionings = new LinkedHashMap<Integer,Provisioning> ();

    int nextPinHandle = 1;
    LinkedHashMap<Integer,PINPolicy> pinPolicies = new LinkedHashMap<Integer,PINPolicy> ();

    int nextPukHandle = 1;
    LinkedHashMap<Integer,PUKPolicy> pukPolicies = new LinkedHashMap<Integer,PUKPolicy> ();

    X509Certificate deviceCertificate;
    PrivateKey attestationKey;
    
    SKSImplementation (X509Certificate deviceCertificate, PrivateKey attestationKey)
      {
        this.deviceCertificate = deviceCertificate;
        this.attestationKey = attestationKey;
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
            checkIDSyntax (id, "ID", owner);
            owner.names.put (id, false);
            this.owner = owner;
            this.id = id;
          }
      }


    static void checkIDSyntax (String identifier, String symbolicName, SKSError sks_error) throws SKSException
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
            sks_error.abort ("Malformed \"" + symbolicName + "\" : " + identifier);
          }
      }


    class KeyEntry extends NameSpace implements Serializable
      {
        private static final long serialVersionUID = 1L;

        int keyHandle;

        byte appUsage;

        PublicKey publicKey;     // In this implementation overwritten by "setCertificatePath"
        PrivateKey privateKey;   // Overwritten if "restorePivateKey" is called
        X509Certificate[] certificatePath;

        byte[] symmetricKey;     // Defined by "importSymmetricKey"

        LinkedHashSet<String> endorsedAlgorithms;

        LinkedHashSet<String> grantedDomains = new LinkedHashSet<String> ();

        String friendlyName;

        boolean devicePinProtection;

        byte[] pinValue;
        short errorCount;
        PINPolicy pinPolicy;
        boolean enablePinCaching;
        
        byte biometricProtection;
        byte exportProtection;
        byte deleteProtection;
        
        byte keyBackup;


        LinkedHashMap<String,ExtObject> extensions = new LinkedHashMap<String,ExtObject> ();

        KeyEntry (Provisioning owner, String id) throws SKSException
          {
            super (owner, id);
            keyHandle = nextKeyHandle++;
            keys.put (keyHandle, this);
          }

        void authError () throws SKSException
          {
            abort ("Authorization error for key #" + keyHandle, SKSException.ERROR_AUTHORIZATION);
          }

        @SuppressWarnings("fallthrough")
        Vector<KeyEntry> getPINSynchronizedKeys ()
          {
            Vector<KeyEntry> group = new Vector<KeyEntry> ();
            if (pinPolicy.grouping == PIN_GROUPING_NONE)
              {
                group.add (this);
              }
            else
              {
                /////////////////////////////////////////////////////////////////////////////////////////
                // Multiple keys "sharing" a PIN means that status and values must be distributed
                /////////////////////////////////////////////////////////////////////////////////////////
                for (KeyEntry keyEntry : keys.values ())
                  {
                    if (keyEntry.pinPolicy == pinPolicy)
                      {
                        switch (pinPolicy.grouping)
                          {
                            case PIN_GROUPING_UNIQUE:
                              if (appUsage != keyEntry.appUsage)
                                {
                                  continue;
                                }
                            case PIN_GROUPING_SIGN_PLUS_STD:
                              if ((appUsage == APP_USAGE_SIGNATURE) ^ (keyEntry.appUsage == APP_USAGE_SIGNATURE))
                                {
                                  continue;
                                }
                          }
                        group.add (keyEntry);
                      }
                  }
              }
            return group;
          }

        void setErrorCounter (short newErrorCount)
          {
            for (KeyEntry keyEntry : getPINSynchronizedKeys ())
              {
                keyEntry.errorCount = newErrorCount;
              }
          }
        
         void updatePIN (byte[] newPin)
          {
            for (KeyEntry keyEntry : getPINSynchronizedKeys ())
              {
                keyEntry.pinValue = newPin;
              }
          }

        void verifyPIN (byte[] pin) throws SKSException
          {
            ///////////////////////////////////////////////////////////////////////////////////
            // If there is no PIN policy there is nothing to verify...
            ///////////////////////////////////////////////////////////////////////////////////
            if (pinPolicy == null)
              {
                if (devicePinProtection)
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
                    abort ("Redundant authorization information for key #" + keyHandle);
                  }
              }
            else
              {
                ///////////////////////////////////////////////////////////////////////////////////
                // Check that we haven't already passed the limit
                ///////////////////////////////////////////////////////////////////////////////////
                if (errorCount >= pinPolicy.retryLimit)
                  {
                    authError ();
                  }

                ///////////////////////////////////////////////////////////////////////////////////
                // Check the PIN value
                ///////////////////////////////////////////////////////////////////////////////////
                if (!Arrays.equals (this.pinValue, pin))
                  {
                    setErrorCounter (++errorCount);
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
            if (pinPolicy == null || pinPolicy.pukPolicy == null)
              {
                abort ("Key #" + keyHandle + " has no PUK");
              }

            PUKPolicy pukPolicy = pinPolicy.pukPolicy;
            if (pukPolicy.retryLimit > 0)
              {
                ///////////////////////////////////////////////////////////////////////////////////
                // The key is using the "standard" retry PUK policy
                ///////////////////////////////////////////////////////////////////////////////////
                if (pukPolicy.errorCount >= pukPolicy.retryLimit)
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
            if (!Arrays.equals (pukPolicy.pukValue, puk))
              {
                if (pukPolicy.retryLimit > 0)
                  {
                    ++pukPolicy.errorCount;
                  }
                authError ();
              }

            ///////////////////////////////////////////////////////////////////////////////////
            // A success always resets the PUK error counter
            ///////////////////////////////////////////////////////////////////////////////////
            pukPolicy.errorCount = 0;
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
                  abort ("Operation not allowed on key #" + keyHandle, SKSException.ERROR_NOT_ALLOWED);
              }
            if (authorization != null)
              {
                abort ("Redundant authorization information for key #" + keyHandle);
              }
          }

        void checkEECerificateAvailablity () throws SKSException
          {
            if (certificatePath == null)
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
                mac_builder.addArray (certificatePath[0].getEncoded ());
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
                provisioning.abort ("Inconsistent use of the \"PrivacyEnabled\" attribute for key #" + keyHandle);
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
                                                                provisioning.getMacBuilder (getDeviceID (provisioning.privacy_enabled)).addVerbatim (certificatePath[0].getEncoded ()).getResult (),
                                                                authorization))
                  {
                    provisioning.abort ("\"Authorization\" signature did not verify for key #" + keyHandle);
                  }
              }
            catch (GeneralSecurityException e)
              {
                provisioning.abort (e.getMessage (), SKSException.ERROR_CRYPTO);
              }
          }

        boolean isRSA ()
          {
            return publicKey instanceof RSAPublicKey;
          }
        
        boolean isSymmetric ()
          {
            return symmetricKey != null;
          }

        void checkCryptoDataSize (byte[] data) throws SKSException
          {
            if (data.length > MAX_LENGTH_CRYPTO_DATA)
              {
                abort ("Exceeded \"CryptoDataSize\" for key #" + keyHandle);
              }
          }

        void setAndVerifyServerBackupFlag () throws SKSException
          {
            if ((keyBackup & KeyProtectionInfo.KEYBACKUP_IMPORTED) != 0)
              {
                owner.abort ("Mutiple key imports for: " + id);
              }
            keyBackup |= KeyProtectionInfo.KEYBACKUP_IMPORTED;
          }

        BigInteger getPublicRSAExponentFromPrivateKey ()
          {
            return ((RSAPrivateCrtKey)privateKey).getPublicExponent ();
          }
      }


    class ExtObject implements Serializable
      {
        private static final long serialVersionUID = 1L;

        String qualifier;
        byte[] extensionData;
        byte sub_type;
      }


    class PINPolicy extends NameSpace implements Serializable
      {
        private static final long serialVersionUID = 1L;

        int pinPolicyHandle;

        PUKPolicy pukPolicy;

        short retryLimit;
        byte format;
        boolean userDefined;
        boolean userModifiable;
        byte inputMethod;
        byte grouping;
        byte patternRestrictions;
        short minLength;
        short maxLength;

        PINPolicy (Provisioning owner, String id) throws SKSException
          {
            super (owner, id);
            pinPolicyHandle = nextPinHandle++;
            pinPolicies.put (pinPolicyHandle, this);
          }
      }


    class PUKPolicy extends NameSpace implements Serializable
      {
        private static final long serialVersionUID = 1L;

        int pukPolicyHandle;

        byte[] pukValue;
        byte format;
        short retryLimit;
        short errorCount;

        PUKPolicy (Provisioning owner, String id) throws SKSException
          {
            super (owner, id);
            pukPolicyHandle = nextPukHandle++;
            pukPolicies.put (pukPolicyHandle, this);
          }
      }


    class Provisioning implements SKSError, Serializable
      {
        private static final long serialVersionUID = 1L;

        int provisioningHandle;

        // The virtual/shared name-space
        LinkedHashMap<String,Boolean> names = new LinkedHashMap<String,Boolean> ();

        // Post provisioning management
        Vector<PostProvisioningObject> postProvisioning_objects = new Vector<PostProvisioningObject> ();

        boolean privacy_enabled;
        String client_session_id;
        String server_session_id;
        String issuer_uri;
        byte[] sessionKey;
        boolean open = true;
        PublicKey key_managementKey;
        short mac_sequenceCounter;
        int client_time;
        int sessionLife_time;
        short sessionKeyLimit;

        Provisioning ()
          {
            provisioningHandle = nextProvHandle++;
            provisionings.put (provisioningHandle, this);
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
            abortProvisioningSession (provisioningHandle);
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
            if (sessionKeyLimit-- <= 0)
              {
                abort ("\"SessionKeyLimit\" exceeded");
              }
            try
              {
                return new MacBuilder (addArrays (sessionKey, key_modifier));
              }
            catch (GeneralSecurityException e)
              {
                throw new SKSException (e);
              }
          }

        MacBuilder getMacBuilderForMethodCall (byte[] method) throws SKSException
          {
            short q = mac_sequenceCounter++;
            return getMacBuilder (addArrays (method, new byte[]{(byte)(q >>> 8), (byte)q}));
          }

        KeyEntry getTargetKey (int keyHandle) throws SKSException
          {
            KeyEntry keyEntry = keys.get (keyHandle);
            if (keyEntry == null)
              {
                abort ("Key not found #" + keyHandle, SKSException.ERROR_NO_KEY);
              }
            if (keyEntry.owner.open)
              {
                abort ("Key #" + keyHandle + " still in provisioning");
              }
            if (keyEntry.owner.key_managementKey == null)
              {
                abort ("Key #" + keyHandle + " belongs to a non-updatable provisioning session");
              }
            return keyEntry;
          }

        void addPostProvisioningObject (KeyEntry targetKey_entry, KeyEntry newKey, boolean upd_orDel) throws SKSException
          {
            for (PostProvisioningObject post_op : postProvisioning_objects)
              {
                if (post_op.newKey != null && post_op.newKey == newKey)
                  {
                    abort ("New key used for multiple operations: " + newKey.id);
                  }
                if (post_op.targetKey_entry == targetKey_entry)
                  {
                    ////////////////////////////////////////////////////////////////////////////////////////////////
                    // Multiple targeting of the same old key is OK but has restrictions
                    ////////////////////////////////////////////////////////////////////////////////////////////////
                    if ((newKey == null && upd_orDel) || (post_op.newKey == null && post_op.upd_orDel)) // postDeleteKey
                      {
                        abort ("Delete wasn't exclusive for key #" + targetKey_entry.keyHandle);
                      }
                    else if (newKey == null && post_op.newKey == null) // postUnlockKey * 2
                      {
                        abort ("Multiple unlocks of key #" + targetKey_entry.keyHandle);
                      }
                    else if (upd_orDel && post_op.upd_orDel)
                      {
                        abort ("Multiple updates of key #" + targetKey_entry.keyHandle);
                      }
                  }
              }
            postProvisioning_objects.add (new PostProvisioningObject (targetKey_entry, newKey, upd_orDel));
          }

        void rangeTest (byte value, byte lowLimit, byte highLimit, String objectName) throws SKSException
          {
            if (value > highLimit || value < lowLimit)
              {
                abort ("Invalid \"" + objectName + "\" value=" + value);
              }
          }

        void passphraseFormatTest (byte format) throws SKSException
          {
            rangeTest (format, PASSPHRASE_FORMAT_NUMERIC, PASSPHRASE_FORMAT_BINARY, "Format");
          }

        void retryLimitTest (short retryLimit, short min) throws SKSException
          {
            if (retryLimit < min || retryLimit > MAX_RETRY_LIMIT)
              {
                abort ("Invalid \"RetryLimit\" value=" + retryLimit);
              }
          }

        boolean verifyKeyManagementKeyAuthorization (byte[] kmk_kdf,
                                                     byte[] argument,
                                                     byte[] authorization) throws GeneralSecurityException
          {
            Signature kmk_verify = Signature.getInstance (key_managementKey instanceof RSAPublicKey ? 
                                                                                     "SHA256WithRSA" : "SHA256WithECDSA");
            kmk_verify.initVerify (key_managementKey);
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

        KeyEntry targetKey_entry;
        KeyEntry newKey;      // null for postDeleteKey and postUnlockKey
        boolean upd_orDel;    // true for postUpdateKey and postDeleteKey

        PostProvisioningObject (KeyEntry targetKey_entry, KeyEntry newKey, boolean upd_orDel)
          {
            this.targetKey_entry = targetKey_entry;
            this.newKey = newKey;
            this.upd_orDel = upd_orDel;
          }
      }


    /////////////////////////////////////////////////////////////////////////////////////////////
    // Algorithm Support
    /////////////////////////////////////////////////////////////////////////////////////////////

    static class Algorithm implements Serializable
      {
        private static final long serialVersionUID = 1L;

        int mask;
        String jceName;
        byte[] pkcs1DigestInfo;
      }

    static LinkedHashMap<String,Algorithm> supportedAlgorithms = new LinkedHashMap<String,Algorithm> ();

    static Algorithm addAlgorithm (String uri, String jceName, int mask)
      {
        Algorithm alg = new Algorithm ();
        alg.mask = mask;
        alg.jceName = jceName;
        supportedAlgorithms.put (uri, alg);
        return alg;
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
    static final int ALG_HASH_384 = 0x00300000;
    static final int ALG_HASH_512 = 0x00400000;
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

        addAlgorithm ("http://xmlns.webpki.org/sks/algorithm#aes.cbc",
                      "AES/CBC/PKCS5Padding",
                      ALG_SYM_ENC | ALG_IV_REQ | ALG_SYML_128 | ALG_SYML_192 | ALG_SYML_256);

        //////////////////////////////////////////////////////////////////////////////////////
        //  HMAC Operations
        //////////////////////////////////////////////////////////////////////////////////////
        addAlgorithm ("http://www.w3.org/2000/09/xmldsig#hmac-sha1", "HmacSHA1", ALG_HMAC);

        addAlgorithm ("http://www.w3.org/2001/04/xmldsig-more#hmac-sha256", "HmacSHA256", ALG_HMAC);

        addAlgorithm ("http://www.w3.org/2001/04/xmldsig-more#hmac-sha384", "HmacSHA384", ALG_HMAC);

        addAlgorithm ("http://www.w3.org/2001/04/xmldsig-more#hmac-sha512", "HmacSHA512", ALG_HMAC);

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
                      ALG_ASYM_SGN | ALG_RSA_KEY | ALG_HASH_160).pkcs1DigestInfo =
                          new byte[]{0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02,
                                     0x1a, 0x05, 0x00, 0x04, 0x14};

        addAlgorithm ("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                      "NONEwithRSA",
                      ALG_ASYM_SGN | ALG_RSA_KEY | ALG_HASH_256).pkcs1DigestInfo =
                          new byte[]{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte)0x86, 0x48,
                                     0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};

       addAlgorithm ("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
                      "NONEwithRSA",
                       ALG_ASYM_SGN | ALG_RSA_KEY | ALG_HASH_384).pkcs1DigestInfo =
                           new byte[]{0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte)0x86, 0x48,
                                      0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30};

        addAlgorithm ("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
                      "NONEwithRSA",
                      ALG_ASYM_SGN | ALG_RSA_KEY | ALG_HASH_512).pkcs1DigestInfo =
                          new byte[]{0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte)0x86, 0x48,
                                     0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40};

        addAlgorithm ("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
                      "NONEwithECDSA",
                      ALG_ASYM_SGN | ALG_EC_KEY | ALG_HASH_256);

        addAlgorithm ("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
                      "NONEwithECDSA",
                      ALG_ASYM_SGN | ALG_EC_KEY | ALG_HASH_384);

        addAlgorithm ("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512",
                      "NONEwithECDSA",
                      ALG_ASYM_SGN | ALG_EC_KEY | ALG_HASH_512);

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

        addAlgorithm ("http://xmlns.webpki.org/sks/algorithm#ec.nist.p384",
                      "secp384r1",
                      ALG_EC_KEY | ALG_KEY_GEN);

        addAlgorithm ("http://xmlns.webpki.org/sks/algorithm#ec.nist.p521",
                      "secp521r1",
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
    static LinkedHashMap<String,EllipticCurve> supported_ecKeyAlgorithms = new LinkedHashMap<String,EllipticCurve> ();
    
    static void addECKeyAlgorithm (String jceName, byte[] samplePublicKey)
      {
        try
          {
            supported_ecKeyAlgorithms.put (jceName,
                                             ((ECPublicKey) KeyFactory.getInstance ("EC").generatePublic (
                new X509EncodedKeySpec (samplePublicKey))).getParams ().getCurve ());
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

    X509Certificate[] getDeviceCertificatePath () throws GeneralSecurityException
      {
        return new X509Certificate[]{deviceCertificate};
      }
    
    byte[] getDeviceID (boolean privacy_enabled) throws GeneralSecurityException
      {
        return privacy_enabled ? KDF_ANONYMOUS : getDeviceCertificatePath ()[0].getEncoded ();
      }

    PrivateKey getAttestationKey () throws GeneralSecurityException
      {
        return attestationKey;        
      }

    void logCertificateOperation (KeyEntry keyEntry, String operation)
      {
        Log.i (SKS_DEBUG, certificateLogData (keyEntry) + " " + operation);
      }

    String certificateLogData (KeyEntry keyEntry)
      {
        return "Certificate for '" + keyEntry.certificatePath[0].getSubjectX500Principal ().getName () + "' Serial=" + keyEntry.certificatePath[0].getSerialNumber ();
      }

    Provisioning getProvisioningSession (int provisioningHandle) throws SKSException
      {
        Provisioning provisioning = provisionings.get (provisioningHandle);
        if (provisioning == null)
          {
            abort ("No such provisioning session: " + provisioningHandle, SKSException.ERROR_NO_SESSION);
          }
        return provisioning;
      }

    Provisioning getOpenProvisioningSession (int provisioningHandle) throws SKSException
      {
        Provisioning provisioning = getProvisioningSession (provisioningHandle);
        if (!provisioning.open)
          {
            abort ("Session not open: " +  provisioningHandle, SKSException.ERROR_NO_SESSION);
          }
        return provisioning;
      }

    Provisioning getClosedProvisioningSession (int provisioningHandle) throws SKSException
      {
        Provisioning provisioning = getProvisioningSession (provisioningHandle);
        if (provisioning.open)
          {
            abort ("Session is open: " +  provisioningHandle, SKSException.ERROR_NOT_ALLOWED);
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
    
    KeyEntry getOpenKey (int keyHandle) throws SKSException
      {
        KeyEntry keyEntry = keys.get (keyHandle);
        if (keyEntry == null)
          {
            abort ("Key not found #" + keyHandle, SKSException.ERROR_NO_KEY);
          }
        if (!keyEntry.owner.open)
          {
            abort ("Key #" + keyHandle + " not belonging to open session", SKSException.ERROR_NO_KEY);
          }
        return keyEntry;
      }

    KeyEntry getStdKey (int keyHandle) throws SKSException
      {
        KeyEntry keyEntry = keys.get (keyHandle);
        if (keyEntry == null)
          {
            abort ("Key not found #" + keyHandle, SKSException.ERROR_NO_KEY);
          }
        if (keyEntry.owner.open)
          {
            abort ("Key #" + keyHandle + " still in provisioning", SKSException.ERROR_NO_KEY);
          }
        return keyEntry;
      }

    EnumeratedKey getKey (Iterator<KeyEntry> iter)
      {
        while (iter.hasNext ())
          {
            KeyEntry keyEntry = iter.next ();
            if (!keyEntry.owner.open)
              {
                return new EnumeratedKey (keyEntry.keyHandle, keyEntry.owner.provisioningHandle);
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
                return new EnumeratedProvisioningSession (provisioning.provisioningHandle,
                                                          ALGORITHM_SESSION_ATTEST_1,
                                                          provisioning.privacy_enabled,
                                                          provisioning.key_managementKey,
                                                          provisioning.client_time,
                                                          provisioning.sessionLife_time,
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

    String checkECKeyCompatibility (ECKey ecKey, SKSError sks_error, String key_id) throws SKSException
      {
        for (String jceName : supported_ecKeyAlgorithms.keySet ())
          {
            if (ecKey.getParams ().getCurve ().equals (supported_ecKeyAlgorithms.get (jceName)))
              {
                return jceName;
              }
          }
        sks_error.abort ("Unsupported EC key algorithm for: " + key_id);
        return null;
      }

    void checkRSAKeyCompatibility (int rsaKey_size, BigInteger exponent, SKSError sks_error, String key_id) throws SKSException
      {
        if (!SKS_RSA_EXPONENT_SUPPORT && !exponent.equals (RSAKeyGenParameterSpec.F4))
          {
            sks_error.abort ("Unsupported RSA exponent value for: " + key_id);
          }
        boolean found = false;
        for (short key_size : SKS_DEFAULT_RSA_SUPPORT)
          {
            if (key_size == rsaKey_size)
              {
                found = true;
                break;
              }
          }
        if (!found)
          {
            sks_error.abort ("Unsupported RSA key size " + rsaKey_size + " for: " + key_id);
          }
      }

    int getRSAKeySize (RSAKey rsaKey)
      {
        byte[] modblob = rsaKey.getModulus ().toByteArray ();
        return (modblob[0] == 0 ? modblob.length - 1 : modblob.length) * 8;
      }

    @SuppressWarnings("fallthrough")
    void verifyPINPolicyCompliance (boolean forced_setter, byte[] pinValue, PINPolicy pinPolicy, byte appUsage, SKSError sks_error) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Check PIN length
        ///////////////////////////////////////////////////////////////////////////////////
        if (pinValue.length > pinPolicy.maxLength || pinValue.length < pinPolicy.minLength)
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
        for (int i = 0; i < pinValue.length; i++)
          {
            int c = pinValue[i];
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
        if ((pinPolicy.format == PASSPHRASE_FORMAT_NUMERIC && (loweralpha || nonalphanum || upperalpha)) ||
            (pinPolicy.format == PASSPHRASE_FORMAT_ALPHANUMERIC && (loweralpha || nonalphanum)))
          {
            sks_error.abort ("PIN syntax error");
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Check PIN patterns
        ///////////////////////////////////////////////////////////////////////////////////
        if ((pinPolicy.patternRestrictions & PIN_PATTERN_MISSING_GROUP) != 0)
          {
            if (!upperalpha || !number ||
                (pinPolicy.format == PASSPHRASE_FORMAT_STRING && (!loweralpha || !nonalphanum)))
              {
                sks_error.abort ("Missing character group in PIN");
              }
          }
        if ((pinPolicy.patternRestrictions & PIN_PATTERN_SEQUENCE) != 0)
          {
            byte c = pinValue[0];
            byte f = (byte)(pinValue[1] - c);
            boolean seq = (f == 1) || (f == -1);
            for (int i = 1; i < pinValue.length; i++)
              {
                if ((byte)(c + f) != pinValue[i])
                  {
                    seq = false;
                    break;
                  }
                c = pinValue[i];
              }
            if (seq)
              {
                sks_error.abort ("PIN must not be a sequence");
              }
          }
        if ((pinPolicy.patternRestrictions & PIN_PATTERN_REPEATED) != 0)
          {
            for (int i = 0; i < pinValue.length; i++)
              {
                byte b = pinValue[i];
                for (int j = 0; j < pinValue.length; j++)
                  {
                    if (j != i && b == pinValue[j])
                      {
                        sks_error.abort ("Repeated PIN character");
                      }
                  }
              }
          }
        if ((pinPolicy.patternRestrictions & (PIN_PATTERN_TWO_IN_A_ROW | PIN_PATTERN_THREE_IN_A_ROW)) != 0)
          {
            int max = ((pinPolicy.patternRestrictions & PIN_PATTERN_TWO_IN_A_ROW) == 0) ? 3 : 2;
            byte c = pinValue [0];
            int sameCount = 1;
            for (int i = 1; i < pinValue.length; i++)
              {
                if (c == pinValue[i])
                  {
                    if (++sameCount == max)
                      {
                        sks_error.abort ("PIN with " + max + " or more of same the character in a row");
                      }
                  }
                else
                  {
                    sameCount = 1;
                    c = pinValue[i];
                  }
              }
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Check that PIN grouping rules are followed
        ///////////////////////////////////////////////////////////////////////////////////
        for (KeyEntry keyEntry : keys.values ())
          {
            if (keyEntry.pinPolicy == pinPolicy)
              {
                boolean equal = Arrays.equals (keyEntry.pinValue, pinValue);
                if (forced_setter && !equal)
                  {
                    continue;
                  }
                switch (pinPolicy.grouping)
                  {
                    case PIN_GROUPING_SHARED:
                      if (!equal)
                        {
                          sks_error.abort ("Grouping = \"shared\" requires identical PINs");
                        }
                      continue;

                    case PIN_GROUPING_UNIQUE:
                      if (equal ^ (appUsage == keyEntry.appUsage))
                        {
                          sks_error.abort ("Grouping = \"unique\" PIN error");
                        }
                      continue;

                    case PIN_GROUPING_SIGN_PLUS_STD:
                      if (((appUsage == APP_USAGE_SIGNATURE) ^ (keyEntry.appUsage == APP_USAGE_SIGNATURE)) ^ !equal)
                        {
                          sks_error.abort ("Grouping = \"signature+standard\" PIN error");
                        }
                  }
              }
          }
      }
    
    void testUpdatablePIN (KeyEntry keyEntry, byte[] newPin) throws SKSException
      {
        if (!keyEntry.pinPolicy.userModifiable)
          {
            abort ("PIN for key #" + keyEntry.keyHandle + " is not user modifiable", SKSException.ERROR_NOT_ALLOWED);
          }
        verifyPINPolicyCompliance (true, newPin, keyEntry.pinPolicy, keyEntry.appUsage, this);
      }
    
    void deleteEmptySession (Provisioning provisioning)
      {
        for (KeyEntry keyEntry : keys.values ())
          {
            if (keyEntry.owner == provisioning)
              {
                return;
              }
          }
        provisionings.remove (provisioning.provisioningHandle);
      }

    void localDeleteKey (KeyEntry keyEntry)
      {
        keys.remove (keyEntry.keyHandle);
        if (keyEntry.pinPolicy != null)
          {
            int pinPolicyHandle = keyEntry.pinPolicy.pinPolicyHandle;
            for (int handle : keys.keySet ())
              {
                if (handle == pinPolicyHandle)
                  {
                    return;
                  }
              }
            pinPolicies.remove (pinPolicyHandle);
            if (keyEntry.pinPolicy.pukPolicy != null)
              {
                int pukPolicyHandle = keyEntry.pinPolicy.pukPolicy.pukPolicyHandle;
                for (int handle : pinPolicies.keySet ())
                  {
                    if (handle == pukPolicyHandle)
                      {
                        return;
                      }
                  }
                pukPolicies.remove (pukPolicyHandle);
              }
          }
      }

    Algorithm checkKeyAndAlgorithm (KeyEntry keyEntry, String inputAlgorithm, int expected_type) throws SKSException
      {
        Algorithm alg = getAlgorithm (inputAlgorithm);
        if ((alg.mask & expected_type) == 0)
          {
            abort ("Algorithm does not match operation: " + inputAlgorithm, SKSException.ERROR_ALGORITHM);
          }
        if (((alg.mask & (ALG_SYM_ENC | ALG_HMAC)) != 0) ^ keyEntry.isSymmetric ())
          {
            abort ((keyEntry.isSymmetric () ? "S" : "As") + "ymmetric key #" + keyEntry.keyHandle + " is incompatible with: " + inputAlgorithm, SKSException.ERROR_ALGORITHM);
          }
        if (keyEntry.isSymmetric ())
          {
            testAESKey (inputAlgorithm, keyEntry.symmetricKey, "#" + keyEntry.keyHandle, this);
          }
        else if (keyEntry.isRSA () ^ (alg.mask & ALG_RSA_KEY) != 0)
          {
            abort ((keyEntry.isRSA () ? "RSA" : "EC") + " key #" + keyEntry.keyHandle + " is incompatible with: " + inputAlgorithm, SKSException.ERROR_ALGORITHM);
          }
        if (keyEntry.endorsedAlgorithms.isEmpty () || keyEntry.endorsedAlgorithms.contains (inputAlgorithm))
          {
            return alg;
          }
        abort ("\"EndorsedAlgorithms\" for key #" + keyEntry.keyHandle + " does not include: " + inputAlgorithm, SKSException.ERROR_ALGORITHM);
        return null;    // For the compiler only...
      }

    byte[] addArrays (byte[] a, byte[] b)
      {
        byte[] r = new byte[a.length + b.length];
        System.arraycopy (a, 0, r, 0, a.length);
        System.arraycopy (b, 0, r, a.length, b.length);
        return r;
      }

    void testAESKey (String algorithm, byte[] symmetricKey, String key_id, SKSError sks_error) throws SKSException
      {
        Algorithm alg = getAlgorithm (algorithm);
        if ((alg.mask & ALG_SYM_ENC) != 0)
          {
            int l = symmetricKey.length;
            if (l == 16) l = ALG_SYML_128;
            else if (l == 24) l = ALG_SYML_192;
            else if (l == 32) l = ALG_SYML_256;
            else l = 0;
            if ((l & alg.mask) == 0)
              {
                sks_error.abort ("Key " + key_id + " has wrong size (" + symmetricKey.length + ") for algorithm: " + algorithm);
              }
          }
      }

    Algorithm getAlgorithm (String algorithm_uri) throws SKSException
      {
        Algorithm alg = supportedAlgorithms.get (algorithm_uri);
        if (alg == null)
          {
            abort ("Unsupported algorithm: " + algorithm_uri, SKSException.ERROR_ALGORITHM);
          }
        return alg;
      }

    void verifyExportDeleteProtection (byte actualProtection, byte minProtection_val, Provisioning provisioning) throws SKSException
      {
        if (actualProtection >= minProtection_val && actualProtection <= EXPORT_DELETE_PROTECTION_PUK)
          {
            provisioning.abort ("Protection object lacks a PIN or PUK object");
          }
      }

    void addUpdateKeyOrCloneKeyProtection (int keyHandle,
                                           int targetKeyHandle,
                                           byte[] authorization,
                                           byte[] mac,
                                           boolean update) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get open key and associated provisioning session
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry newKey = getOpenKey (keyHandle);
        Provisioning provisioning = newKey.owner;

        ///////////////////////////////////////////////////////////////////////////////////
        // Get key to be updated/cloned
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry targetKey_entry = provisioning.getTargetKey (targetKeyHandle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Perform some "sanity" tests
        ///////////////////////////////////////////////////////////////////////////////////
        if (newKey.pinPolicy != null || newKey.devicePinProtection)
          {
            provisioning.abort ("Updated/cloned keys must not define PIN protection");
          }
        if (update)
          {
            if (targetKey_entry.appUsage != newKey.appUsage)
              {
                provisioning.abort ("Updated keys must have the same \"AppUsage\" as the target key");
              }
          }
        else
          {
            ///////////////////////////////////////////////////////////////////////////////////
            // Cloned keys must share the PIN of its parent
            ///////////////////////////////////////////////////////////////////////////////////
            if (targetKey_entry.pinPolicy != null && targetKey_entry.pinPolicy.grouping != PIN_GROUPING_SHARED)
              {
                provisioning.abort ("A cloned key protection must have PIN grouping=\"shared\"");
              }
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify incoming MAC and target key data
        ///////////////////////////////////////////////////////////////////////////////////
        MacBuilder verifier = newKey.getEECertMacBuilder (update ? METHOD_POST_UPDATE_KEY : METHOD_POST_CLONE_KEY_PROTECTION);
        targetKey_entry.validateTargetKeyReference (verifier, mac, authorization, provisioning);

        ///////////////////////////////////////////////////////////////////////////////////
        // Put the operation in the post-op buffer used by "closeProvisioningSession"
        ///////////////////////////////////////////////////////////////////////////////////
        logCertificateOperation (targetKey_entry, update ? "post-updated" : "post-cloned");
        provisioning.addPostProvisioningObject (targetKey_entry, newKey, update);
      }

    void addUnlockKeyOrDeleteKey (int provisioningHandle,
                                  int targetKeyHandle,
                                  byte[] authorization,
                                  byte[] mac,
                                  boolean delete) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get provisioning session
        ///////////////////////////////////////////////////////////////////////////////////
        Provisioning provisioning = getOpenProvisioningSession (provisioningHandle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Get key to be deleted or unlocked
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry targetKey_entry = provisioning.getTargetKey (targetKeyHandle);
        if (!delete && targetKey_entry.pinPolicy == null)
          {
            provisioning.abort ("Key #" + targetKeyHandle + " is not PIN protected");
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify incoming MAC and target key data
        ///////////////////////////////////////////////////////////////////////////////////
        MacBuilder verifier = provisioning.getMacBuilderForMethodCall (delete ? METHOD_POST_DELETE_KEY : METHOD_POST_UNLOCK_KEY);
        targetKey_entry.validateTargetKeyReference (verifier, mac, authorization, provisioning);

        ///////////////////////////////////////////////////////////////////////////////////
        // Put the operation in the post-op buffer used by "closeProvisioningSession"
        ///////////////////////////////////////////////////////////////////////////////////
        logCertificateOperation (targetKey_entry, delete ? "post-deleted" : "post-unlocked");
        provisioning.addPostProvisioningObject (targetKey_entry, null, delete);
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
    public synchronized void unlockKey (int keyHandle, byte[] authorization) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key (which must belong to an already fully provisioned session)
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry keyEntry = getStdKey (keyHandle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify PUK
        ///////////////////////////////////////////////////////////////////////////////////
        keyEntry.verifyPUK (authorization);

        ///////////////////////////////////////////////////////////////////////////////////
        // Success!  Reset PIN error counter(s)
        ///////////////////////////////////////////////////////////////////////////////////
        keyEntry.setErrorCounter ((short)0);
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                               changePIN                                    //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized void changePin (int keyHandle, 
                                        byte[] authorization,
                                        byte[] newPin) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key (which must belong to an already fully provisioned session)
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry keyEntry = getStdKey (keyHandle);
        
        ///////////////////////////////////////////////////////////////////////////////////
        // Verify old PIN
        ///////////////////////////////////////////////////////////////////////////////////
        keyEntry.verifyPIN (authorization);

        ///////////////////////////////////////////////////////////////////////////////////
        // Test new PIN
        ///////////////////////////////////////////////////////////////////////////////////
        testUpdatablePIN (keyEntry, newPin);

        ///////////////////////////////////////////////////////////////////////////////////
        // Success!  Set PIN value(s)
        ///////////////////////////////////////////////////////////////////////////////////
        keyEntry.updatePIN (newPin);
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                                 setPIN                                     //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized void setPin (int keyHandle,
                                     byte[] authorization,
                                     byte[] newPin) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key (which must belong to an already fully provisioned session)
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry keyEntry = getStdKey (keyHandle);
        
        ///////////////////////////////////////////////////////////////////////////////////
        // Verify PUK
        ///////////////////////////////////////////////////////////////////////////////////
        keyEntry.verifyPUK (authorization);

        ///////////////////////////////////////////////////////////////////////////////////
        // Test new PIN
        ///////////////////////////////////////////////////////////////////////////////////
        testUpdatablePIN (keyEntry, newPin);

        ///////////////////////////////////////////////////////////////////////////////////
        // Success!  Set PIN value(s) and unlock associated key(s)
        ///////////////////////////////////////////////////////////////////////////////////
        keyEntry.updatePIN (newPin);
        keyEntry.setErrorCounter ((short)0);
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                               deleteKey                                    //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized void deleteKey (int keyHandle, byte[] authorization) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key (which must belong to an already fully provisioned session)
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry keyEntry = getStdKey (keyHandle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Check that authorization matches the declaration
        ///////////////////////////////////////////////////////////////////////////////////
        keyEntry.authorizeExportOrDeleteOperation (keyEntry.deleteProtection, authorization);

        ///////////////////////////////////////////////////////////////////////////////////
        // Delete key and optionally the entire provisioning object (if empty)
        ///////////////////////////////////////////////////////////////////////////////////
        localDeleteKey (keyEntry);
        deleteEmptySession (keyEntry.owner);
      }

    
    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                               exportKey                                    //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized byte[] exportKey (int keyHandle, byte[] authorization) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key (which must belong to an already fully provisioned session)
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry keyEntry = getStdKey (keyHandle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Check that authorization matches the declaration
        ///////////////////////////////////////////////////////////////////////////////////
        keyEntry.authorizeExportOrDeleteOperation (keyEntry.exportProtection, authorization);

        ///////////////////////////////////////////////////////////////////////////////////
        // Mark as "copied" locally
        ///////////////////////////////////////////////////////////////////////////////////
        keyEntry.keyBackup |= KeyProtectionInfo.KEYBACKUP_EXPORTED;

        ///////////////////////////////////////////////////////////////////////////////////
        // Export key in raw unencrypted format
        ///////////////////////////////////////////////////////////////////////////////////
        return keyEntry.isSymmetric () ? keyEntry.symmetricKey : keyEntry.privateKey.getEncoded ();
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                              setProperty                                   //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized void setProperty (int keyHandle,
                                          String type,
                                          String name,
                                          String value) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key (which must belong to an already fully provisioned session)
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry keyEntry = getStdKey (keyHandle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Lookup the extension(s) bound to the key
        ///////////////////////////////////////////////////////////////////////////////////
        ExtObject ext_obj = keyEntry.extensions.get (type);
        if (ext_obj == null || ext_obj.sub_type != SUB_TYPE_PROPERTY_BAG)
          {
            abort ("No such \"PropertyBag\" : " + type);
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Found, now look for the property name and update the associated value
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] binName = getBinary (name);
        byte[] binValue = getBinary (value);
        int i = 0;
        while (i < ext_obj.extensionData.length)
          {
            int namLen = getShort (ext_obj.extensionData, i);
            i += 2;
            byte[] pname = Arrays.copyOfRange (ext_obj.extensionData, i, namLen + i);
            i += namLen;
            int valLen = getShort (ext_obj.extensionData, i + 1);
            if (Arrays.equals (binName, pname))
              {
                if (ext_obj.extensionData[i] != 0x01)
                  {
                    abort ("\"Property\" not writable: " + name, SKSException.ERROR_NOT_ALLOWED);
                  }
                ext_obj.extensionData = addArrays (addArrays (Arrays.copyOfRange (ext_obj.extensionData, 0, ++i),
                                                               addArrays (new byte[]{(byte)(binValue.length >> 8),(byte)binValue.length}, binValue)),
                                                    Arrays.copyOfRange (ext_obj.extensionData, i + valLen + 2, ext_obj.extensionData.length));
                return;
              }
            i += valLen + 3;
          }
        abort ("\"Property\" not found: " + name);
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                              getExtension                                  //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized Extension getExtension (int keyHandle, String type) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key (which must belong to an already fully provisioned session)
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry keyEntry = getStdKey (keyHandle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Lookup the extension(s) bound to the key
        ///////////////////////////////////////////////////////////////////////////////////
        ExtObject ext_obj = keyEntry.extensions.get (type);
        if (ext_obj == null)
          {
            abort ("No such extension: " + type + " for key #" + keyHandle);
          }
        return new Extension (ext_obj.sub_type, ext_obj.qualifier, ext_obj.extensionData);
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                         asymmetricKeyDecrypt                               //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized byte[] asymmetricKeyDecrypt (int keyHandle,
                                                     String algorithm,
                                                     byte[] parameters,
                                                     byte[] authorization,
                                                     byte[] data) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key (which must belong to an already fully provisioned session)
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry keyEntry = getStdKey (keyHandle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify PIN (in any)
        ///////////////////////////////////////////////////////////////////////////////////
        keyEntry.verifyPIN (authorization);

        ///////////////////////////////////////////////////////////////////////////////////
        // Check that the encryption algorithm is known and applicable
        ///////////////////////////////////////////////////////////////////////////////////
        Algorithm alg = checkKeyAndAlgorithm (keyEntry, algorithm, ALG_ASYM_ENC);
        if (parameters != null)  // Only support basic RSA yet...
          {
            abort ("\"Parameters\" for key #" + keyHandle + " do not match algorithm");
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Finally, perform operation
        ///////////////////////////////////////////////////////////////////////////////////
        try
          {
            Cipher cipher = Cipher.getInstance (alg.jceName);
            cipher.init (Cipher.DECRYPT_MODE, keyEntry.privateKey);
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
    public synchronized byte[] signHashedData (int keyHandle,
                                               String algorithm,
                                               byte[] parameters,
                                               byte[] authorization,
                                               byte[] data) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key (which must belong to an already fully provisioned session)
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry keyEntry = getStdKey (keyHandle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify PIN (in any)
        ///////////////////////////////////////////////////////////////////////////////////
        keyEntry.verifyPIN (authorization);

        ///////////////////////////////////////////////////////////////////////////////////
        // Enforce the data limit
        ///////////////////////////////////////////////////////////////////////////////////
        keyEntry.checkCryptoDataSize (data);

        ///////////////////////////////////////////////////////////////////////////////////
        // Check that the signature algorithm is known and applicable
        ///////////////////////////////////////////////////////////////////////////////////
        Algorithm alg = checkKeyAndAlgorithm (keyEntry, algorithm, ALG_ASYM_SGN);
        int hashLen = (alg.mask / ALG_HASH_DIV) & ALG_HASH_MSK;
        if (hashLen > 0 && hashLen != data.length)
          {
            abort ("Incorrect length of \"Data\": " + data.length);
          }
        if (parameters != null)  // Only supports non-parameterized operations yet...
          {
            abort ("\"Parameters\" for key #" + keyHandle + " do not match algorithm");
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Finally, perform operation
        ///////////////////////////////////////////////////////////////////////////////////
        try
          {
            if (keyEntry.isRSA () && hashLen > 0)
              {
                data = addArrays (alg.pkcs1DigestInfo, data);
              }
            Signature signature = Signature.getInstance (alg.jceName);
            signature.initSign (keyEntry.privateKey);
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
    public synchronized byte[] keyAgreement (int keyHandle, 
                                             String algorithm,
                                             byte[] parameters,
                                             byte[] authorization,
                                             ECPublicKey publicKey) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key (which must belong to an already fully provisioned session)
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry keyEntry = getStdKey (keyHandle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify PIN (in any)
        ///////////////////////////////////////////////////////////////////////////////////
        keyEntry.verifyPIN (authorization);

        ///////////////////////////////////////////////////////////////////////////////////
        // Check that the key agreement algorithm is known and applicable
        ///////////////////////////////////////////////////////////////////////////////////
        Algorithm alg = checkKeyAndAlgorithm (keyEntry, algorithm, ALG_ASYM_KA);
        if (parameters != null)  // Only support external KDFs yet...
          {
            abort ("\"Parameters\" for key #" + keyHandle + " do not match algorithm");
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Check that the key type matches the algorithm
        ///////////////////////////////////////////////////////////////////////////////////
        checkECKeyCompatibility (publicKey, this, "\"PublicKey\"");

        ///////////////////////////////////////////////////////////////////////////////////
        // Finally, perform operation
        ///////////////////////////////////////////////////////////////////////////////////
        try
          {
            KeyAgreement key_agreement = KeyAgreement.getInstance (alg.jceName);
            key_agreement.init (keyEntry.privateKey);
            key_agreement.doPhase (publicKey, true);
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
    public synchronized byte[] symmetricKeyEncrypt (int keyHandle,
                                                    String algorithm,
                                                    boolean mode,
                                                    byte[] parameters,
                                                    byte[] authorization,
                                                    byte[] data) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key (which must belong to an already fully provisioned session)
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry keyEntry = getStdKey (keyHandle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify PIN (in any)
        ///////////////////////////////////////////////////////////////////////////////////
        keyEntry.verifyPIN (authorization);

        ///////////////////////////////////////////////////////////////////////////////////
        // Enforce the data limit
        ///////////////////////////////////////////////////////////////////////////////////
        keyEntry.checkCryptoDataSize (data);

        ///////////////////////////////////////////////////////////////////////////////////
        // Check the key and then check that the algorithm is known and applicable
        ///////////////////////////////////////////////////////////////////////////////////
        Algorithm alg = checkKeyAndAlgorithm (keyEntry, algorithm, ALG_SYM_ENC);
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
            Cipher crypt = Cipher.getInstance (alg.jceName);
            SecretKeySpec sk = new SecretKeySpec (keyEntry.symmetricKey, "AES");
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
    public synchronized byte[] performHmac (int keyHandle,
                                            String algorithm,
                                            byte[] parameters,
                                            byte[] authorization,
                                            byte[] data) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key (which must belong to an already fully provisioned session)
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry keyEntry = getStdKey (keyHandle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify PIN (in any)
        ///////////////////////////////////////////////////////////////////////////////////
        keyEntry.verifyPIN (authorization);

        ///////////////////////////////////////////////////////////////////////////////////
        // Enforce the data limit
        ///////////////////////////////////////////////////////////////////////////////////
        keyEntry.checkCryptoDataSize (data);

        ///////////////////////////////////////////////////////////////////////////////////
        // Check the key and then check that the algorithm is known and applicable
        ///////////////////////////////////////////////////////////////////////////////////
        Algorithm alg = checkKeyAndAlgorithm (keyEntry, algorithm, ALG_HMAC);
        if (parameters != null)
          {
            abort ("\"Parameters\" does not apply to: " + algorithm);
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Finally, perform operation
        ///////////////////////////////////////////////////////////////////////////////////
        try
          {
            Mac mac = Mac.getInstance (alg.jceName);
            mac.init (new SecretKeySpec (keyEntry.symmetricKey, "RAW"));
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
                                   supportedAlgorithms.keySet ().toArray (new String[0]),
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
    public synchronized EnumeratedKey enumerateKeys (int keyHandle) throws SKSException
      {
        if (keyHandle == EnumeratedKey.INIT_ENUMERATION)
          {
            return getKey (keys.values ().iterator ());
          }
        Iterator<KeyEntry> list = keys.values ().iterator ();
        while (list.hasNext ())
          {
            if (list.next ().keyHandle == keyHandle)
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
    public synchronized KeyProtectionInfo getKeyProtectionInfo (int keyHandle) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key (which must belong to an already fully provisioned session)
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry keyEntry = getStdKey (keyHandle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Find the protection data objects that are not stored in the key entry
        ///////////////////////////////////////////////////////////////////////////////////
        byte protection_status = KeyProtectionInfo.PROTSTAT_NO_PIN;
        byte puk_format = 0;
        short puk_retryLimit = 0;
        short puk_errorCount = 0;
        boolean userDefined = false;
        boolean userModifiable = false;
        byte format = 0;
        short retryLimit = 0;
        byte grouping = 0;
        byte patternRestrictions = 0;
        short minLength = 0;
        short maxLength = 0;
        byte inputMethod = 0;
        if (keyEntry.devicePinProtection)
          {
            protection_status = KeyProtectionInfo.PROTSTAT_DEVICE_PIN;
          }
        else if (keyEntry.pinPolicy != null)
          {
            protection_status = KeyProtectionInfo.PROTSTAT_PIN_PROTECTED;
            if (keyEntry.errorCount >= keyEntry.pinPolicy.retryLimit)
              {
                protection_status |= KeyProtectionInfo.PROTSTAT_PIN_BLOCKED;
              }
            if (keyEntry.pinPolicy.pukPolicy != null)
              {
                puk_format = keyEntry.pinPolicy.pukPolicy.format; 
                puk_retryLimit = keyEntry.pinPolicy.pukPolicy.retryLimit;
                puk_errorCount = keyEntry.pinPolicy.pukPolicy.errorCount;
                protection_status |= KeyProtectionInfo.PROTSTAT_PUK_PROTECTED;
                if (keyEntry.pinPolicy.pukPolicy.errorCount >= keyEntry.pinPolicy.pukPolicy.retryLimit &&
                    keyEntry.pinPolicy.pukPolicy.retryLimit > 0)
                  {
                    protection_status |= KeyProtectionInfo.PROTSTAT_PUK_BLOCKED;
                  }
              }
            userDefined = keyEntry.pinPolicy.userDefined;
            userModifiable = keyEntry.pinPolicy.userModifiable;
            format = keyEntry.pinPolicy.format;
            retryLimit = keyEntry.pinPolicy.retryLimit;
            grouping = keyEntry.pinPolicy.grouping;
            patternRestrictions = keyEntry.pinPolicy.patternRestrictions;
            minLength = keyEntry.pinPolicy.minLength;
            maxLength = keyEntry.pinPolicy.maxLength;
            inputMethod = keyEntry.pinPolicy.inputMethod;
          }
        return new KeyProtectionInfo (protection_status,
                                      puk_format,
                                      puk_retryLimit,
                                      puk_errorCount,
                                      userDefined,
                                      userModifiable,
                                      format,
                                      retryLimit,
                                      grouping,
                                      patternRestrictions,
                                      minLength,
                                      maxLength,
                                      inputMethod,
                                      keyEntry.errorCount,
                                      keyEntry.enablePinCaching,
                                      keyEntry.biometricProtection,
                                      keyEntry.exportProtection,
                                      keyEntry.deleteProtection,
                                      keyEntry.keyBackup);
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                            getKeyAttributes                                //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized KeyAttributes getKeyAttributes (int keyHandle) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key (which must belong to an already fully provisioned session)
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry keyEntry = getStdKey (keyHandle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Return core key entry metadata
        ///////////////////////////////////////////////////////////////////////////////////
        return new KeyAttributes ((short)(keyEntry.isSymmetric () ? keyEntry.symmetricKey.length : 0),
                                  keyEntry.certificatePath,
                                  keyEntry.appUsage,
                                  keyEntry.friendlyName,
                                  keyEntry.endorsedAlgorithms.toArray (new String[0]),
                                  keyEntry.extensions.keySet ().toArray (new String[0]));
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                           updateKeyManagementKey                           //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public void updateKeyManagementKey (int provisioningHandle,
                                        PublicKey key_managementKey,
                                        byte[] authorization) throws SKSException
      {
        Provisioning provisioning = getClosedProvisioningSession (provisioningHandle);
        if (provisioning.key_managementKey == null)
          {
            abort ("Session is not updatable: " +  provisioningHandle, SKSException.ERROR_NOT_ALLOWED);
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify KMK signature
        ///////////////////////////////////////////////////////////////////////////////////
        try
          {
            if (!provisioning.verifyKeyManagementKeyAuthorization (KMK_ROLL_OVER_AUTHORIZATION,
                                                                   key_managementKey.getEncoded (),
                                                                   authorization))
              {
                abort ("\"Authorization\" signature did not verify for session: " + provisioningHandle);
              }

            ///////////////////////////////////////////////////////////////////////////////////
            // Success, update KeyManagementKey
            ///////////////////////////////////////////////////////////////////////////////////
            provisioning.key_managementKey = key_managementKey;
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
    public synchronized EnumeratedProvisioningSession enumerateProvisioningSessions (int provisioningHandle,
                                                                                     boolean provisioning_state) throws SKSException
      {
        if (provisioningHandle == EnumeratedProvisioningSession.INIT_ENUMERATION)
          {
            return getProvisioning (provisionings.values ().iterator (), provisioning_state);
          }
        Iterator<Provisioning> list = provisionings.values ().iterator ();
        while (list.hasNext ())
          {
            if (list.next ().provisioningHandle == provisioningHandle)
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
    public synchronized byte[] signProvisioningSessionData (int provisioningHandle, byte[] data) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get provisioning session
        ///////////////////////////////////////////////////////////////////////////////////
        Provisioning provisioning = getOpenProvisioningSession (provisioningHandle);

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
    public synchronized int getKeyHandle (int provisioningHandle, String id) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get provisioning session
        ///////////////////////////////////////////////////////////////////////////////////
        Provisioning provisioning = getOpenProvisioningSession (provisioningHandle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Look for key with virtual ID
        ///////////////////////////////////////////////////////////////////////////////////
        for (KeyEntry keyEntry : keys.values ())
          {
            if (keyEntry.owner == provisioning && keyEntry.id.equals (id))
              {
                return keyEntry.keyHandle;
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
    public synchronized void postDeleteKey (int provisioningHandle,
                                            int targetKeyHandle,
                                            byte[] authorization,
                                            byte[] mac) throws SKSException
      {
        addUnlockKeyOrDeleteKey (provisioningHandle, targetKeyHandle, authorization, mac, true);
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                             postUnlockKey                                  //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized void postUnlockKey (int provisioningHandle,
                                            int targetKeyHandle,
                                            byte[] authorization,
                                            byte[] mac) throws SKSException
      {
        addUnlockKeyOrDeleteKey (provisioningHandle, targetKeyHandle, authorization, mac, false);
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                          postCloneKeyProtection                            //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized void postCloneKeyProtection (int keyHandle,
                                                     int targetKeyHandle,
                                                     byte[] authorization,
                                                     byte[] mac) throws SKSException
      {
        addUpdateKeyOrCloneKeyProtection (keyHandle, targetKeyHandle, authorization, mac, false);
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                              postUpdateKey                                 //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized void postUpdateKey (int keyHandle,
                                            int targetKeyHandle,
                                            byte[] authorization,
                                            byte[] mac) throws SKSException
      {
        addUpdateKeyOrCloneKeyProtection (keyHandle, targetKeyHandle, authorization, mac, true);
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                         abortProvisioningSession                           //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized void abortProvisioningSession (int provisioningHandle) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get provisioning session
        ///////////////////////////////////////////////////////////////////////////////////
        Provisioning provisioning = getOpenProvisioningSession (provisioningHandle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Wind it down
        ///////////////////////////////////////////////////////////////////////////////////
        deleteObject (keys, provisioning);
        deleteObject (pinPolicies, provisioning);
        deleteObject (pukPolicies, provisioning);
        provisionings.remove (provisioningHandle);
        Log.e (SKS_DEBUG, "Session ABORTED");
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                        closeProvisioningSession                            //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized byte[] closeProvisioningSession (int provisioningHandle,
                                                         byte[] nonce,
                                                         byte[] mac) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get provisioning session
        ///////////////////////////////////////////////////////////////////////////////////
        Provisioning provisioning = getOpenProvisioningSession (provisioningHandle);

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
        close_attestation.addArray (nonce);
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
        for (KeyEntry keyEntry : keys.values ())
          {
            if (keyEntry.owner == provisioning)
              {
                ///////////////////////////////////////////////////////////////////////////////////
                // A key provisioned in this session
                ///////////////////////////////////////////////////////////////////////////////////
                keyEntry.checkEECerificateAvailablity ();

                ///////////////////////////////////////////////////////////////////////////////////
                // Check public versus private key match
                ///////////////////////////////////////////////////////////////////////////////////
                if (keyEntry.isRSA () ^ keyEntry.privateKey instanceof RSAPrivateKey)
                  {
                    provisioning.abort ("RSA/EC mixup between public and private keys for: " + keyEntry.id);
                  }
                if (keyEntry.isRSA ())
                  {
                    if (!((RSAPublicKey)keyEntry.publicKey).getPublicExponent ().equals (keyEntry.getPublicRSAExponentFromPrivateKey ()) ||
                        !((RSAPublicKey)keyEntry.publicKey).getModulus ().equals (((RSAPrivateKey)keyEntry.privateKey).getModulus ()))
                      {
                        provisioning.abort ("RSA mismatch between public and private keys for: " + keyEntry.id);
                      }
                  }
                else
                  {
                    try
                      {
                        Signature ec_signer = Signature.getInstance ("SHA256withECDSA");
                        ec_signer.initSign (keyEntry.privateKey);
                        ec_signer.update (RSA_ENCRYPTION_OID);  // Any data could be used...
                        byte[] ec_signData = ec_signer.sign ();
                        Signature ec_verifier = Signature.getInstance ("SHA256withECDSA");
                        ec_verifier.initVerify (keyEntry.publicKey);
                        ec_verifier.update (RSA_ENCRYPTION_OID);
                        if (!ec_verifier.verify (ec_signData))
                          {
                            provisioning.abort ("EC mismatch between public and private keys for: " + keyEntry.id);
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
                    if (key_entry_temp.keyHandle != keyEntry.keyHandle && key_entry_temp.certificatePath != null &&
                        key_entry_temp.certificatePath[0].equals (keyEntry.certificatePath[0]))
                      {
                        ///////////////////////////////////////////////////////////////////////////////////
                        // There was a conflict, ignore updates/deletes
                        ///////////////////////////////////////////////////////////////////////////////////
                        boolean collision = true;
                        for (PostProvisioningObject post_op : provisioning.postProvisioning_objects)
                          {
                            if (post_op.targetKey_entry == key_entry_temp && post_op.upd_orDel)
                              {
                                collision = false;
                              }
                          }
                        if (collision)
                          {
                            provisioning.abort ("Duplicate certificate in \"setCertificatePath\" for: " + keyEntry.id);
                          }
                      }
                  }
                  
                ///////////////////////////////////////////////////////////////////////////////////
                // Check that possible endorsed algorithms match key material
                ///////////////////////////////////////////////////////////////////////////////////
                for (String algorithm : keyEntry.endorsedAlgorithms)
                  {
                    Algorithm alg = getAlgorithm (algorithm);
                    if ((alg.mask & ALG_NONE) == 0)
                      {
                        ///////////////////////////////////////////////////////////////////////////////////
                        // A non-null endorsed algorithm found.  Symmetric or asymmetric key?
                        ///////////////////////////////////////////////////////////////////////////////////
                        if (((alg.mask & (ALG_SYM_ENC | ALG_HMAC)) == 0) ^ keyEntry.isSymmetric ())
                          {
                            if (keyEntry.isSymmetric ())
                              {
                                ///////////////////////////////////////////////////////////////////////////////////
                                // Symmetric. AES algorithms only operates on 128, 192, and 256 bit keys
                                ///////////////////////////////////////////////////////////////////////////////////
                                testAESKey (algorithm, keyEntry.symmetricKey, keyEntry.id, provisioning);
                                continue;
                              }
                            else
                              {
                                ///////////////////////////////////////////////////////////////////////////////////
                                // Asymmetric.  Check that algorithms match RSA or EC
                                ///////////////////////////////////////////////////////////////////////////////////
                                if (((alg.mask & ALG_RSA_KEY) == 0) ^ keyEntry.isRSA ())
                                  {
                                    continue;
                                  }
                              }
                          }
                        provisioning.abort ((keyEntry.isSymmetric () ? "Symmetric" : keyEntry.isRSA () ? "RSA" : "EC") + 
                                            " key " + keyEntry.id + " does not match algorithm: " + algorithm);
                      }
                  }
              }
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Post provisioning 1: Check that all the target keys are still there...
        ///////////////////////////////////////////////////////////////////////////////////
        for (PostProvisioningObject post_op : provisioning.postProvisioning_objects)
          {
            provisioning.getTargetKey (post_op.targetKey_entry.keyHandle);
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Post provisioning 2: Perform operations
        ///////////////////////////////////////////////////////////////////////////////////
        for (PostProvisioningObject post_op : provisioning.postProvisioning_objects)
          {
            KeyEntry keyEntry = post_op.targetKey_entry;
            if (post_op.newKey == null)
              {
                if (post_op.upd_orDel)
                  {
                    ///////////////////////////////////////////////////////////////////////////////////
                    // postDeleteKey
                    ///////////////////////////////////////////////////////////////////////////////////
                    localDeleteKey (keyEntry);
                  }
                else
                  {
                    ///////////////////////////////////////////////////////////////////////////////////
                    // postUnlockKey 
                    ///////////////////////////////////////////////////////////////////////////////////
                    keyEntry.setErrorCounter ((short) 0);
                    if (keyEntry.pinPolicy.pukPolicy != null)
                      {
                        keyEntry.pinPolicy.pukPolicy.errorCount = 0;
                      }
                  }
              }
            else
              {
                ///////////////////////////////////////////////////////////////////////////////////
                // Inherit protection data from the old key but nothing else
                ///////////////////////////////////////////////////////////////////////////////////
                post_op.newKey.pinPolicy = keyEntry.pinPolicy;
                post_op.newKey.pinValue = keyEntry.pinValue;
                post_op.newKey.errorCount = keyEntry.errorCount;
                post_op.newKey.devicePinProtection = keyEntry.devicePinProtection;

                if (post_op.upd_orDel)
                  {
                    ///////////////////////////////////////////////////////////////////////////////////
                    // postUpdateKey. Store new key in the place of the old
                    ///////////////////////////////////////////////////////////////////////////////////
                    keys.put (keyEntry.keyHandle, post_op.newKey);

                    ///////////////////////////////////////////////////////////////////////////////////
                    // Remove space occupied by the new key and restore old key handle
                    ///////////////////////////////////////////////////////////////////////////////////
                    keys.remove (post_op.newKey.keyHandle);
                    post_op.newKey.keyHandle = keyEntry.keyHandle;
                  }
              }
         }

        ///////////////////////////////////////////////////////////////////////////////////
        // Post provisioning 3: Take ownership of managed keys and their associates
        ///////////////////////////////////////////////////////////////////////////////////
        for (PostProvisioningObject post_op : provisioning.postProvisioning_objects)
          {
            Provisioning old_owner = post_op.targetKey_entry.owner;
            if (old_owner == provisioning)
              {
                continue;
              }
            for (KeyEntry keyEntry : keys.values ())
              {
                if (keyEntry.owner == old_owner)
                  {
                    ///////////////////////////////////////////////////////////////////////////////////
                    // There was a key that required changed ownership
                    ///////////////////////////////////////////////////////////////////////////////////
                    keyEntry.owner = provisioning;
                    if (keyEntry.pinPolicy != null)
                      {
                        ///////////////////////////////////////////////////////////////////////////////
                        // Which also had a PIN policy...
                        ///////////////////////////////////////////////////////////////////////////////
                        keyEntry.pinPolicy.owner = provisioning;
                        if (keyEntry.pinPolicy.pukPolicy != null)
                          {
                            ///////////////////////////////////////////////////////////////////////////
                            // Which in turn had a PUK policy...
                            ///////////////////////////////////////////////////////////////////////////
                            keyEntry.pinPolicy.pukPolicy.owner = provisioning;
                          }
                      }
                  }
              }
            provisionings.remove (old_owner.provisioningHandle);  // OK to perform also if already done
          }
        provisioning.postProvisioning_objects.clear ();  // No need to save

        ///////////////////////////////////////////////////////////////////////////////////
        // If there are no keys associated with the session we just delete it
        ///////////////////////////////////////////////////////////////////////////////////
        deleteEmptySession (provisioning);

        ///////////////////////////////////////////////////////////////////////////////////
        // We are done, close the show for this time
        ///////////////////////////////////////////////////////////////////////////////////
        provisioning.open = false;
        Log.i (SKS_DEBUG, "Session successfully CLOSED");
        return attestation;
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                        createProvisioningSession                           //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized ProvisioningSession createProvisioningSession (String sessionKeyAlgorithm,
                                                                       boolean privacy_enabled,
                                                                       String server_session_id,
                                                                       ECPublicKey server_ephemeralKey,
                                                                       String issuer_uri,
                                                                       PublicKey key_managementKey, // May be null
                                                                       int client_time,
                                                                       int sessionLife_time,
                                                                       short sessionKeyLimit) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Check provisioning session algorithm compatibility
        ///////////////////////////////////////////////////////////////////////////////////
        if (!sessionKeyAlgorithm.equals (ALGORITHM_SESSION_ATTEST_1))
          {
            abort ("Unknown \"SessionKeyAlgorithm\" : " + sessionKeyAlgorithm);
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
        String jceName = checkECKeyCompatibility (server_ephemeralKey, this, "\"ServerEphemeralKey\"");

        ///////////////////////////////////////////////////////////////////////////////////
        // Check optional key management key compatibility
        ///////////////////////////////////////////////////////////////////////////////////
        if (key_managementKey != null)
          {
            if (key_managementKey instanceof RSAPublicKey)
              {
                checkRSAKeyCompatibility (getRSAKeySize ((RSAPublicKey)key_managementKey),
                                          ((RSAPublicKey)key_managementKey).getPublicExponent (), this, "\"KeyManagementKey\"");
              }
            else
              {
                checkECKeyCompatibility ((ECPublicKey)key_managementKey, this, "\"KeyManagementKey\"");
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
        byte[] sessionKey = null;
        ECPublicKey client_ephemeralKey = null;
        try
          {
            ///////////////////////////////////////////////////////////////////////////////////
            // Create client ephemeral key
            ///////////////////////////////////////////////////////////////////////////////////
            KeyPairGenerator generator = KeyPairGenerator.getInstance ("EC");
            ECGenParameterSpec eccgen = new ECGenParameterSpec (jceName);
            generator.initialize (eccgen, new SecureRandom ());
            KeyPair kp = generator.generateKeyPair ();
            client_ephemeralKey = (ECPublicKey) kp.getPublic ();

            ///////////////////////////////////////////////////////////////////////////////////
            // Apply the SP800-56A ECC CDH primitive
            ///////////////////////////////////////////////////////////////////////////////////
            KeyAgreement key_agreement = KeyAgreement.getInstance ("ECDH");
            key_agreement.init (kp.getPrivate ());
            key_agreement.doPhase (server_ephemeralKey, true);
            byte[] Z = key_agreement.generateSecret ();

            ///////////////////////////////////////////////////////////////////////////////////
            // Use a custom KDF
            ///////////////////////////////////////////////////////////////////////////////////
            MacBuilder kdf = new MacBuilder (Z);
            kdf.addString (client_session_id);
            kdf.addString (server_session_id);
            kdf.addString (issuer_uri);
            kdf.addArray (getDeviceID (privacy_enabled));
            sessionKey = kdf.getResult ();

            ///////////////////////////////////////////////////////////////////////////////////
            // Finally, create the Attestation
            ///////////////////////////////////////////////////////////////////////////////////
            if (privacy_enabled)
              {
                ///////////////////////////////////////////////////////////////////////////////////
                // SessionKey attest
                ///////////////////////////////////////////////////////////////////////////////////
                MacBuilder ska = new MacBuilder (sessionKey);
                ska.addString (client_session_id);
                ska.addString (server_session_id);
                ska.addString (issuer_uri);
                ska.addArray (getDeviceID (privacy_enabled));
                ska.addString (sessionKeyAlgorithm);
                ska.addBool (privacy_enabled);
                ska.addArray (server_ephemeralKey.getEncoded ());
                ska.addArray (client_ephemeralKey.getEncoded ());
                ska.addArray (key_managementKey == null ? ZERO_LENGTH_ARRAY : key_managementKey.getEncoded ());
                ska.addInt (client_time);
                ska.addInt (sessionLife_time);
                ska.addShort (sessionKeyLimit);
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
                pka.addString (sessionKeyAlgorithm);
                pka.addBool (privacy_enabled);
                pka.addArray (server_ephemeralKey.getEncoded ());
                pka.addArray (client_ephemeralKey.getEncoded ());
                pka.addArray (key_managementKey == null ? ZERO_LENGTH_ARRAY : key_managementKey.getEncoded ());
                pka.addInt (client_time);
                pka.addInt (sessionLife_time);
                pka.addShort (sessionKeyLimit);
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
        p.sessionKey = sessionKey;
        p.key_managementKey = key_managementKey;
        p.client_time = client_time;
        p.sessionLife_time = sessionLife_time;
        p.sessionKeyLimit = sessionKeyLimit;
        Log.i (SKS_DEBUG, "Session CREATED");
        return new ProvisioningSession (p.provisioningHandle,
                                        client_session_id,
                                        attestation,
                                        client_ephemeralKey);
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                              addExtension                                  //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized void addExtension (int keyHandle,
                                           String type,
                                           byte sub_type,
                                           String qualifier,
                                           byte[] extensionData,
                                           byte[] mac) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key and associated provisioning session
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry keyEntry = getOpenKey (keyHandle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Check for duplicates and length errors
        ///////////////////////////////////////////////////////////////////////////////////
        keyEntry.owner.rangeTest (sub_type, SUB_TYPE_EXTENSION, SUB_TYPE_LOGOTYPE, "SubType");
        if (type.length () == 0 || type.length () >  MAX_LENGTH_URI)
          {
            keyEntry.owner.abort ("URI length error: " + type.length ());
          }
        if (keyEntry.extensions.get (type) != null)
          {
            keyEntry.owner.abort ("Duplicate \"Type\" : " + type);
          }
        if (extensionData.length > (sub_type == SUB_TYPE_ENCRYPTED_EXTENSION ? 
                            MAX_LENGTH_EXTENSION_DATA + AES_CBC_PKCS5_PADDING : MAX_LENGTH_EXTENSION_DATA))
          {
            keyEntry.owner.abort ("Extension data exceeds " + MAX_LENGTH_EXTENSION_DATA + " bytes");
          }
        byte[] bin_qualifier = getBinary (qualifier);
        if (((sub_type == SUB_TYPE_LOGOTYPE) ^ (bin_qualifier.length != 0)) || bin_qualifier.length > MAX_LENGTH_QUALIFIER)
          {
            keyEntry.owner.abort ("\"Qualifier\" length error");
          }
        ///////////////////////////////////////////////////////////////////////////////////
        // Property bags are checked for not being empty or incorrectly formatted
        ///////////////////////////////////////////////////////////////////////////////////
        if (sub_type == SUB_TYPE_PROPERTY_BAG)
          {
            int i = 0;
            do
              {
                if (i > extensionData.length - 5 || getShort (extensionData, i) == 0 ||
                    (i += getShort (extensionData, i) + 2) >  extensionData.length - 3 ||
                    ((extensionData[i++] & 0xFE) != 0) ||
                    (i += getShort (extensionData, i) + 2) > extensionData.length)
                  {
                    keyEntry.owner.abort ("\"PropertyBag\" format error: " + type);
                  }
              }
            while (i != extensionData.length);
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify incoming MAC
        ///////////////////////////////////////////////////////////////////////////////////
        MacBuilder verifier = keyEntry.getEECertMacBuilder (METHOD_ADD_EXTENSION);
        verifier.addString (type);
        verifier.addByte (sub_type);
        verifier.addArray (bin_qualifier);
        verifier.addBlob (extensionData);
        keyEntry.owner.verifyMac (verifier, mac);

        ///////////////////////////////////////////////////////////////////////////////////
        // Succeeded, create object
        ///////////////////////////////////////////////////////////////////////////////////
        ExtObject extension = new ExtObject ();
        extension.sub_type = sub_type;
        extension.qualifier = qualifier;
        extension.extensionData = (sub_type == SUB_TYPE_ENCRYPTED_EXTENSION) ?
                                     keyEntry.owner.decrypt (extensionData) : extensionData;
        keyEntry.extensions.put (type, extension);
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                            importPrivateKey                                //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized void importPrivateKey (int keyHandle,
                                               byte[] encryptedKey,
                                               byte[] mac) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key and associated provisioning session
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry keyEntry = getOpenKey (keyHandle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Check for key length errors
        ///////////////////////////////////////////////////////////////////////////////////
        if (encryptedKey.length > (MAX_LENGTH_CRYPTO_DATA + AES_CBC_PKCS5_PADDING))
          {
            keyEntry.owner.abort ("Private key: " + keyEntry.id + " exceeds " + MAX_LENGTH_CRYPTO_DATA + " bytes");
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify incoming MAC
        ///////////////////////////////////////////////////////////////////////////////////
        MacBuilder verifier = keyEntry.getEECertMacBuilder (METHOD_IMPORT_PRIVATE_KEY);
        verifier.addArray (encryptedKey);
        keyEntry.owner.verifyMac (verifier, mac);


        ///////////////////////////////////////////////////////////////////////////////////
        // Mark as "copied" by the server
        ///////////////////////////////////////////////////////////////////////////////////
        keyEntry.setAndVerifyServerBackupFlag ();

        ///////////////////////////////////////////////////////////////////////////////////
        // Decrypt and store private key
        ///////////////////////////////////////////////////////////////////////////////////
        try
          {
            byte[] pkcs8PrivateKey = keyEntry.owner.decrypt (encryptedKey);
            PKCS8EncodedKeySpec key_spec = new PKCS8EncodedKeySpec (pkcs8PrivateKey);

            ///////////////////////////////////////////////////////////////////////////////////
            // Bare-bones ASN.1 decoding to find out if it is RSA or EC 
            ///////////////////////////////////////////////////////////////////////////////////
            boolean rsaFlag = false;
            for (int j = 8; j < 11; j++)
              {
                rsaFlag = true;
                for (int i = 0; i < RSA_ENCRYPTION_OID.length; i++)
                  {
                    if (pkcs8PrivateKey[j + i] != RSA_ENCRYPTION_OID[i])
                      {
                        rsaFlag = false;
                      }
                  }
                if (rsaFlag) break;
              }
            keyEntry.privateKey = KeyFactory.getInstance (rsaFlag ? "RSA" : "EC").generatePrivate (key_spec);
            if (rsaFlag)
              {
                checkRSAKeyCompatibility (getRSAKeySize((RSAPrivateKey) keyEntry.privateKey),
                                          keyEntry.getPublicRSAExponentFromPrivateKey (),
                                          keyEntry.owner, keyEntry.id);
              }
            else
              {
                checkECKeyCompatibility ((ECPrivateKey)keyEntry.privateKey, keyEntry.owner, keyEntry.id);
              }
          }
        catch (GeneralSecurityException e)
          {
            keyEntry.owner.abort (e.getMessage (), SKSException.ERROR_CRYPTO);
          }
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                           importSymmetricKey                               //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized void importSymmetricKey (int keyHandle,
                                                 byte[] encryptedKey,
                                                 byte[] mac) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key and associated provisioning session
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry keyEntry = getOpenKey (keyHandle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Check for various input errors
        ///////////////////////////////////////////////////////////////////////////////////
        if (encryptedKey.length > (MAX_LENGTH_SYMMETRIC_KEY + AES_CBC_PKCS5_PADDING))
          {
            keyEntry.owner.abort ("Symmetric key: " + keyEntry.id + " exceeds " + MAX_LENGTH_SYMMETRIC_KEY + " bytes");
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Mark as "copied" by the server
        ///////////////////////////////////////////////////////////////////////////////////
        keyEntry.setAndVerifyServerBackupFlag ();

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify incoming MAC
        ///////////////////////////////////////////////////////////////////////////////////
        MacBuilder verifier = keyEntry.getEECertMacBuilder (METHOD_IMPORT_SYMMETRIC_KEY);
        verifier.addArray (encryptedKey);
        keyEntry.owner.verifyMac (verifier, mac);

        ///////////////////////////////////////////////////////////////////////////////////
        // Decrypt and store symmetric key
        ///////////////////////////////////////////////////////////////////////////////////
        keyEntry.symmetricKey = keyEntry.owner.decrypt (encryptedKey);
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                           setCertificatePath                               //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized void setCertificatePath (int keyHandle,
                                                 X509Certificate[] certificatePath,
                                                 byte[] mac) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key and associated provisioning session
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry keyEntry = getOpenKey (keyHandle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify incoming MAC
        ///////////////////////////////////////////////////////////////////////////////////
        MacBuilder verifier = keyEntry.owner.getMacBuilderForMethodCall (METHOD_SET_CERTIFICATE_PATH);
        try
          {
            verifier.addArray (keyEntry.publicKey.getEncoded ());
            verifier.addString (keyEntry.id);
            for (X509Certificate certificate : certificatePath)
              {
                byte[] der = certificate.getEncoded ();
                if (der.length > MAX_LENGTH_CRYPTO_DATA)
                  {
                    keyEntry.owner.abort ("Certificate for: " + keyEntry.id + " exceeds " + MAX_LENGTH_CRYPTO_DATA + " bytes");
                  }
                verifier.addArray (der);
              }
          }
        catch (GeneralSecurityException e)
          {
            keyEntry.owner.abort (e.getMessage (), SKSException.ERROR_INTERNAL);
          }
        keyEntry.owner.verifyMac (verifier, mac);

        ///////////////////////////////////////////////////////////////////////////////////
        // Update public key value.  It has no use after "setCertificatePath" anyway...
        ///////////////////////////////////////////////////////////////////////////////////
        keyEntry.publicKey = certificatePath[0].getPublicKey ();

        ///////////////////////////////////////////////////////////////////////////////////
        // Check key material for SKS compliance
        ///////////////////////////////////////////////////////////////////////////////////
        if (keyEntry.publicKey instanceof RSAPublicKey)
          {
            checkRSAKeyCompatibility (getRSAKeySize((RSAPublicKey) keyEntry.publicKey),
                                      ((RSAPublicKey) keyEntry.publicKey).getPublicExponent (),
                                      keyEntry.owner, keyEntry.id);
          }
        else
          {
            checkECKeyCompatibility ((ECPublicKey) keyEntry.publicKey, keyEntry.owner, keyEntry.id);
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Store certificate path
        ///////////////////////////////////////////////////////////////////////////////////
        if (keyEntry.certificatePath != null)
          {
            keyEntry.owner.abort ("Multiple calls to \"setCertificatePath\" for: " + keyEntry.id);
          }
        keyEntry.certificatePath = certificatePath.clone ();
        logCertificateOperation (keyEntry, "received");
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                              createKeyEntry                                //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized KeyData createKeyEntry (int provisioningHandle,
                                                String id,
                                                String key_entryAlgorithm,
                                                byte[] server_seed,
                                                boolean devicePinProtection,
                                                int pinPolicyHandle,
                                                byte[] pinValue,
                                                boolean enablePinCaching,
                                                byte biometricProtection,
                                                byte exportProtection,
                                                byte deleteProtection,
                                                byte appUsage,
                                                String friendlyName,
                                                String keyAlgorithm,
                                                byte[] keyParameters,
                                                String[] endorsedAlgorithms,
                                                byte[] mac) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get provisioning session
        ///////////////////////////////////////////////////////////////////////////////////
        Provisioning provisioning = getOpenProvisioningSession (provisioningHandle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Validate input as much as possible
        ///////////////////////////////////////////////////////////////////////////////////
        if (!key_entryAlgorithm.equals (ALGORITHM_KEY_ATTEST_1))
          {
            provisioning.abort ("Unknown \"KeyEntryAlgorithm\" : " + key_entryAlgorithm, SKSException.ERROR_ALGORITHM);
          }
        Algorithm kalg = supportedAlgorithms.get (keyAlgorithm);
        if (kalg == null || (kalg.mask & ALG_KEY_GEN) == 0)
          {
            provisioning.abort ("Unsupported \"KeyAlgorithm\": " + keyAlgorithm);
          }
        if ((kalg.mask & ALG_KEY_PARM) == 0 ^ keyParameters == null)
          {
            provisioning.abort ((keyParameters == null ? "Missing" : "Unexpected") + " \"KeyParameters\"");
          }
        if (server_seed == null)
          {
            server_seed = ZERO_LENGTH_ARRAY;
          }
        else if (server_seed.length > MAX_LENGTH_SERVER_SEED)
          {
            provisioning.abort ("\"ServerSeed\" length error: " + server_seed.length);
          }
        provisioning.rangeTest (exportProtection, EXPORT_DELETE_PROTECTION_NONE, EXPORT_DELETE_PROTECTION_NOT_ALLOWED, "ExportProtection");
        provisioning.rangeTest (deleteProtection, EXPORT_DELETE_PROTECTION_NONE, EXPORT_DELETE_PROTECTION_NOT_ALLOWED, "DeleteProtection");
        provisioning.rangeTest (appUsage, APP_USAGE_SIGNATURE, APP_USAGE_UNIVERSAL, "AppUsage");
        provisioning.rangeTest (biometricProtection, BIOMETRIC_PROTECTION_NONE, BIOMETRIC_PROTECTION_EXCLUSIVE, "BiometricProtection");

        ///////////////////////////////////////////////////////////////////////////////////
        // Get proper PIN policy ID
        ///////////////////////////////////////////////////////////////////////////////////
        PINPolicy pinPolicy = null;
        boolean decryptPin = false;
        String pinPolicy_id = CRYPTO_STRING_NOT_AVAILABLE;
        boolean pinProtection = true;
        if (devicePinProtection)
          {
            if (pinPolicyHandle != 0)
              {
                provisioning.abort ("Device PIN mixed with PIN policy ojbect");
              }
          }
        else if (pinPolicyHandle != 0)
          {
            pinPolicy = pinPolicies.get (pinPolicyHandle);
            if (pinPolicy == null || pinPolicy.owner != provisioning)
              {
                provisioning.abort ("Referenced PIN policy object not found");
              }
            if (enablePinCaching && pinPolicy.inputMethod != INPUT_METHOD_TRUSTED_GUI)
              {
                provisioning.abort ("\"EnablePINCaching\" must be combined with \"trusted-gui\"");
              }
            pinPolicy_id = pinPolicy.id;
            provisioning.names.put (pinPolicy_id, true); // Referenced
            decryptPin = !pinPolicy.userDefined;
          }
        else
          {
            verifyExportDeleteProtection (deleteProtection, EXPORT_DELETE_PROTECTION_PIN, provisioning);
            verifyExportDeleteProtection (exportProtection, EXPORT_DELETE_PROTECTION_PIN, provisioning);
            pinProtection = false;
            if (enablePinCaching)
              {
                provisioning.abort ("\"EnablePINCaching\" without PIN");
              }
            if (pinValue != null)
              {
                provisioning.abort ("\"PINValue\" expected to be empty");
              }
          }
        if (biometricProtection != BIOMETRIC_PROTECTION_NONE &&
            ((biometricProtection != BIOMETRIC_PROTECTION_EXCLUSIVE) ^ pinProtection))
          {
            provisioning.abort ("Invalid \"BiometricProtection\" and PIN combination");
          }
        if (pinPolicy == null || pinPolicy.pukPolicy == null)
          {
            verifyExportDeleteProtection (deleteProtection, EXPORT_DELETE_PROTECTION_PUK, provisioning);
            verifyExportDeleteProtection (exportProtection, EXPORT_DELETE_PROTECTION_PUK, provisioning);
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify incoming MAC
        ///////////////////////////////////////////////////////////////////////////////////
        MacBuilder verifier = provisioning.getMacBuilderForMethodCall (METHOD_CREATE_KEY_ENTRY);
        verifier.addString (id);
        verifier.addString (key_entryAlgorithm);
        verifier.addArray (server_seed);
        verifier.addString (pinPolicy_id);
        if (decryptPin)
          {
            verifier.addArray (pinValue);
            pinValue = provisioning.decrypt (pinValue);
          }
        else
          {
            if (pinValue != null)
              {
                pinValue = pinValue.clone ();
              }
            verifier.addString (CRYPTO_STRING_NOT_AVAILABLE);
          }
        verifier.addBool (devicePinProtection);
        verifier.addBool (enablePinCaching);
        verifier.addByte (biometricProtection);
        verifier.addByte (exportProtection);
        verifier.addByte (deleteProtection);
        verifier.addByte (appUsage);
        verifier.addString (friendlyName == null ? "" : friendlyName);
        verifier.addString (keyAlgorithm);
        verifier.addArray (keyParameters == null ? ZERO_LENGTH_ARRAY : keyParameters);
        LinkedHashSet<String> temp_endorsed = new LinkedHashSet<String> ();
        String prev_alg = "\0";
        for (String endorsedAlgorithm : endorsedAlgorithms)
          {
            ///////////////////////////////////////////////////////////////////////////////////
            // Check that the algorithms are sorted and known
            ///////////////////////////////////////////////////////////////////////////////////
            if (prev_alg.compareTo (endorsedAlgorithm) >= 0)
              {
                provisioning.abort ("Duplicate or incorrectly sorted algorithm: " + endorsedAlgorithm);
              }
            Algorithm alg = supportedAlgorithms.get (endorsedAlgorithm);
            if (alg == null || alg.mask == 0)
              {
                provisioning.abort ("Unsupported algorithm: " + endorsedAlgorithm);
              }
            if ((alg.mask & ALG_NONE) != 0 && endorsedAlgorithms.length > 1)
              {
                provisioning.abort ("Algorithm must be alone: " + endorsedAlgorithm);
              }
            temp_endorsed.add (prev_alg = endorsedAlgorithm);
            verifier.addString (endorsedAlgorithm);
          }
        provisioning.verifyMac (verifier, mac);

        ///////////////////////////////////////////////////////////////////////////////////
        // Perform a gazillion tests on PINs if applicable
        ///////////////////////////////////////////////////////////////////////////////////
        if (pinPolicy != null)
          {
            ///////////////////////////////////////////////////////////////////////////////////
            // Testing the actual PIN value
            ///////////////////////////////////////////////////////////////////////////////////
            verifyPINPolicyCompliance (false, pinValue, pinPolicy, appUsage, provisioning);
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Decode key algorithm specifier
        ///////////////////////////////////////////////////////////////////////////////////
        AlgorithmParameterSpec algPar_spec = null;
        if ((kalg.mask & ALG_RSA_KEY) == ALG_RSA_KEY)
          {
            int rsaKey_size = kalg.mask & ALG_RSA_GMSK;
            BigInteger exponent = RSAKeyGenParameterSpec.F4;
            if (keyParameters != null)
              {
                if (keyParameters.length == 0 || keyParameters.length > 8)
                  {
                    provisioning.abort ("\"KeyParameters\" length error: " + keyParameters.length);
                  }
                exponent = new BigInteger (keyParameters);
              }
            algPar_spec = new RSAKeyGenParameterSpec (rsaKey_size, exponent);
            Log.i (SKS_DEBUG, "RSA " + rsaKey_size + " key created");
          }
        else
          {
            algPar_spec = new ECGenParameterSpec (kalg.jceName);
            Log.i (SKS_DEBUG, "EC " + kalg.jceName + " key created");
          }
        try
          {
            ///////////////////////////////////////////////////////////////////////////////////
            // At last, generate the desired key-pair
            ///////////////////////////////////////////////////////////////////////////////////
            SecureRandom secure_random = server_seed.length == 0 ? new SecureRandom () : new SecureRandom (server_seed);
            KeyPairGenerator kpg = KeyPairGenerator.getInstance (algPar_spec instanceof RSAKeyGenParameterSpec ? "RSA" : "EC");
            kpg.initialize (algPar_spec, secure_random);
            KeyPair keyPair = kpg.generateKeyPair ();
            PublicKey publicKey = keyPair.getPublic ();
            PrivateKey privateKey = keyPair.getPrivate ();

            ///////////////////////////////////////////////////////////////////////////////////
            // Create key attest
            ///////////////////////////////////////////////////////////////////////////////////
            MacBuilder cka = provisioning.getMacBuilderForMethodCall (KDF_DEVICE_ATTESTATION);
            cka.addString (id);
            cka.addArray (publicKey.getEncoded ());
            byte[] attestation = cka.getResult ();

            ///////////////////////////////////////////////////////////////////////////////////
            // Finally, create a key entry
            ///////////////////////////////////////////////////////////////////////////////////
            KeyEntry keyEntry = new KeyEntry (provisioning, id);
            provisioning.names.put (id, true); // Referenced (for "closeProvisioningSession")
            keyEntry.pinPolicy = pinPolicy;
            keyEntry.friendlyName = friendlyName;
            keyEntry.pinValue = pinValue;
            keyEntry.publicKey = publicKey;
            keyEntry.privateKey = privateKey;
            keyEntry.appUsage = appUsage;
            keyEntry.devicePinProtection = devicePinProtection;
            keyEntry.enablePinCaching = enablePinCaching;
            keyEntry.biometricProtection = biometricProtection;
            keyEntry.exportProtection = exportProtection;
            keyEntry.deleteProtection = deleteProtection;
            keyEntry.endorsedAlgorithms = temp_endorsed;
            return new KeyData (keyEntry.keyHandle, publicKey, attestation);
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
    public synchronized int createPinPolicy (int provisioningHandle,
                                             String id,
                                             int pukPolicyHandle,
                                             boolean userDefined,
                                             boolean userModifiable,
                                             byte format,
                                             short retryLimit,
                                             byte grouping,
                                             byte patternRestrictions,
                                             short minLength,
                                             short maxLength,
                                             byte inputMethod,
                                             byte[] mac) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get provisioning session
        ///////////////////////////////////////////////////////////////////////////////////
        Provisioning provisioning = getOpenProvisioningSession (provisioningHandle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Perform PIN "sanity" checks
        ///////////////////////////////////////////////////////////////////////////////////
        provisioning.rangeTest (grouping, PIN_GROUPING_NONE, PIN_GROUPING_UNIQUE, "Grouping");
        provisioning.rangeTest (inputMethod, INPUT_METHOD_ANY, INPUT_METHOD_TRUSTED_GUI, "InputMethod");
        provisioning.passphraseFormatTest (format);
        provisioning.retryLimitTest (retryLimit, (short)1);
        if ((patternRestrictions & ~(PIN_PATTERN_TWO_IN_A_ROW | 
                                      PIN_PATTERN_THREE_IN_A_ROW |
                                      PIN_PATTERN_SEQUENCE |
                                      PIN_PATTERN_REPEATED |
                                      PIN_PATTERN_MISSING_GROUP)) != 0)
          {
            provisioning.abort ("Invalid \"PatternRestrictions\" value=" + patternRestrictions);
          }
        String pukPolicy_id = CRYPTO_STRING_NOT_AVAILABLE;
        PUKPolicy pukPolicy = null;
        if (pukPolicyHandle != 0)
          {
            pukPolicy = pukPolicies.get (pukPolicyHandle);
            if (pukPolicy == null || pukPolicy.owner != provisioning)
              {
                provisioning.abort ("Referenced PUK policy object not found");
              }
            pukPolicy_id = pukPolicy.id;
            provisioning.names.put (pukPolicy_id, true); // Referenced
          }
        if ((patternRestrictions & PIN_PATTERN_MISSING_GROUP) != 0 &&
            format != PASSPHRASE_FORMAT_ALPHANUMERIC && format != PASSPHRASE_FORMAT_STRING)
          {
            provisioning.abort ("Incorrect \"Format\" for the \"missing-group\" PIN pattern policy");
          }
        if (minLength < 1 || maxLength > MAX_LENGTH_PIN_PUK || maxLength < minLength)
          {
            provisioning.abort ("PIN policy length error");
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify incoming MAC
        ///////////////////////////////////////////////////////////////////////////////////
        MacBuilder verifier = provisioning.getMacBuilderForMethodCall (METHOD_CREATE_PIN_POLICY);
        verifier.addString (id);
        verifier.addString (pukPolicy_id);
        verifier.addBool (userDefined);
        verifier.addBool (userModifiable);
        verifier.addByte (format);
        verifier.addShort (retryLimit);
        verifier.addByte (grouping);
        verifier.addByte (patternRestrictions);
        verifier.addShort (minLength);
        verifier.addShort (maxLength);
        verifier.addByte (inputMethod);
        provisioning.verifyMac (verifier, mac);

        ///////////////////////////////////////////////////////////////////////////////////
        // Success, create object
        ///////////////////////////////////////////////////////////////////////////////////
        PINPolicy pinPolicy = new PINPolicy (provisioning, id);
        pinPolicy.pukPolicy = pukPolicy;
        pinPolicy.userDefined = userDefined;
        pinPolicy.userModifiable = userModifiable;
        pinPolicy.format = format;
        pinPolicy.retryLimit = retryLimit;
        pinPolicy.grouping = grouping;
        pinPolicy.patternRestrictions = patternRestrictions;
        pinPolicy.minLength = minLength;
        pinPolicy.maxLength = maxLength;
        pinPolicy.inputMethod = inputMethod;
        Log.i (SKS_DEBUG, "PIN policy object created");
        return pinPolicy.pinPolicyHandle;
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                            createPUKPolicy                                 //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized int createPukPolicy (int provisioningHandle,
                                             String id,
                                             byte[] pukValue,
                                             byte format,
                                             short retryLimit,
                                             byte[] mac) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get provisioning session
        ///////////////////////////////////////////////////////////////////////////////////
        Provisioning provisioning = getOpenProvisioningSession (provisioningHandle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Perform PUK "sanity" checks
        ///////////////////////////////////////////////////////////////////////////////////
        provisioning.passphraseFormatTest (format);
        provisioning.retryLimitTest (retryLimit, (short)0);
        byte[] decryptedPukValue = provisioning.decrypt (pukValue);
        if (decryptedPukValue.length == 0 || decryptedPukValue.length > MAX_LENGTH_PIN_PUK)
          {
            provisioning.abort ("PUK length error");
          }
        for (int i = 0; i < decryptedPukValue.length; i++)
          {
            byte c = decryptedPukValue[i];
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
        verifier.addArray (pukValue);
        verifier.addByte (format);
        verifier.addShort (retryLimit);
        provisioning.verifyMac (verifier, mac);

        ///////////////////////////////////////////////////////////////////////////////////
        // Success, create object
        ///////////////////////////////////////////////////////////////////////////////////
        PUKPolicy pukPolicy = new PUKPolicy (provisioning, id);
        pukPolicy.pukValue = decryptedPukValue;
        pukPolicy.format = format;
        pukPolicy.retryLimit = retryLimit;
        Log.i (SKS_DEBUG, "PUK policy object created");
        return pukPolicy.pukPolicyHandle;
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                      A set of public non-SKS methods                       //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////

    @Override
    public boolean isGranted (int keyHandle, String domain) throws SKSException
      {
        KeyEntry keyEntry = getStdKey (keyHandle);
        return keyEntry.grantedDomains.contains (domain);
      }
    
    @Override
    public void setGrant (int keyHandle, String domain, boolean granted) throws SKSException
      {
        KeyEntry keyEntry = getStdKey (keyHandle);
        if (granted)
          {
            keyEntry.grantedDomains.add (domain);
          }
        else
          {
            keyEntry.grantedDomains.remove (domain);
          }
      }
    
    @Override
    public String[] listGrants (int keyHandle) throws SKSException
      {
        KeyEntry keyEntry = getStdKey (keyHandle);
        return keyEntry.grantedDomains.toArray (new String[0]);
      }
  }
