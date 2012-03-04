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
package org.webpki.sks.twolayer.se;

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
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.ECParameterSpec;

import java.util.Arrays;
import java.util.Date;
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
import org.webpki.sks.SKSException;
import org.webpki.sks.SecureKeyStore;

/*
 *                          ################################################
 *                          #  SKS - Secure Key Store - Two Layer Version  #
 *                          #          SE - Security Element Part          #
 *                          ################################################
 *
 *  SKS is a cryptographic module that supports On-line Provisioning and Management
 *  of PKI, Symmetric keys, PINs, PUKs and Extension data.
 *
 *  Author: Anders Rundgren
 */
public class SEReferenceImplementation
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
        addAlgorithm (SecureKeyStore.ALGORITHM_SESSION_ATTEST_1, null, 0);

        addAlgorithm (SecureKeyStore.ALGORITHM_KEY_ATTEST_1, null, 0);

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
    static final byte[] MASTER_SECRET_32 = {0,1,2,3,4,5,6,7,8,9,1,0,3,2,5,4,7,6,9,8,9,8,7,6,5,4,3,2,1,0,3,2};
    
    static final byte[] MASTER_SECRET_SESSION_KDF = {'S','e','s','s','i','o','n','K','e','y'};

    static final byte[] MASTER_SECRET_USER_KDF    = {'U','s','e','r','K','e','y'};

    static final char[] ATTESTATION_KEY_PASSWORD =  {'t','e','s','t','i','n','g'};

    static final String ATTESTATION_KEY_ALIAS = "mykey";
    
    static KeyStore getAttestationKeyStore () throws GeneralSecurityException
      {
        try
          {
            KeyStore ks = KeyStore.getInstance ("JKS");
            ks.load (SEReferenceImplementation.class.getResourceAsStream ("attestationkeystore.jks"), ATTESTATION_KEY_PASSWORD);
            return ks;
          }
        catch (IOException e)
          {
            throw new GeneralSecurityException (e);
          }
      }
    
    static X509Certificate[] getDeviceCertificatePath () throws GeneralSecurityException
      {
        return new X509Certificate[]{(X509Certificate)getAttestationKeyStore ().getCertificate (ATTESTATION_KEY_ALIAS)};
      }
    
    static byte[] getDeviceID (boolean privacy_enabled) throws GeneralSecurityException
      {
        return privacy_enabled ? SecureKeyStore.KDF_ANONYMOUS : getDeviceCertificatePath ()[0].getEncoded ();
      }

    static PrivateKey getAttestationKey () throws GeneralSecurityException
      {
        return (PrivateKey) getAttestationKeyStore ().getKey (ATTESTATION_KEY_ALIAS, ATTESTATION_KEY_PASSWORD);        
      }


    static int getShort (byte[] buffer, int index)
      {
        return ((buffer[index++] << 8) & 0xFFFF) + (buffer[index] & 0xFF);
      }


    static void abort (String message) throws SKSException
      {
        throw new SKSException (message);
      }

    
    static void abort (String message, int option) throws SKSException
      {
        throw new SKSException (message, option);
      }


    static void abort (GeneralSecurityException e) throws SKSException
      {
        throw new SKSException (e.getMessage (), SKSException.ERROR_INTERNAL);
      }

    
    static void checkECKeyCompatibility (ECKey ec_key, String key_id) throws SKSException
      {
        ECParameterSpec ec = ec_key.getParams ();
        if (!ec.getCurve ().getA ().equals (secp256r1_A) ||
            !ec.getCurve ().getB ().equals (secp256r1_B) ||
            !ec.getGenerator ().getAffineX ().equals (secp256r1_AffineX) ||
            !ec.getGenerator ().getAffineY ().equals (secp256r1_AffineY) ||
            !ec.getOrder ().equals (secp256r1_Order) ||
            ec.getCofactor () != secp256r1_Cofactor)
          {
            abort ("EC key " + key_id + " not of P-256/secp256r1 type");
          }
      }


    static void checkRSAKeyCompatibility (int rsa_key_size, BigInteger  exponent, String key_id) throws SKSException
      {
        boolean found = false;
        for (short key_size : SecureKeyStore.SKS_DEFAULT_RSA_SUPPORT)
          {
            if (key_size == rsa_key_size)
              {
                found = true;
                break;
              }
          }
        if (!found)
          {
            abort ("Unsupported RSA key size " + rsa_key_size + " for: " + key_id);
          }
      }


    static int getRSAKeySize (RSAKey rsa_key)
      {
        byte[] modblob = rsa_key.getModulus ().toByteArray ();
        return (modblob[0] == 0 ? modblob.length - 1 : modblob.length) * 8;
      }


    static byte[] addArrays (byte[] a, byte[] b)
      {
        byte[] r = new byte[a.length + b.length];
        System.arraycopy (a, 0, r, 0, a.length);
        System.arraycopy (b, 0, r, a.length, b.length);
        return r;
      }


    static class MacBuilder implements Serializable
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

        void verify (byte[] claimed_mac) throws SKSException
          {
            if (!Arrays.equals (getResult (), claimed_mac))
              {
                abort ("MAC error", SKSException.ERROR_MAC);
              }
          }
      }


    static MacBuilder getMacBuilder (SEProvisioningState se_provisioning_state, byte[] key_modifier) throws SKSException
      {
        if (se_provisioning_state.session_key_limit-- <= 0)
          {
            abort ("\"SessionKeyLimit\" exceeded");
          }
        try
          {
            return new MacBuilder (addArrays (se_provisioning_state.wrapped_session_key, key_modifier));
          }
        catch (GeneralSecurityException e)
          {
            throw new SKSException (e);
          }
      }


    static MacBuilder getMacBuilderForMethodCall (SEProvisioningState se_provisioning_state, byte[] method) throws SKSException
      {
        short q = se_provisioning_state.mac_sequence_counter++;
        return getMacBuilder (se_provisioning_state, addArrays (method, new byte[]{(byte)(q >>> 8), (byte)q}));
      }


    static MacBuilder getEECertMacBuilder (SEProvisioningState se_provisioning_state, X509Certificate ee_certificate, byte[] method) throws SKSException, GeneralSecurityException
      {
        MacBuilder mac_builder = getMacBuilderForMethodCall (se_provisioning_state, method);
        mac_builder.addArray (ee_certificate.getEncoded ());
        return mac_builder;
      }


    static byte[] decrypt (SEProvisioningState se_provisioning_state, byte[] data) throws SKSException
      {
        byte[] key = getMacBuilder (se_provisioning_state, 
                                    SecureKeyStore.ZERO_LENGTH_ARRAY).addVerbatim (SecureKeyStore.KDF_ENCRYPTION_KEY).getResult ();
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


    static Algorithm getAlgorithm (String algorithm_uri) throws SKSException
      {
        Algorithm alg = supported_algorithms.get (algorithm_uri);
        if (alg == null)
          {
            abort ("Unsupported algorithm: " + algorithm_uri, SKSException.ERROR_ALGORITHM);
          }
        return alg;
      }


    static Algorithm checkKeyAndAlgorithm (SEKeyState se_key_state, int key_handle, String algorithm, int expected_type) throws SKSException
      {
        Algorithm alg = getAlgorithm (algorithm);
        if ((alg.mask & expected_type) == 0)
          {
            abort ("Algorithm does not match operation: " + algorithm, SKSException.ERROR_ALGORITHM);
          }
        if (((alg.mask & (ALG_SYM_ENC | ALG_HMAC)) != 0) ^ se_key_state.is_symmetric_key)
          {
            abort ((se_key_state.is_symmetric_key ? "S" : "As") + "ymmetric key #" + key_handle + " is incompatible with: " + algorithm, SKSException.ERROR_ALGORITHM);
          }
        if (se_key_state.is_symmetric_key)
          {
            testSymmetricKey (algorithm, se_key_state.symmetric_key.length, "#" + key_handle);
          }
        else if (se_key_state.isRSA () ^ (alg.mask & ALG_RSA_KEY) != 0)
          {
            abort ((se_key_state.isRSA () ? "RSA" : "EC") + " key #" + key_handle + " is incompatible with: " + algorithm, SKSException.ERROR_ALGORITHM);
          }
        return alg;
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
    //                              getDeviceInfo                                 //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static DeviceInfo getDeviceInfo () throws SKSException
      {
        try
          {
            return new DeviceInfo (SecureKeyStore.SKS_API_LEVEL,
                                   (byte)(DeviceInfo.LOCATION_EMBEDDED | DeviceInfo.TYPE_SOFTWARE),
                                   SKS_UPDATE_URL,
                                   SKS_VENDOR_NAME,
                                   SKS_VENDOR_DESCRIPTION,
                                   getDeviceCertificatePath (),
                                   supported_algorithms.keySet ().toArray (new String[0]),
                                   SKS_RSA_EXPONENT_SUPPORT,
                                   SecureKeyStore.SKS_DEFAULT_RSA_SUPPORT,
                                   SecureKeyStore.MAX_LENGTH_CRYPTO_DATA,
                                   SecureKeyStore.MAX_LENGTH_EXTENSION_DATA,
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
    //                              checkKeyPair                                  //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static void checkKeyPair (SEKeyState se_key_state, 
                                     PublicKey public_key,
                                     String id) throws SKSException
      {
        if (se_key_state.isRSA () ^ se_key_state.private_key instanceof RSAPrivateKey)
          {
            abort ("RSA/EC mixup between public and private keys for: " + id);
          }
        if (se_key_state.isRSA ())
          {
            if (!((RSAPublicKey)public_key).getPublicExponent ().equals (((RSAPrivateCrtKey)se_key_state.private_key).getPublicExponent ()) ||
                !((RSAPublicKey)public_key).getModulus ().equals (((RSAPrivateKey)se_key_state.private_key).getModulus ()))
              {
                abort ("RSA mismatch between public and private keys for: " + id);
              }
          }
        else
          {
            try
              {
                Signature ec_signer = Signature.getInstance ("SHA256withECDSA");
                ec_signer.initSign (se_key_state.private_key);
                ec_signer.update (RSA_ENCRYPTION_OID);  // Any data could be used...
                byte[] ec_sign_data = ec_signer.sign ();
                Signature ec_verifier = Signature.getInstance ("SHA256withECDSA");
                ec_verifier.initVerify (public_key);
                ec_verifier.update (RSA_ENCRYPTION_OID);
                if (!ec_verifier.verify (ec_sign_data))
                  {
                    abort ("EC mismatch between public and private keys for: " + id);
                  }
              }
            catch (GeneralSecurityException e)
              {
                abort (e);
              }
          }
      }

    
    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                            testSymmetricKey                                //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static void testSymmetricKey (String algorithm,
                                         int symmetric_key_length,
                                         String key_id) throws SKSException
      {
        Algorithm alg = getAlgorithm (algorithm);
        if ((alg.mask & ALG_SYM_ENC) != 0)
          {
            int l = 0;
            if (symmetric_key_length == 16) l = ALG_SYML_128;
            else if (symmetric_key_length == 24) l = ALG_SYML_192;
            else if (symmetric_key_length == 32) l = ALG_SYML_256;
            if ((l & alg.mask) == 0)
              {
                abort ("Key " + key_id + " has wrong size (" + symmetric_key_length + ") for algorithm: " + algorithm);
              }
          }
      }

    
    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                             executeSignHash                                 //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static byte[] executeSignHash (SEKeyState se_key_state,
                                          int key_handle,
                                          String algorithm,
                                          byte[] parameters,
                                          byte[] data) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Check input arguments
        ///////////////////////////////////////////////////////////////////////////////////
        Algorithm alg = checkKeyAndAlgorithm (se_key_state, key_handle, algorithm, ALG_ASYM_SGN);
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
            if (se_key_state.isRSA () && hash_len > 0)
              {
                data = addArrays (hash_len == 20 ? DIGEST_INFO_SHA1 : DIGEST_INFO_SHA256, data);
              }
            Signature signature = Signature.getInstance (alg.jce_name);
            signature.initSign (se_key_state.private_key);
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
    //                               executeHMAC                                  //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static byte[] executeHMAC (SEKeyState se_key_state,
                                      int key_handle,
                                      String algorithm,
                                      byte[] data) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Check input arguments
        ///////////////////////////////////////////////////////////////////////////////////
        Algorithm alg = checkKeyAndAlgorithm (se_key_state, key_handle, algorithm, ALG_HMAC);
 
        ///////////////////////////////////////////////////////////////////////////////////
        // Finally, perform operation
        ///////////////////////////////////////////////////////////////////////////////////
        try
          {
            Mac mac = Mac.getInstance (alg.jce_name);
            mac.init (new SecretKeySpec (se_key_state.symmetric_key, "RAW"));
            return mac.doFinal (data);
          }
        catch (Exception e)
          {
            throw new SKSException (e, SKSException.ERROR_CRYPTO);
          }
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                      executeSymmetricEncryption                            //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static byte[] executeSymmetricEncryption (SEKeyState se_key_state,
                                                     int key_handle,
                                                     String algorithm,
                                                     boolean mode,
                                                     byte[] iv,
                                                     byte[] data) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Check input arguments
        ///////////////////////////////////////////////////////////////////////////////////
        Algorithm alg = checkKeyAndAlgorithm (se_key_state, key_handle, algorithm, ALG_SYM_ENC);
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
        // Finally, perform operation
        ///////////////////////////////////////////////////////////////////////////////////
        try
          {
            Cipher crypt = Cipher.getInstance (alg.jce_name);
            SecretKeySpec sk = new SecretKeySpec (se_key_state.symmetric_key, "AES");
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
    //                      signProvisioningSessionData                           //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
/*
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
*/


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                        closeProvisioningAttest                            //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static byte[] closeProvisioningAttest (SEProvisioningState se_provisioning_state,
                                                  String server_session_id,
                                                  String client_session_id,
                                                  String issuer_uri,
                                                  byte[] nonce,
                                                  byte[] mac) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Verify incoming MAC
        ///////////////////////////////////////////////////////////////////////////////////
        MacBuilder verifier = getMacBuilderForMethodCall (se_provisioning_state, SecureKeyStore.METHOD_CLOSE_PROVISIONING_SESSION);
        verifier.addString (client_session_id);
        verifier.addString (server_session_id);
        verifier.addString (issuer_uri);
        verifier.addArray (nonce);
        verifier.verify (mac);

        ///////////////////////////////////////////////////////////////////////////////////
        // Generate the attestation in advance => checking SessionKeyLimit before "commit"
        ///////////////////////////////////////////////////////////////////////////////////
        MacBuilder close_attestation = getMacBuilderForMethodCall (se_provisioning_state, SecureKeyStore.KDF_DEVICE_ATTESTATION);
        close_attestation.addArray (nonce);
        close_attestation.addString (SecureKeyStore.ALGORITHM_SESSION_ATTEST_1);
        return close_attestation.getResult ();
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                         createProvisioningData                             //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static SEProvisioningData createProvisioningData (String algorithm,
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
        if (!algorithm.equals (SecureKeyStore.ALGORITHM_SESSION_ATTEST_1))
          {
            abort ("Unknown \"Algorithm\" : " + algorithm);
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Check IssuerURI
        ///////////////////////////////////////////////////////////////////////////////////
        if (issuer_uri.length () == 0 || issuer_uri.length () >  SecureKeyStore.MAX_LENGTH_URI)
          {
            abort ("\"IssuerURI\" length error: " + issuer_uri.length ());
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Check server ECDH key compatibility
        ///////////////////////////////////////////////////////////////////////////////////
        checkECKeyCompatibility (server_ephemeral_key, "\"ServerEphemeralKey\"");

        ///////////////////////////////////////////////////////////////////////////////////
        // Check optional key management key compatibility
        ///////////////////////////////////////////////////////////////////////////////////
        if (key_management_key != null)
          {
            if (key_management_key instanceof RSAPublicKey)
              {
                checkRSAKeyCompatibility (getRSAKeySize ((RSAPublicKey)key_management_key),
                                          ((RSAPublicKey)key_management_key).getPublicExponent (), "\"KeyManagementKey\"");
              }
            else
              {
                checkECKeyCompatibility ((ECPublicKey)key_management_key, "\"KeyManagementKey\"");
              }
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Create ClientSessionID
        ///////////////////////////////////////////////////////////////////////////////////
        String client_session_id = "C-" + Long.toHexString (new Date().getTime()) + Long.toHexString(new SecureRandom().nextLong());

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
            ECGenParameterSpec eccgen = new ECGenParameterSpec ("secp256r1");
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
            // SessionKey attest
            ///////////////////////////////////////////////////////////////////////////////////
            MacBuilder ska = new MacBuilder (session_key);
            ska.addString (algorithm);
            ska.addBool (privacy_enabled);
            ska.addArray (server_ephemeral_key.getEncoded ());
            ska.addArray (client_ephemeral_key.getEncoded ());
            ska.addArray (key_management_key == null ? SecureKeyStore.ZERO_LENGTH_ARRAY : key_management_key.getEncoded ());
            ska.addInt (client_time);
            ska.addInt (session_life_time);
            ska.addShort (session_key_limit);
            attestation = ska.getResult ();

            ///////////////////////////////////////////////////////////////////////////////////
            // Optionally sign attestation
            ///////////////////////////////////////////////////////////////////////////////////
            if (!privacy_enabled)
              {
                PrivateKey attester = getAttestationKey ();
                Signature signer = Signature.getInstance (attester instanceof RSAPrivateKey ? "SHA256withRSA" : "SHA256withECDSA");
                signer.initSign (attester);
                signer.update (attestation);
                attestation = signer.sign ();
              }
          }
        catch (Exception e)
          {
            throw new SKSException (e);
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // We did it!
        ///////////////////////////////////////////////////////////////////////////////////
        SEProvisioningState ps = new SEProvisioningState ();
        ps.wrapped_session_key = session_key;
        ps.session_key_limit = session_key_limit;
        SEProvisioningData pd = new SEProvisioningData ();
        pd.client_session_id = client_session_id;
        pd.attestation = attestation;
        pd.client_ephemeral_key = client_ephemeral_key;
        pd.se_provisioning_state = ps;
        return pd;
      }
/* TODO

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
        MacBuilder verifier = key_entry.getEECertMacBuilder (METHOD_RESTORE_PRIVATE_KEY);
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

*/
    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                       verifyAndImportSymmetricKey                          //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static short verifyAndImportSymmetricKey (SEProvisioningState se_provisioning_state,
                                                     SEKeyState se_key_state,
                                                     X509Certificate ee_certificate,
                                                     byte[] symmetric_key,
                                                     byte[] mac) throws SKSException
      {
        short symmetric_key_length = 0;
        try
          {
            ///////////////////////////////////////////////////////////////////////////////////
            // Verify incoming MAC
            ///////////////////////////////////////////////////////////////////////////////////
            MacBuilder verifier = getEECertMacBuilder (se_provisioning_state,
                                                       ee_certificate,
                                                       SecureKeyStore.METHOD_IMPORT_SYMMETRIC_KEY);
            verifier.addArray (symmetric_key);
            verifier.verify (mac);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Decrypt and store symmetric key
            ///////////////////////////////////////////////////////////////////////////////////
            se_key_state.symmetric_key = decrypt (se_provisioning_state, symmetric_key);
            se_key_state.is_symmetric_key = true;
            symmetric_key_length = (short)se_key_state.symmetric_key.length; 
          }
        catch (GeneralSecurityException e)
          {
            abort (e);
          }
        return symmetric_key_length;
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                       setAndVerifyCertificatePath                          //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static void setAndVerifyCertificatePath (SEProvisioningState se_provisioning_state,
                                                    SEKeyState se_key_state,
                                                    String id,
                                                    PublicKey public_key,
                                                    X509Certificate[] certificate_path,
                                                    byte[] mac) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Verify incoming MAC
        ///////////////////////////////////////////////////////////////////////////////////
        MacBuilder verifier = getMacBuilderForMethodCall (se_provisioning_state, SecureKeyStore.METHOD_SET_CERTIFICATE_PATH);
        try
          {
            verifier.addArray (public_key.getEncoded ());
            verifier.addString (id);
            for (X509Certificate certificate : certificate_path)
              {
                byte[] der = certificate.getEncoded ();
                if (der.length > SecureKeyStore.MAX_LENGTH_CRYPTO_DATA)
                  {
                    abort ("Certificate for: " + id + " exceeds " + SecureKeyStore.MAX_LENGTH_CRYPTO_DATA + " bytes");
                  }
                verifier.addArray (der);
              }
          }
        catch (GeneralSecurityException e)
          {
            abort (e);
          }
        verifier.verify (mac);
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                              createKeyPair                                 //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static SEKeyData createKeyPair (SEProvisioningState se_provisioning_state,
                                           String id,
                                           String algorithm,
                                           byte[] server_seed,
                                           boolean device_pin_protection,
                                           String pin_policy_id,
                                           byte[] encrypted_pin_value,
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
        // Verify incoming MAC
        ///////////////////////////////////////////////////////////////////////////////////
        MacBuilder verifier = getMacBuilderForMethodCall (se_provisioning_state, SecureKeyStore.METHOD_CREATE_KEY_ENTRY);
        verifier.addString (id);
        verifier.addString (algorithm);
        verifier.addArray (server_seed == null ? SecureKeyStore.ZERO_LENGTH_ARRAY : server_seed);
        verifier.addString (pin_policy_id);
        byte[] decrypted_pin_value = null;
        if (encrypted_pin_value == null)
          {
            verifier.addString (SecureKeyStore.CRYPTO_STRING_NOT_AVAILABLE);
          }
        else
          {
            verifier.addArray (encrypted_pin_value);
            decrypted_pin_value = decrypt (se_provisioning_state, encrypted_pin_value);
          }
        verifier.addBool (enable_pin_caching);
        verifier.addByte (biometric_protection);
        verifier.addByte (export_protection);
        verifier.addByte (delete_protection);
        verifier.addByte (app_usage);
        verifier.addString (friendly_name == null ? "" : friendly_name);
        verifier.addArray (key_specifier);
        String prev_alg = "\0";
        for (String endorsed_algorithm : endorsed_algorithms)
          {
            ///////////////////////////////////////////////////////////////////////////////////
            // Check that the algorithms are sorted and known
            ///////////////////////////////////////////////////////////////////////////////////
            if (prev_alg.compareTo (endorsed_algorithm) >= 0)
              {
                abort ("Duplicate or incorrectly sorted algorithm: " + endorsed_algorithm);
              }
            Algorithm alg = supported_algorithms.get (endorsed_algorithm);
            if (alg == null || alg.mask == 0)
              {
                abort ("Unsupported algorithm: " + endorsed_algorithm);
              }
            if ((alg.mask & ALG_NONE) != 0 && endorsed_algorithms.length > 1)
              {
                abort ("Algorithm must be alone: " + endorsed_algorithm);
              }
            verifier.addString (endorsed_algorithm);
          }
        verifier.verify (mac);

        ///////////////////////////////////////////////////////////////////////////////////
        // Decode key algorithm specifier
        ///////////////////////////////////////////////////////////////////////////////////
        AlgorithmParameterSpec alg_par_spec = null;
        if (key_specifier == null || key_specifier.length == 0)
          {
            abort ("Empty \"KeySpecifier\"");
          }
        if (key_specifier[0] == SecureKeyStore.KEY_ALGORITHM_TYPE_RSA)
          {
            if (key_specifier.length != 7)
              {
                abort ("Incorrectly formatted RSA \"KeySpecifier\"");
              }
            int rsa_key_size = getShort (key_specifier, 1);
            BigInteger exponent = BigInteger.valueOf ((getShort (key_specifier, 3) << 16) + getShort (key_specifier, 5));
            if (!SKS_RSA_EXPONENT_SUPPORT && exponent.intValue () != 0)
              {
                abort ("Explicit RSA exponent setting not supported by this device");
              }
            checkRSAKeyCompatibility (rsa_key_size, exponent, "\"KeySpecifier\"");
            alg_par_spec = new RSAKeyGenParameterSpec (rsa_key_size,
                                                       exponent.intValue () == 0 ? RSAKeyGenParameterSpec.F4 : exponent);
          }
        else if (key_specifier[0] == SecureKeyStore.KEY_ALGORITHM_TYPE_EC)
          {
            StringBuffer ec_uri = new StringBuffer ();
            for (int i = 1; i < key_specifier.length; i++)
              {
                ec_uri.append ((char) key_specifier[i]);
              }
            Algorithm alg = supported_algorithms.get (ec_uri.toString ());
            if (alg == null || (alg.mask & ALG_EC_CRV) == 0)
              {
                abort ("Unsupported eliptic curve: " + ec_uri + " in \"KeySpecifier\"");
              }
            alg_par_spec = new ECGenParameterSpec (alg.jce_name);
          }
        else
          {
            abort ("Unknown key type in \"KeySpecifier\"");
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
            MacBuilder cka = getMacBuilderForMethodCall (se_provisioning_state, SecureKeyStore.KDF_DEVICE_ATTESTATION);
            cka.addString (id);
            cka.addArray (public_key.getEncoded ());
            byte[] attestation = cka.getResult ();

            ///////////////////////////////////////////////////////////////////////////////////
            // Finally, create a key entry
            ///////////////////////////////////////////////////////////////////////////////////
            SEKeyState se_key_state = new SEKeyState ();
            se_key_state.private_key = private_key;
            SEKeyData se_key_data = new SEKeyData ();
            se_key_data.se_key_state = se_key_state;
            se_key_data.attestation = attestation;
            se_key_data.public_key = public_key;
            se_key_data.decrypted_pin_value = decrypted_pin_value;
            return se_key_data;
          }
        catch (GeneralSecurityException e)
          {
            abort (e);
          }
        return null;    // For the compiler only...
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                            verifyPINPolicy                                 //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////

    public static void verifyPINPolicy (SEProvisioningState se_provisioning_state,
                                        String id,
                                        String puk_policy_id,
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
        // Verify incoming MAC
        ///////////////////////////////////////////////////////////////////////////////////
        MacBuilder verifier = getMacBuilderForMethodCall (se_provisioning_state, SecureKeyStore.METHOD_CREATE_PIN_POLICY);
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
        verifier.verify (mac);
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                              getPUKValue                                   //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static byte[] getPUKValue (SEProvisioningState se_provisioning_state,
                                      String id,
                                      byte[] puk_value,
                                      byte format,
                                      short retry_limit,
                                      byte[] mac) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get value
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] decrypted_puk_value = decrypt (se_provisioning_state, puk_value);

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify incoming MAC
        ///////////////////////////////////////////////////////////////////////////////////
        MacBuilder verifier = getMacBuilderForMethodCall (se_provisioning_state, SecureKeyStore.METHOD_CREATE_PUK_POLICY);
        verifier.addString (id);
        verifier.addArray (puk_value);
        verifier.addByte (format);
        verifier.addShort (retry_limit);
        verifier.verify (mac);

        ///////////////////////////////////////////////////////////////////////////////////
        // Success, create object
        ///////////////////////////////////////////////////////////////////////////////////
        return decrypted_puk_value;
      }
  }