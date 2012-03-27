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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.Serializable;

import java.math.BigInteger;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyPair;
import java.security.MessageDigest;
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
import java.util.LinkedHashMap;

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
    static final String SKS_VENDOR_DESCRIPTION             = "SKS TEE/SE RI - SE Module";
    static final String SKS_UPDATE_URL                     = null;  // Change here to test or disable
    static final boolean SKS_DEVICE_PIN_SUPPORT            = true;  // Change here to test or disable
    static final boolean SKS_BIOMETRIC_SUPPORT             = true;  // Change here to test or disable
    static final boolean SKS_RSA_EXPONENT_SUPPORT          = true;  // Change here to test or disable

    /////////////////////////////////////////////////////////////////////////////////////////////
    // Specific TEE/SE constants.  We want the SE to provide strong entropy without hampering
    // the TEE from introducing monotonic sequence numbers to facilitate easy lookup
    /////////////////////////////////////////////////////////////////////////////////////////////
    public static final int MAX_LENGTH_TEE_CS_PREFIX = 16;

    static final char[] MODIFIED_BASE64 = {'A','B','C','D','E','F','G','H',
                                           'I','J','K','L','M','N','O','P',
                                           'Q','R','S','T','U','V','W','X',
                                           'Y','Z','a','b','c','d','e','f',
                                           'g','h','i','j','k','l','m','n',
                                           'o','p','q','r','s','t','u','v',
                                           'w','x','y','z','0','1','2','3',
                                           '4','5','6','7','8','9','-','_'};

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
    // The embedded SE "Master Key" that is the origin for the seal and integrity functions 
    /////////////////////////////////////////////////////////////////////////////////////////////
    static final byte[] SE_MASTER_SECRET = {(byte)0x80, (byte)0xD4, (byte)0xCA, (byte)0xBB, (byte)0x8A, (byte)0x22, (byte)0xA3, (byte)0xD0,
                                            (byte)0x18, (byte)0x07, (byte)0x1A, (byte)0xD5, (byte)0x97, (byte)0x8D, (byte)0x7D, (byte)0x22,
                                            (byte)0x65, (byte)0x40, (byte)0x36, (byte)0xDD, (byte)0x28, (byte)0xDC, (byte)0x63, (byte)0x73,
                                            (byte)0xC5, (byte)0xF8, (byte)0x61, (byte)0x1C, (byte)0xB6, (byte)0xB6, (byte)0x27, (byte)0xF8};
    
    /////////////////////////////////////////////////////////////////////////////////////////////
    // The SE "Master Key" is always derived 
    /////////////////////////////////////////////////////////////////////////////////////////////
    static final byte[] SESSION_KEY_ENCRYPTION = {'S','e','s','s','i','o','n','K','e','y'};

    static final byte[] USER_KEY_ENCRYPTION    = {'U','s','e','r','K','e','y'};

    static final byte[] USER_KEY_INTEGRITY     = {'I','n','t','e','g','r','i','t','y'};

    static byte[] user_key_wrapper_secret;
    
    static
      {
        try
          {
            MacBuilder mac_builder = new MacBuilder (SE_MASTER_SECRET);
            mac_builder.addVerbatim (USER_KEY_ENCRYPTION);
            user_key_wrapper_secret = mac_builder.getResult ();
          }
        catch (GeneralSecurityException e)
          {
            throw new RuntimeException (e);
          }
      }

    static byte[] session_key_wrapper_secret;
    
    static
      {
        try
          {
            MacBuilder mac_builder = new MacBuilder (SE_MASTER_SECRET);
            mac_builder.addVerbatim (SESSION_KEY_ENCRYPTION);
            session_key_wrapper_secret = mac_builder.getResult ();
          }
        catch (GeneralSecurityException e)
          {
            throw new RuntimeException (e);
          }
      }
    
    static byte[] user_key_mac_secret;

    static
      {
        try
          {
            MacBuilder mac_builder = new MacBuilder (SE_MASTER_SECRET);
            mac_builder.addVerbatim (USER_KEY_INTEGRITY);
            user_key_mac_secret = mac_builder.getResult ();
          }
        catch (GeneralSecurityException e)
          {
            throw new RuntimeException (e);
          }
      }

    static final char[] ATTESTATION_KEY_PASSWORD =  {'t','e','s','t','i','n','g'};

    static final String ATTESTATION_KEY_ALIAS = "mykey";
    
    static class ByteReader extends DataInputStream
      {
        ByteReader (byte[] input)
          {
            super (new ByteArrayInputStream (input));
          }

        byte[] readArray (int expected_length) throws IOException
          {
            int length = readUnsignedShort ();
            if (expected_length > 0 && expected_length != length)
              {
                throw new IOException ("Array length error");
              }
            byte[] data = new byte[length];
            readFully (data);
            return data;
          }

        byte[] getArray () throws IOException
          {
            return readArray (0);
          }

        void checkEOF () throws IOException
          {
            if (read () != -1)
              {
                throw new IOException ("Length error reading sealed data");
              }
          }
      }
    
    static class ByteWriter
      {
        ByteArrayOutputStream baos = new ByteArrayOutputStream ();
        DataOutputStream das = new DataOutputStream (baos);

        void writeBoolean (boolean value) throws IOException
          {
            das.writeBoolean (value);
          }

        void writeArray (byte[] value) throws IOException
          {
            das.writeShort (value.length);
            das.write (value);
          }

        public byte[] getData () throws IOException
          {
            das.flush ();
            return baos.toByteArray ();
          }

        void writeShort (int value) throws IOException
          {
            das.writeShort (value);            
          }
      }

    static class UnwrappedKey
      {
        byte[] wrapped_key;

        boolean is_symmetric;
        
        boolean is_exportable;
        
        byte[] sha256_of_public_key_or_ee_certificate;
        
        PrivateKey private_key;
        
        byte[] symmetric_key;

        byte[] mac;
    
        boolean isRSA ()
          {
            return private_key instanceof RSAKey;
          }

        public void createMAC (byte[] os_instance_key) throws GeneralSecurityException
          {
            MacBuilder mac_builder = new MacBuilder (deriveKey (os_instance_key, user_key_mac_secret));
            mac_builder.addBool (is_exportable);
            mac_builder.addBool (is_symmetric);
            mac_builder.addArray (wrapped_key);
            mac = mac_builder.getResult ();
          }

        byte[] writeKey (byte[] os_instance_key) throws GeneralSecurityException
          {
            try
              {
                ByteWriter byte_writer = new ByteWriter ();
                byte_writer.writeArray (wrapped_key);
                byte_writer.writeBoolean (is_symmetric);
                byte_writer.writeBoolean (is_exportable);
                byte_writer.writeArray (sha256_of_public_key_or_ee_certificate);
                createMAC (os_instance_key);
                byte_writer.writeArray (mac);
                return byte_writer.getData ();
              }
            catch (IOException e)
              {
                throw new GeneralSecurityException (e);
              }
          }

        void readKey (byte[] os_instance_key, byte[] sealed_key) throws GeneralSecurityException
          {
            try
              {
                ByteReader byte_reader = new ByteReader (sealed_key);
                wrapped_key = byte_reader.getArray ();
                is_symmetric = byte_reader.readBoolean ();
                is_exportable = byte_reader.readBoolean ();
                sha256_of_public_key_or_ee_certificate = byte_reader.readArray (32);
                byte[] old_mac = mac = byte_reader.readArray (32);
                byte_reader.checkEOF ();
                createMAC (os_instance_key);
                if (!Arrays.equals (old_mac, mac))
                  {
                    throw new GeneralSecurityException ("Sealed key MAC error");
                  }
              }
            catch (IOException e)
              {
                throw new GeneralSecurityException (e);
              }
          }
      }

    static class UnwrappedSessionKey
      {
        byte[] session_key;
        
        byte[] wrapped_session_key;
        
        short mac_sequence_counter;

        short session_key_limit;

        public void readKey (byte[] provisioning_state) throws GeneralSecurityException
          {
            try
              {
                ByteReader byte_reader = new ByteReader (provisioning_state);
                wrapped_session_key = byte_reader.readArray (AES_CBC_PKCS5_PADDING + 32);
                mac_sequence_counter = byte_reader.readShort ();
                session_key_limit = byte_reader.readShort ();
                byte_reader.checkEOF ();
              }
            catch (IOException e)
              {
                throw new GeneralSecurityException (e);
              }
          }

        byte[] writeKey () throws SKSException
          {
            try
              {
                ByteWriter byte_writer = new ByteWriter ();
                byte_writer.writeArray (wrapped_session_key);
                byte_writer.writeShort (mac_sequence_counter);
                byte_writer.writeShort (session_key_limit);
                return byte_writer.getData ();
              }
            catch (IOException e)
              {
                throw new SKSException (e);
              }
          }
      }
    
    /////////////////////////////////////////////////////////////////////////////////////////////
    // Utility Functions
    /////////////////////////////////////////////////////////////////////////////////////////////

    static byte[] deriveKey (byte[] os_instance_key, byte[] original_key) throws GeneralSecurityException
      {
        if (os_instance_key.length != 32)
          {
            throw new GeneralSecurityException ("\"os_instance_key\" length error: " + os_instance_key.length);
          }
        byte[] result = new byte[32];
        for (int i = 0; i < 32; i++)
          {
            result[i] = (byte)(os_instance_key[i] ^ original_key[i]);
          }
        return result;
      }

    static UnwrappedKey getUnwrappedKey (byte[] os_instance_key, byte[] sealed_key) throws SKSException
      {
        UnwrappedKey unwrapped_key = new UnwrappedKey ();
        try
          {
            unwrapped_key.readKey (os_instance_key, sealed_key);
            byte[] data = unwrapped_key.wrapped_key;
            Cipher crypt = Cipher.getInstance ("AES/CBC/PKCS5Padding");
            crypt.init (Cipher.DECRYPT_MODE, new SecretKeySpec (deriveKey (os_instance_key, user_key_wrapper_secret),"AES"), new IvParameterSpec (data, 0, 16));
            byte[] raw_key = crypt.doFinal (data, 16, data.length - 16);
            if (unwrapped_key.is_symmetric)
              {
                unwrapped_key.is_symmetric = true;
                unwrapped_key.symmetric_key = raw_key;
              }
            else
              {
                unwrapped_key.private_key = raw2PrivateKey (raw_key);
              }
          }
        catch (GeneralSecurityException e)
          {
            abort (e);
          }
        return unwrapped_key;
      }

    static byte[] wrapKey (byte[] os_instance_key, UnwrappedKey unwrapped_key, byte[] raw_key) throws GeneralSecurityException
      {
        Cipher crypt = Cipher.getInstance ("AES/CBC/PKCS5Padding");
        byte[] iv = new byte[16];
        new SecureRandom ().nextBytes (iv);
        crypt.init (Cipher.ENCRYPT_MODE,  new SecretKeySpec (deriveKey (os_instance_key, user_key_wrapper_secret), "AES"), new IvParameterSpec (iv));
        unwrapped_key.wrapped_key = addArrays (iv, crypt.doFinal (raw_key));
        return unwrapped_key.writeKey (os_instance_key);
      }

    static UnwrappedSessionKey getUnwrappedSessionKey (byte[] os_instance_key, byte[] provisioning_state) throws SKSException
      {
        UnwrappedSessionKey unwrapped_session_key = new UnwrappedSessionKey ();
        try
          {
            unwrapped_session_key.readKey (provisioning_state);
            byte[] data = unwrapped_session_key.wrapped_session_key;
            Cipher crypt = Cipher.getInstance ("AES/CBC/PKCS5Padding");
            crypt.init (Cipher.DECRYPT_MODE, new SecretKeySpec (deriveKey (os_instance_key, session_key_wrapper_secret), "AES"), new IvParameterSpec (data, 0, 16));
            unwrapped_session_key.session_key = crypt.doFinal (data, 16, data.length - 16);
          }
        catch (GeneralSecurityException e)
          {
            abort (e);
          }
        return unwrapped_session_key;
      }

    static byte[] wrapSessionKey (byte[] os_instance_key, UnwrappedSessionKey unwrapped_session_key, byte[] raw_key, short session_key_limit) throws GeneralSecurityException, SKSException
      {
        Cipher crypt = Cipher.getInstance ("AES/CBC/PKCS5Padding");
        byte[] iv = new byte[16];
        new SecureRandom ().nextBytes (iv);
        crypt.init (Cipher.ENCRYPT_MODE, new SecretKeySpec (deriveKey (os_instance_key, session_key_wrapper_secret), "AES"), new IvParameterSpec (iv));
        unwrapped_session_key.wrapped_session_key = addArrays (iv, crypt.doFinal (raw_key));
        unwrapped_session_key.session_key_limit = session_key_limit;
        return unwrapped_session_key.writeKey ();
      }

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

    static void abort (Exception e) throws SKSException
      {
        throw new SKSException (e, SKSException.ERROR_CRYPTO);
      }
  
    static void checkIDSyntax (String identifier, String symbolic_name) throws SKSException
      {
        boolean flag = false;
        if (identifier.length () == 0 || identifier.length () > SecureKeyStore.MAX_LENGTH_ID_TYPE)
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
            abort ("Malformed \"" + symbolic_name + "\" : " + identifier);
          }
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

    static MacBuilder getMacBuilder (UnwrappedSessionKey unwrapped_session_key, byte[] key_modifier) throws SKSException
      {
        if (unwrapped_session_key.session_key_limit-- <= 0)
          {
            abort ("\"SessionKeyLimit\" exceeded");
          }
        try
          {
            return new MacBuilder (addArrays (unwrapped_session_key.session_key, key_modifier));
          }
        catch (GeneralSecurityException e)
          {
            throw new SKSException (e);
          }
      }

    static MacBuilder getMacBuilderForMethodCall (UnwrappedSessionKey unwrapped_session_key, byte[] method) throws SKSException
      {
        short q = unwrapped_session_key.mac_sequence_counter++;
        return getMacBuilder (unwrapped_session_key, addArrays (method, new byte[]{(byte)(q >>> 8), (byte)q}));
      }

    static MacBuilder getEECertMacBuilder (UnwrappedSessionKey unwrapped_session_key,
                                           UnwrappedKey unwrapped_key,
                                           X509Certificate ee_certificate,
                                           byte[] method) throws SKSException, GeneralSecurityException
      {
        byte[] bin_ee = ee_certificate.getEncoded ();
        if (!Arrays.equals (unwrapped_key.sha256_of_public_key_or_ee_certificate, getSHA256 (bin_ee)))
          {
            throw new GeneralSecurityException ("\"EECertificate\" Inconsistency test failed");
          }
        MacBuilder mac_builder = getMacBuilderForMethodCall (unwrapped_session_key, method);
        mac_builder.addArray (bin_ee);
        return mac_builder;
      }

    static byte[] decrypt (UnwrappedSessionKey unwrapped_session_key, byte[] data) throws SKSException
      {
        byte[] key = getMacBuilder (unwrapped_session_key, 
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

    static void validateTargetKeyLocal (MacBuilder verifier,
                                        PublicKey key_management_key,
                                        X509Certificate target_key_ee_certificate,
                                        int target_key_handle,
                                        byte[] authorization,
                                        boolean privacy_enabled,
                                        UnwrappedSessionKey unwrapped_session_key,
                                        byte[] mac) throws SKSException, GeneralSecurityException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Verify MAC
        ///////////////////////////////////////////////////////////////////////////////////
        verifier.addArray (authorization);
        verifier.verify (mac);

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify KM signature
        ///////////////////////////////////////////////////////////////////////////////////
        Signature km_verify = Signature.getInstance (key_management_key instanceof RSAPublicKey ? "SHA256WithRSA" : "SHA256WithECDSA");
        km_verify.initVerify (key_management_key);
        km_verify.update (getMacBuilder (unwrapped_session_key, getDeviceID (privacy_enabled)).addVerbatim (target_key_ee_certificate.getEncoded ()).getResult ());
        if (!km_verify.verify (authorization))
          {
            abort ("\"Authorization\" signature did not verify for key #" + target_key_handle);
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

    static void testSymmetricKey (String algorithm,
                                  byte[] symmetric_key,
                                  String key_id) throws SKSException
      {
        Algorithm alg = getAlgorithm (algorithm);
        if ((alg.mask & ALG_SYM_ENC) != 0)
          {
            int l = symmetric_key.length;
            if (l == 16) l = ALG_SYML_128;
            else if (l == 24) l = ALG_SYML_192;
            else if (l == 32) l = ALG_SYML_256;
            else
              l = 0;
            if ((l & alg.mask) == 0)
              {
                abort ("Key " + key_id + " has wrong size (" + symmetric_key.length + ") for algorithm: " + algorithm);
              }
          }
      }

    static Algorithm checkKeyAndAlgorithm (UnwrappedKey unwrapped_key, int key_handle, String algorithm, int expected_type) throws SKSException
      {
        Algorithm alg = getAlgorithm (algorithm);
        if ((alg.mask & expected_type) == 0)
          {
            abort ("Algorithm does not match operation: " + algorithm, SKSException.ERROR_ALGORITHM);
          }
        if (((alg.mask & (ALG_SYM_ENC | ALG_HMAC)) != 0) ^ unwrapped_key.is_symmetric)
          {
            abort ((unwrapped_key.is_symmetric ? "S" : "As") + "ymmetric key #" + key_handle + " is incompatible with: " + algorithm, SKSException.ERROR_ALGORITHM);
          }
        if (unwrapped_key.is_symmetric)
          {
            testSymmetricKey (algorithm, unwrapped_key.symmetric_key, "#" + key_handle);
          }
        else if (unwrapped_key.isRSA () ^ (alg.mask & ALG_RSA_KEY) != 0)
          {
            abort ((unwrapped_key.isRSA () ? "RSA" : "EC") + " key #" + key_handle + " is incompatible with: " + algorithm, SKSException.ERROR_ALGORITHM);
          }
        return alg;
      }

    public static void testKeyAndAlgorithmCompliance (byte[] os_instance_key,
                                                      byte[] sealed_key,
                                                      String algorithm,
                                                      String id) throws SKSException
      {
        Algorithm alg = getAlgorithm (algorithm);
        UnwrappedKey unwrapped_key = getUnwrappedKey (os_instance_key, sealed_key);
        if ((alg.mask & ALG_NONE) == 0)
          {
            ///////////////////////////////////////////////////////////////////////////////////
            // A non-null endorsed algorithm found.  Symmetric or asymmetric key?
            ///////////////////////////////////////////////////////////////////////////////////
            if (((alg.mask & (ALG_SYM_ENC | ALG_HMAC)) == 0) ^ unwrapped_key.is_symmetric)
              {
                if (unwrapped_key.is_symmetric)
                  {
                    ///////////////////////////////////////////////////////////////////////////////////
                    // Symmetric. AES algorithms only operates on 128, 192, and 256 bit keys
                    ///////////////////////////////////////////////////////////////////////////////////
                    testSymmetricKey (algorithm, unwrapped_key.symmetric_key, id);
                    return;
                  }
                else
                  {
                    ///////////////////////////////////////////////////////////////////////////////////
                    // Asymmetric.  Check that algorithms match RSA or EC
                    ///////////////////////////////////////////////////////////////////////////////////
                    if (((alg.mask & ALG_RSA_KEY) == 0) ^ unwrapped_key.isRSA ())
                      {
                        return;
                      }
                  }
              }
            abort ((unwrapped_key.is_symmetric ? "Symmetric" : unwrapped_key.isRSA () ? "RSA" : "EC") + 
                   " key " + id + " does not match algorithm: " + algorithm);
          }
      }
    
    static byte[] getSHA256 (byte[] encoded) throws GeneralSecurityException
      {
        return MessageDigest.getInstance ("SHA-256").digest (encoded);
      }

    static PrivateKey raw2PrivateKey (byte[] pkcs8_private_key) throws GeneralSecurityException
      {
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
        return KeyFactory.getInstance (rsa_flag ? "RSA" : "EC").generatePrivate (key_spec);
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
    public static void checkKeyPair (byte[] os_instance_key,
                                     byte[] sealed_key, 
                                     PublicKey public_key,
                                     String id) throws SKSException
      {
        UnwrappedKey unwrapped_key = getUnwrappedKey (os_instance_key, sealed_key);
        if (public_key instanceof RSAPublicKey ^ unwrapped_key.isRSA ())
          {
            abort ("RSA/EC mixup between public and private keys for: " + id);
          }
        if (unwrapped_key.isRSA ())
          {
            if (!((RSAPublicKey)public_key).getPublicExponent ().equals (((RSAPrivateCrtKey)unwrapped_key.private_key).getPublicExponent ()) ||
                !((RSAPublicKey)public_key).getModulus ().equals (((RSAPrivateKey)unwrapped_key.private_key).getModulus ()))
              {
                abort ("RSA mismatch between public and private keys for: " + id);
              }
          }
        else
          {
            try
              {
                Signature ec_signer = Signature.getInstance ("SHA256withECDSA");
                ec_signer.initSign (unwrapped_key.private_key);
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
    //                           executeSessionSign                               //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static byte[] executeSessionSign (byte[] os_instance_key,
                                             byte[] provisioning_state,
                                             byte[] data) throws SKSException
      {
        return getMacBuilder (getUnwrappedSessionKey (os_instance_key, provisioning_state),
                              SecureKeyStore.KDF_EXTERNAL_SIGNATURE).addVerbatim (data).getResult ();
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                        executeAsymmetricDecrypt                            //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static byte[] executeAsymmetricDecrypt (byte[] os_instance_key,
                                                   byte[] sealed_key, 
                                                   int key_handle,
                                                   String algorithm,
                                                   byte[] parameters,
                                                   byte[] data) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Unwrap the key to use
        ///////////////////////////////////////////////////////////////////////////////////
        UnwrappedKey unwrapped_key = getUnwrappedKey (os_instance_key, sealed_key);

        ///////////////////////////////////////////////////////////////////////////////////
        // Check input arguments
        ///////////////////////////////////////////////////////////////////////////////////
        Algorithm alg = checkKeyAndAlgorithm (unwrapped_key, key_handle, algorithm, ALG_ASYM_ENC);
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
            cipher.init (Cipher.DECRYPT_MODE, unwrapped_key.private_key);
            return cipher.doFinal (data);
          }
        catch (Exception e)
          {
            throw new SKSException (e, SKSException.ERROR_CRYPTO);
          }
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                            executeSignHash                                 //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static byte[] executeSignHash (byte[] os_instance_key,
                                          byte[] sealed_key,
                                          int key_handle,
                                          String algorithm,
                                          byte[] parameters,
                                          byte[] data) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Unwrap the key to use
        ///////////////////////////////////////////////////////////////////////////////////
        UnwrappedKey unwrapped_key = getUnwrappedKey (os_instance_key, sealed_key);

        ///////////////////////////////////////////////////////////////////////////////////
        // Check input arguments
        ///////////////////////////////////////////////////////////////////////////////////
        Algorithm alg = checkKeyAndAlgorithm (unwrapped_key, key_handle, algorithm, ALG_ASYM_SGN);
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
            if (unwrapped_key.isRSA () && hash_len > 0)
              {
                data = addArrays (hash_len == 20 ? DIGEST_INFO_SHA1 : DIGEST_INFO_SHA256, data);
              }
            Signature signature = Signature.getInstance (alg.jce_name);
            signature.initSign (unwrapped_key.private_key);
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
    public static byte[] executeHMAC (byte[] os_instance_key,
                                      byte[] sealed_key,
                                      int key_handle,
                                      String algorithm,
                                      byte[] data) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Unwrap the key to use
        ///////////////////////////////////////////////////////////////////////////////////
        UnwrappedKey unwrapped_key = getUnwrappedKey (os_instance_key, sealed_key);

        ///////////////////////////////////////////////////////////////////////////////////
        // Check input arguments
        ///////////////////////////////////////////////////////////////////////////////////
        Algorithm alg = checkKeyAndAlgorithm (unwrapped_key, key_handle, algorithm, ALG_HMAC);
 
        ///////////////////////////////////////////////////////////////////////////////////
        // Finally, perform operation
        ///////////////////////////////////////////////////////////////////////////////////
        try
          {
            Mac mac = Mac.getInstance (alg.jce_name);
            mac.init (new SecretKeySpec (unwrapped_key.symmetric_key, "RAW"));
            return mac.doFinal (data);
          }
        catch (GeneralSecurityException e)
          {
            throw new SKSException (e, SKSException.ERROR_CRYPTO);
          }
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                      executeSymmetricEncryption                            //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static byte[] executeSymmetricEncryption (byte[] os_instance_key,
                                                     byte[] sealed_key,
                                                     int key_handle,
                                                     String algorithm,
                                                     boolean mode,
                                                     byte[] iv,
                                                     byte[] data) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Unwrap the key to use
        ///////////////////////////////////////////////////////////////////////////////////
        UnwrappedKey unwrapped_key = getUnwrappedKey (os_instance_key, sealed_key);

        ///////////////////////////////////////////////////////////////////////////////////
        // Check input arguments
        ///////////////////////////////////////////////////////////////////////////////////
        Algorithm alg = checkKeyAndAlgorithm (unwrapped_key, key_handle, algorithm, ALG_SYM_ENC);
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
            SecretKeySpec sk = new SecretKeySpec (unwrapped_key.symmetric_key, "AES");
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
        catch (GeneralSecurityException e)
          {
            throw new SKSException (e, SKSException.ERROR_CRYPTO);
          }
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                         executeKeyAgreement                                //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static byte[] executeKeyAgreement (byte[] os_instance_key,
                                              byte[] sealed_key,
                                              int key_handle,
                                              String algorithm,
                                              byte[] parameters,
                                              ECPublicKey public_key) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Unwrap the key to use
        ///////////////////////////////////////////////////////////////////////////////////
        UnwrappedKey unwrapped_key = getUnwrappedKey (os_instance_key, sealed_key);

        ///////////////////////////////////////////////////////////////////////////////////
        // Check input arguments
        ///////////////////////////////////////////////////////////////////////////////////
        Algorithm alg = checkKeyAndAlgorithm (unwrapped_key, key_handle, algorithm, ALG_ASYM_KA);
        if (parameters != null) // Only support external KDFs yet...
          {
            abort ("\"Parameters\" for key #" + key_handle + " do not match algorithm");
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Check that the key type matches the algorithm
        ///////////////////////////////////////////////////////////////////////////////////
        checkECKeyCompatibility (public_key, "\"PublicKey\"");

        ///////////////////////////////////////////////////////////////////////////////////
        // Finally, perform operation
        ///////////////////////////////////////////////////////////////////////////////////
        try
          {
            KeyAgreement key_agreement = KeyAgreement.getInstance (alg.jce_name);
            key_agreement.init (unwrapped_key.private_key);
            key_agreement.doPhase (public_key, true);
            return key_agreement.generateSecret ();
          }
        catch (GeneralSecurityException e)
          {
            throw new SKSException (e, SKSException.ERROR_CRYPTO);
          }
      }

    
    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                              unwrapKey                                     //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static byte[] unwrapKey (byte[] os_instance_key, byte[] sealed_key) throws SKSException
      {
        UnwrappedKey unwrapped_key = getUnwrappedKey (os_instance_key, sealed_key);
        if (unwrapped_key.is_exportable)
          {
            return unwrapped_key.is_symmetric ? unwrapped_key.symmetric_key : unwrapped_key.private_key.getEncoded ();
          }
        throw new SKSException ("TEE export violation attempt");
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                           validateTargetKey2                               //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static byte[] validateTargetKey2 (byte[] os_instance_key,
                                             X509Certificate target_key_ee_certificate,
                                             int target_key_handle,
                                             PublicKey key_management_key,
                                             X509Certificate ee_certificate,
                                             byte[] sealed_key,
                                             boolean privacy_enabled,
                                             byte[] method,
                                             byte[] authorization,
                                             byte[] provisioning_state,
                                             byte[] mac) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Retrieve session key
        ///////////////////////////////////////////////////////////////////////////////////
        UnwrappedSessionKey unwrapped_session_key = getUnwrappedSessionKey (os_instance_key, provisioning_state);

        ///////////////////////////////////////////////////////////////////////////////////
        // Unwrap the new key
        ///////////////////////////////////////////////////////////////////////////////////
        UnwrappedKey unwrapped_key = getUnwrappedKey (os_instance_key, sealed_key);

        try
          {
            ///////////////////////////////////////////////////////////////////////////////////
            // Validate
            ///////////////////////////////////////////////////////////////////////////////////
            validateTargetKeyLocal (getEECertMacBuilder (unwrapped_session_key,
                                                         unwrapped_key,
                                                         ee_certificate,
                                                         method),
                                    key_management_key,
                                    target_key_ee_certificate,
                                    target_key_handle,
                                    authorization,
                                    privacy_enabled,
                                    unwrapped_session_key,
                                    mac);
          }
        catch (GeneralSecurityException e)
          {
            abort (e);
          }
        ///////////////////////////////////////////////////////////////////////////////////
        // Success, return updated session data
        ///////////////////////////////////////////////////////////////////////////////////
        return unwrapped_session_key.writeKey ();
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                           validateTargetKey                                //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static byte[] validateTargetKey (byte[] os_instance_key,
                                            X509Certificate target_key_ee_certificate,
                                            int target_key_handle,
                                            PublicKey key_management_key,
                                            boolean privacy_enabled,
                                            byte[] method,
                                            byte[] authorization,
                                            byte[] provisioning_state,
                                            byte[] mac) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Retrieve session key
        ///////////////////////////////////////////////////////////////////////////////////
        UnwrappedSessionKey unwrapped_session_key = getUnwrappedSessionKey (os_instance_key, provisioning_state);

        try
          {
            ///////////////////////////////////////////////////////////////////////////////////
            // Validate
            ///////////////////////////////////////////////////////////////////////////////////
            validateTargetKeyLocal (getMacBuilderForMethodCall (unwrapped_session_key, method), 
                                    key_management_key,
                                    target_key_ee_certificate,
                                    target_key_handle,
                                    authorization,
                                    privacy_enabled,
                                    unwrapped_session_key,
                                    mac);
          }
        catch (GeneralSecurityException e)
          {
            abort (e);
          }
        ///////////////////////////////////////////////////////////////////////////////////
        // Success, return updated session data
        ///////////////////////////////////////////////////////////////////////////////////
        return unwrapped_session_key.writeKey ();
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                         closeProvisioningAttest                            //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static byte[] closeProvisioningAttest (byte[] os_instance_key,
                                                  byte[] provisioning_state,
                                                  String server_session_id,
                                                  String client_session_id,
                                                  String issuer_uri,
                                                  byte[] nonce,
                                                  byte[] mac) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Retrieve session key
        ///////////////////////////////////////////////////////////////////////////////////
        UnwrappedSessionKey unwrapped_session_key = getUnwrappedSessionKey (os_instance_key, provisioning_state);
        
        ///////////////////////////////////////////////////////////////////////////////////
        // Check ID syntax
        ///////////////////////////////////////////////////////////////////////////////////
        checkIDSyntax (client_session_id, "ClientSessionID");
        checkIDSyntax (server_session_id, "ServerSessionID");

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify incoming MAC
        ///////////////////////////////////////////////////////////////////////////////////
        MacBuilder verifier = getMacBuilderForMethodCall (unwrapped_session_key, SecureKeyStore.METHOD_CLOSE_PROVISIONING_SESSION);
        verifier.addString (client_session_id);
        verifier.addString (server_session_id);
        verifier.addString (issuer_uri);
        verifier.addArray (nonce);
        verifier.verify (mac);

        ///////////////////////////////////////////////////////////////////////////////////
        // Generate the attestation in advance => checking SessionKeyLimit before "commit"
        ///////////////////////////////////////////////////////////////////////////////////
        MacBuilder close_attestation = getMacBuilderForMethodCall (unwrapped_session_key, SecureKeyStore.KDF_DEVICE_ATTESTATION);
        close_attestation.addArray (nonce);
        close_attestation.addString (SecureKeyStore.ALGORITHM_SESSION_ATTEST_1);
        return close_attestation.getResult ();
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                         createProvisioningData                             //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static SEProvisioningData createProvisioningData (byte[] os_instance_key,
                                                             String algorithm,
                                                             boolean privacy_enabled,
                                                             String server_session_id,
                                                             String tee_client_session_id_prefix,
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
        // Check ID syntax
        ///////////////////////////////////////////////////////////////////////////////////
        checkIDSyntax (tee_client_session_id_prefix, "TEEClientSessionIDPrefix");
        checkIDSyntax (server_session_id, "ServerSessionID");

        ///////////////////////////////////////////////////////////////////////////////////
        // Check TEEClientSessionIDPrefix
        ///////////////////////////////////////////////////////////////////////////////////
        if (tee_client_session_id_prefix.length () >  MAX_LENGTH_TEE_CS_PREFIX)
          {
            abort ("\"TEEClientSessionIDPrefix\" length error: " + tee_client_session_id_prefix.length ());
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
        // Create ClientSessionID.  The SE adds up to 31 random (but valid) characters
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] random = new byte[SecureKeyStore.MAX_LENGTH_ID_TYPE - tee_client_session_id_prefix.length ()];
        new SecureRandom ().nextBytes (random);
        StringBuffer buffer = new StringBuffer (tee_client_session_id_prefix);
        for (int i = 0; i < random.length; i++)
          {
            buffer.append (MODIFIED_BASE64[random[i] & 0x3F]);
          }
        String client_session_id = buffer.toString ();

        ///////////////////////////////////////////////////////////////////////////////////
        // Prepare for the big crypto...
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] attestation = null;
        byte[] session_key = null;
        ECPublicKey client_ephemeral_key = null;
        byte[] provisioning_state;
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

            ///////////////////////////////////////////////////////////////////////////////////
            // Create the wrapped session key and associated data
            ///////////////////////////////////////////////////////////////////////////////////
            provisioning_state = wrapSessionKey (os_instance_key, new UnwrappedSessionKey (), session_key, session_key_limit);
          }
        catch (Exception e)
          {
            throw new SKSException (e);
          }
        ///////////////////////////////////////////////////////////////////////////////////
        // We did it!
        ///////////////////////////////////////////////////////////////////////////////////
        SEProvisioningData se_provisioning_data = new SEProvisioningData ();
        se_provisioning_data.client_session_id = client_session_id;
        se_provisioning_data.attestation = attestation;
        se_provisioning_data.client_ephemeral_key = client_ephemeral_key;
        se_provisioning_data.provisioning_state = provisioning_state;
        return se_provisioning_data;
      }

    
    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                        verifyAndImportPrivateKey                           //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static SEPrivateKeyData verifyAndImportPrivateKey (byte[] os_instance_key,
                                                              byte[] provisioning_state,
                                                              byte[] sealed_key,
                                                              String id,
                                                              X509Certificate ee_certificate,
                                                              byte[] private_key,
                                                              byte[] mac) throws SKSException
      {
        SEPrivateKeyData se_private_key_data = new SEPrivateKeyData ();
        try
          {
            ///////////////////////////////////////////////////////////////////////////////////
            // Unwrap the key to use (verify integrity only in this case)
            ///////////////////////////////////////////////////////////////////////////////////
            UnwrappedKey unwrapped_key = getUnwrappedKey (os_instance_key, sealed_key);

            ///////////////////////////////////////////////////////////////////////////////////
            // Retrieve session key
            ///////////////////////////////////////////////////////////////////////////////////
            UnwrappedSessionKey unwrapped_session_key = getUnwrappedSessionKey (os_instance_key, provisioning_state);

            ///////////////////////////////////////////////////////////////////////////////////
            // Check ID syntax
            ///////////////////////////////////////////////////////////////////////////////////
            checkIDSyntax (id, "ID");

            ///////////////////////////////////////////////////////////////////////////////////
            // Check for key length errors
            ///////////////////////////////////////////////////////////////////////////////////
            if (private_key.length > (SecureKeyStore.MAX_LENGTH_CRYPTO_DATA + AES_CBC_PKCS5_PADDING))
              {
                abort ("Private key: " + id + " exceeds " + SecureKeyStore.MAX_LENGTH_CRYPTO_DATA + " bytes");
              }

            ///////////////////////////////////////////////////////////////////////////////////
            // Verify incoming MAC
            ///////////////////////////////////////////////////////////////////////////////////
            MacBuilder verifier = getEECertMacBuilder (unwrapped_session_key,
                                                       unwrapped_key,
                                                       ee_certificate,
                                                       SecureKeyStore.METHOD_IMPORT_PRIVATE_KEY);
            verifier.addArray (private_key);
            verifier.verify (mac);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Decrypt and store private key
            ///////////////////////////////////////////////////////////////////////////////////
            byte[] decrypted_private_key = decrypt (unwrapped_session_key, private_key);
            PrivateKey decoded_private_key = raw2PrivateKey (decrypted_private_key);
            se_private_key_data.provisioning_state = unwrapped_session_key.writeKey ();
            se_private_key_data.sealed_key = wrapKey (os_instance_key, unwrapped_key, decrypted_private_key);
            if (decoded_private_key instanceof RSAKey)
              {
                checkRSAKeyCompatibility (getRSAKeySize((RSAPrivateKey) decoded_private_key),
                                          ((RSAPrivateCrtKey)decoded_private_key).getPublicExponent (),
                                          id);
              }
            else
              {
                checkECKeyCompatibility ((ECPrivateKey)decoded_private_key, id);
              }
          }
        catch (GeneralSecurityException e)
          {
            abort (e);
          }
        ///////////////////////////////////////////////////////////////////////////////////
        // Success, return updated key and session data
        ///////////////////////////////////////////////////////////////////////////////////
        return se_private_key_data;
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                       verifyAndImportSymmetricKey                          //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static SESymmetricKeyData verifyAndImportSymmetricKey (byte[] os_instance_key,
                                                                  byte[] provisioning_state,
                                                                  byte[] sealed_key,
                                                                  String id,
                                                                  X509Certificate ee_certificate,
                                                                  byte[] symmetric_key,
                                                                  byte[] mac) throws SKSException
      {
        SESymmetricKeyData se_symmetric_key_data = new SESymmetricKeyData ();
        try
          {
            ///////////////////////////////////////////////////////////////////////////////////
            // Unwrap the key to use (verify integrity only in this case)
            ///////////////////////////////////////////////////////////////////////////////////
            UnwrappedKey unwrapped_key = getUnwrappedKey (os_instance_key, sealed_key);

            ///////////////////////////////////////////////////////////////////////////////////
            // Retrieve session key
            ///////////////////////////////////////////////////////////////////////////////////
            UnwrappedSessionKey unwrapped_session_key = getUnwrappedSessionKey (os_instance_key, provisioning_state);

            ///////////////////////////////////////////////////////////////////////////////////
            // Check ID syntax
            ///////////////////////////////////////////////////////////////////////////////////
            checkIDSyntax (id, "ID");

            ///////////////////////////////////////////////////////////////////////////////////
            // Check for key length errors
            ///////////////////////////////////////////////////////////////////////////////////
            if (symmetric_key.length > (SecureKeyStore.MAX_LENGTH_SYMMETRIC_KEY + AES_CBC_PKCS5_PADDING))
              {
                abort ("Symmetric key: " + id + " exceeds " + SecureKeyStore.MAX_LENGTH_SYMMETRIC_KEY + " bytes");
              }

            ///////////////////////////////////////////////////////////////////////////////////
            // Verify incoming MAC
            ///////////////////////////////////////////////////////////////////////////////////
            MacBuilder verifier = getEECertMacBuilder (unwrapped_session_key,
                                                       unwrapped_key,
                                                       ee_certificate,
                                                       SecureKeyStore.METHOD_IMPORT_SYMMETRIC_KEY);
            verifier.addArray (symmetric_key);
            verifier.verify (mac);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Note: This test may appear redundant but the SKS specification is quite strict
            // and does not permit certificates and private key mismatch even if the private
            // key is never used which is the case when a symmetric keys is imported 
            ///////////////////////////////////////////////////////////////////////////////////
            checkKeyPair (os_instance_key, sealed_key, ee_certificate.getPublicKey (), id);

            ///////////////////////////////////////////////////////////////////////////////////
            // Decrypt and store symmetric key
            ///////////////////////////////////////////////////////////////////////////////////
            byte[] raw_key = decrypt (unwrapped_session_key, symmetric_key);
            unwrapped_key.is_symmetric = true;
            se_symmetric_key_data.provisioning_state = unwrapped_session_key.writeKey ();
            se_symmetric_key_data.sealed_key = wrapKey (os_instance_key, unwrapped_key, raw_key);
            se_symmetric_key_data.symmetric_key_length = (short)raw_key.length; 
          }
        catch (GeneralSecurityException e)
          {
            abort (e);
          }
        ///////////////////////////////////////////////////////////////////////////////////
        // Success, return updated key and session data
        ///////////////////////////////////////////////////////////////////////////////////
        return se_symmetric_key_data;
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                          verifyAndGetExtension                             //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static SEExtensionData verifyAndGetExtension (byte[] os_instance_key,
                                                         byte[] provisioning_state,
                                                         byte[] sealed_key,
                                                         String id,
                                                         X509Certificate ee_certificate,
                                                         String type,
                                                         byte sub_type,
                                                         byte[] bin_qualifier,
                                                         byte[] extension_data,
                                                         byte[] mac) throws SKSException
      {
        SEExtensionData se_extension_data = new SEExtensionData ();
        try
          {
            ///////////////////////////////////////////////////////////////////////////////////
            // Unwrap the key to use (verify integrity only in this case)
            ///////////////////////////////////////////////////////////////////////////////////
            UnwrappedKey unwrapped_key = getUnwrappedKey (os_instance_key, sealed_key);

            ///////////////////////////////////////////////////////////////////////////////////
            // Retrieve session key
            ///////////////////////////////////////////////////////////////////////////////////
            UnwrappedSessionKey unwrapped_session_key = getUnwrappedSessionKey (os_instance_key, provisioning_state);

            ///////////////////////////////////////////////////////////////////////////////////
            // Check ID syntax
            ///////////////////////////////////////////////////////////////////////////////////
            checkIDSyntax (id, "ID");

            ///////////////////////////////////////////////////////////////////////////////////
            // Check for length errors
            ///////////////////////////////////////////////////////////////////////////////////
            if (type.length () == 0 || type.length () >  SecureKeyStore.MAX_LENGTH_URI)
              {
                abort ("URI length error: " + type.length ());
              }
            if (extension_data.length > (sub_type == SecureKeyStore.SUB_TYPE_ENCRYPTED_EXTENSION ? 
                                SecureKeyStore.MAX_LENGTH_EXTENSION_DATA + AES_CBC_PKCS5_PADDING : SecureKeyStore.MAX_LENGTH_EXTENSION_DATA))
              {
                abort ("Extension data exceeds " + SecureKeyStore.MAX_LENGTH_EXTENSION_DATA + " bytes");
              }
            if (((sub_type == SecureKeyStore.SUB_TYPE_LOGOTYPE) ^ (bin_qualifier.length != 0)) ||
                bin_qualifier.length > SecureKeyStore.MAX_LENGTH_QUALIFIER)
              {
                abort ("\"Qualifier\" length error");
              }

            ///////////////////////////////////////////////////////////////////////////////////
            // Verify incoming MAC
            ///////////////////////////////////////////////////////////////////////////////////
            MacBuilder verifier = getEECertMacBuilder (unwrapped_session_key,
                                                       unwrapped_key,
                                                       ee_certificate,
                                                       SecureKeyStore.METHOD_ADD_EXTENSION);
            verifier.addString (type);
            verifier.addByte (sub_type);
            verifier.addArray (bin_qualifier);
            verifier.addBlob (extension_data);
            verifier.verify (mac);

            ///////////////////////////////////////////////////////////////////////////////////
            // Return extension data
            ///////////////////////////////////////////////////////////////////////////////////
            se_extension_data.provisioning_state = unwrapped_session_key.writeKey ();
            se_extension_data.extension_data = sub_type == SecureKeyStore.SUB_TYPE_ENCRYPTED_EXTENSION ?
                                                       decrypt (unwrapped_session_key, extension_data) : extension_data.clone ();
          }
        catch (GeneralSecurityException e)
          {
            abort (e);
          }
        ///////////////////////////////////////////////////////////////////////////////////
        // Success, return extension data and updated session data
        ///////////////////////////////////////////////////////////////////////////////////
        return se_extension_data;
      }

    
    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                       setAndVerifyCertificatePath                          //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static SECertificateData setAndVerifyCertificatePath (byte[] os_instance_key,
                                                                 byte[] provisioning_state,
                                                                 byte[] sealed_key,
                                                                 String id,
                                                                 PublicKey public_key,
                                                                 X509Certificate[] certificate_path,
                                                                 byte[] mac) throws SKSException
      {
        SECertificateData se_certificate_data = new SECertificateData ();
        try
          {
            ///////////////////////////////////////////////////////////////////////////////////
            // Unwrap the key to use
            ///////////////////////////////////////////////////////////////////////////////////
            UnwrappedKey unwrapped_key = getUnwrappedKey (os_instance_key, sealed_key);

            ///////////////////////////////////////////////////////////////////////////////////
            // Retrieve session key
            ///////////////////////////////////////////////////////////////////////////////////
            UnwrappedSessionKey unwrapped_session_key = getUnwrappedSessionKey (os_instance_key, provisioning_state);

            ///////////////////////////////////////////////////////////////////////////////////
            // Check ID syntax
            ///////////////////////////////////////////////////////////////////////////////////
            checkIDSyntax (id, "ID");

            ///////////////////////////////////////////////////////////////////////////////////
            // Verify key consistency 
            ///////////////////////////////////////////////////////////////////////////////////
            byte[] bin_public_key = public_key.getEncoded ();
            if (!Arrays.equals (unwrapped_key.sha256_of_public_key_or_ee_certificate, getSHA256 (bin_public_key)))
              {
                throw new GeneralSecurityException ("\"PublicKey\" inconsistency test failed");
              }

            ///////////////////////////////////////////////////////////////////////////////////
            // Verify incoming MAC
            ///////////////////////////////////////////////////////////////////////////////////
            MacBuilder verifier = getMacBuilderForMethodCall (unwrapped_session_key, SecureKeyStore.METHOD_SET_CERTIFICATE_PATH);
            verifier.addArray (bin_public_key);
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
            verifier.verify (mac);

            ///////////////////////////////////////////////////////////////////////////////////
            // Update the sealed key with the certificate link
            ///////////////////////////////////////////////////////////////////////////////////
            unwrapped_key.sha256_of_public_key_or_ee_certificate = getSHA256 (certificate_path[0].getEncoded ());
            se_certificate_data.provisioning_state = unwrapped_session_key.writeKey ();
            se_certificate_data.sealed_key = wrapKey (os_instance_key, unwrapped_key, unwrapped_key.private_key.getEncoded ());
          }
        catch (GeneralSecurityException e)
          {
            abort (e);
          }
        ///////////////////////////////////////////////////////////////////////////////////
        // Success, return updated key and session data
        ///////////////////////////////////////////////////////////////////////////////////
        return se_certificate_data;
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                              createKeyPair                                 //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static SEKeyData createKeyPair (byte[] os_instance_key,
                                           byte[] provisioning_state,
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
        SEKeyData se_key_data = new SEKeyData ();
        try
          {
            ///////////////////////////////////////////////////////////////////////////////////
            // Retrieve session key
            ///////////////////////////////////////////////////////////////////////////////////
            UnwrappedSessionKey unwrapped_session_key = getUnwrappedSessionKey (os_instance_key, provisioning_state);

            ///////////////////////////////////////////////////////////////////////////////////
            // Check ID syntax
            ///////////////////////////////////////////////////////////////////////////////////
            checkIDSyntax (id, "ID");

            ///////////////////////////////////////////////////////////////////////////////////
            // Verify incoming MAC
            ///////////////////////////////////////////////////////////////////////////////////
            MacBuilder verifier = getMacBuilderForMethodCall (unwrapped_session_key, SecureKeyStore.METHOD_CREATE_KEY_ENTRY);
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
                decrypted_pin_value = decrypt (unwrapped_session_key, encrypted_pin_value);
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
                verifier.addString (prev_alg = endorsed_algorithm);
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
            MacBuilder cka = getMacBuilderForMethodCall (unwrapped_session_key, SecureKeyStore.KDF_DEVICE_ATTESTATION);
            cka.addString (id);
            cka.addArray (public_key.getEncoded ());
            byte[] attestation = cka.getResult ();

            ///////////////////////////////////////////////////////////////////////////////////
            // Finally, create the key return data
            ///////////////////////////////////////////////////////////////////////////////////
            UnwrappedKey unwrapped_key = new UnwrappedKey ();
            unwrapped_key.is_exportable = export_protection != SecureKeyStore.EXPORT_DELETE_PROTECTION_NOT_ALLOWED;
            unwrapped_key.sha256_of_public_key_or_ee_certificate = getSHA256 (public_key.getEncoded ());
            se_key_data.sealed_key = wrapKey (os_instance_key, unwrapped_key, private_key.getEncoded ());
            se_key_data.provisioning_state = unwrapped_session_key.writeKey ();
            se_key_data.attestation = attestation;
            se_key_data.public_key = public_key;
            se_key_data.decrypted_pin_value = decrypted_pin_value;
          }
        catch (GeneralSecurityException e)
          {
            abort (e);
          }
        ///////////////////////////////////////////////////////////////////////////////////
        // Success, return key data and updated session data
        ///////////////////////////////////////////////////////////////////////////////////
        return se_key_data;
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                            verifyPINPolicy                                 //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static byte[] verifyPINPolicy (byte[] os_instance_key,
                                          byte[] provisioning_state,
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
        // Retrieve session key
        ///////////////////////////////////////////////////////////////////////////////////
        UnwrappedSessionKey unwrapped_session_key = getUnwrappedSessionKey (os_instance_key, provisioning_state);

        ///////////////////////////////////////////////////////////////////////////////////
        // Check ID syntax
        ///////////////////////////////////////////////////////////////////////////////////
        checkIDSyntax (id, "ID");

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify incoming MAC
        ///////////////////////////////////////////////////////////////////////////////////
        MacBuilder verifier = getMacBuilderForMethodCall (unwrapped_session_key, SecureKeyStore.METHOD_CREATE_PIN_POLICY);
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

        ///////////////////////////////////////////////////////////////////////////////////
        // Success, return updated session data
        ///////////////////////////////////////////////////////////////////////////////////
        return unwrapped_session_key.writeKey ();
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                              getPUKValue                                   //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static SEPUKData getPUKValue (byte[] os_instance_key,
                                         byte[] provisioning_state,
                                         String id,
                                         byte[] puk_value,
                                         byte format,
                                         short retry_limit,
                                         byte[] mac) throws SKSException
      {
        ///////////////////////////////////////////////////////////////////////////////////
        // Retrieve session key
        ///////////////////////////////////////////////////////////////////////////////////
        UnwrappedSessionKey unwrapped_session_key = getUnwrappedSessionKey (os_instance_key, provisioning_state);

        ///////////////////////////////////////////////////////////////////////////////////
        // Get value
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] decrypted_puk_value = decrypt (unwrapped_session_key, puk_value);

        ///////////////////////////////////////////////////////////////////////////////////
        // Check ID syntax
        ///////////////////////////////////////////////////////////////////////////////////
        checkIDSyntax (id, "ID");

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify incoming MAC
        ///////////////////////////////////////////////////////////////////////////////////
        MacBuilder verifier = getMacBuilderForMethodCall (unwrapped_session_key, SecureKeyStore.METHOD_CREATE_PUK_POLICY);
        verifier.addString (id);
        verifier.addArray (puk_value);
        verifier.addByte (format);
        verifier.addShort (retry_limit);
        verifier.verify (mac);

        ///////////////////////////////////////////////////////////////////////////////////
        // Success, return PUK and updated session data
        ///////////////////////////////////////////////////////////////////////////////////
        SEPUKData se_puk_data = new SEPUKData ();
        se_puk_data.provisioning_state = unwrapped_session_key.writeKey ();
        se_puk_data.puk_value = decrypted_puk_value;
        return se_puk_data;
      }
  }
