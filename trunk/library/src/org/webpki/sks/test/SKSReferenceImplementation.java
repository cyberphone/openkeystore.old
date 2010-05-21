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

import java.math.BigInteger;

import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;

import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

import java.util.Date;
import java.util.Iterator;
import java.util.HashMap;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.webpki.keygen2.test.TPMKeyStore;

import org.webpki.sks.DeviceInfo;
import org.webpki.sks.EnumeratedKey;
import org.webpki.sks.EnumeratedProvisioningSession;
import org.webpki.sks.KeyAttributes;
import org.webpki.sks.KeyPair;
import org.webpki.sks.ProvisioningSession;
import org.webpki.sks.SKSException;
import org.webpki.sks.SecureKeyStore;

import org.webpki.util.ArrayUtil;

/*
 *  The following is an SKS reference application that is supposed to complement
 *  the specification by showing how the different constructs can be implemented.
 *  In addition to the reference implementation there is a set of SKS JUnit
 *  tests that should work identical on a "real" SKS token.
 */
public class SKSReferenceImplementation implements SecureKeyStore
  {
    /////////////////////////////////////////////////////////////////////////////////////////////
    // Method IDs are used "as is" in the MAC KDF 
    /////////////////////////////////////////////////////////////////////////////////////////////
    static final byte[] METHOD_SET_CERTIFICATE_PATH       = new byte[] {'s','e','t','C','e','r','t','i','f','i','c','a','t','e','P','a','t','h'};
    static final byte[] METHOD_SET_SYMMETRIC_KEY          = new byte[] {'s','e','t','S','y','m','m','e','t','r','i','c','K','e','y'};
    static final byte[] METHOD_CLOSE_PROVISIONING_SESSION = new byte[] {'c','l','o','s','e','P','r','o','v','i','s','i','o','n','i','n','g','S','e','s','s','i','o','n'};
    static final byte[] METHOD_CREATE_KEY_PAIR            = new byte[] {'c','r','e','a','t','e','K','e','y','P','a','i','r'};
    static final byte[] METHOD_CREATE_PIN_POLICY          = new byte[] {'c','r','e','a','t','e','P','I','N','P','o','l','i','c','y'};
    static final byte[] METHOD_CREATE_PUK_POLICY          = new byte[] {'c','r','e','a','t','e','P','U','K','P','o','l','i','c','y'};
    static final byte[] METHOD_ADD_EXTENSION              = new byte[] {'a','d','d','E','x','t','e','n','s','i','o','n'};

    /////////////////////////////////////////////////////////////////////////////////////////////
    // Other KDF constants that are used "as is"
    /////////////////////////////////////////////////////////////////////////////////////////////
    static final byte[] KDF_DEVICE_ATTESTATION = new byte[] {'D','e','v','i','c','e',' ','A','t','t','e','s','t','a','t','i','o','n'};
    static final byte[] KDF_ENCRYPTION_KEY     = new byte[] {'E','n','c','r','y','p','t','i','o','n',' ','K','e','y'};
    static final byte[] KDF_EXTERNAL_SIGNATURE = new byte[] {'E','x','t','e','r','n','a','l',' ','S','i','g','n','a','t','u','r','e'};
    static final byte[] KDF_PROOF_OF_OWNERSHIP = new byte[] {'P','r','o','o','f',' ','O','f',' ','O','w','n','e','r','s','h','i','p'};

    /////////////////////////////////////////////////////////////////////////////////////////////
    // "Success" used when attesting the completed provisioning session
    /////////////////////////////////////////////////////////////////////////////////////////////
    static final byte[] CRYPTO_STRING_SUCCESS  = new byte[] {(byte)0x00, (byte)0x07, 'S','u','c','c','e','s','s'};

    /////////////////////////////////////////////////////////////////////////////////////////////
    // Predefined PIN and PUK policy IDs for MAC operations
    /////////////////////////////////////////////////////////////////////////////////////////////
    static final String CRYPTO_STRING_NOT_AVAILABLE = "#N/A";
    static final String CRYPTO_STRING_DEVICE_PIN    = "#Device PIN";
    
    /////////////////////////////////////////////////////////////////////////////////////////////
    // SKS key algorithm IDs
    /////////////////////////////////////////////////////////////////////////////////////////////
    static final byte RSA_KEY = 0x00;
    static final byte ECC_KEY = 0x01;
    
    int next_key_handle = 1;
    HashMap<Integer,KeyEntry> keys = new HashMap<Integer,KeyEntry> ();

    int next_prov_handle = 1;
    HashMap<Integer,Provisioning> provisionings = new HashMap<Integer,Provisioning> ();
    
    int next_pin_handle = 1;
    HashMap<Integer,PINPolicy> pin_policies = new HashMap<Integer,PINPolicy> ();
    
    int next_puk_handle = 1;
    HashMap<Integer,PUKPolicy> puk_policies = new HashMap<Integer,PUKPolicy> ();    

    abstract class NameSpace
      {
        String id;
        
        Provisioning owner;
        
        NameSpace (Provisioning owner, String id) throws SKSException
          {
            //////////////////////////////////////////////////////////////////////
            // Keys, PINs and PUKs share virtual ID space during provisioning
            //////////////////////////////////////////////////////////////////////
            if (owner.names.get (id) != null)
              {
                owner.abort ("Duplicate id: " + id);
              }
            boolean flag = false;
            if (id.length () == 0 || id.length () > 32)
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
                owner.abort ("Malformed ID: " + id);
              }
            owner.names.put (id, false);
            this.owner = owner;
            this.id = id;
          }
      
      }

    /////////////////////////////////////////////////////////////////////////////////////////////
    // See "KeyUsage" in the SKS specification
    /////////////////////////////////////////////////////////////////////////////////////////////
    static final byte KEY_USAGE_SIGNATURE        = 0x01;
    static final byte KEY_USAGE_AUTHENTICATION   = 0x02;
    static final byte KEY_USAGE_ENCRYPTION       = 0x04;
    static final byte KEY_USAGE_UNIVERSAL        = 0x08;
    static final byte KEY_USAGE_TRANSPORT        = 0x10;
    static final byte KEY_USAGE_SYMMETRIC_KEY    = 0x20;

    class KeyEntry extends NameSpace
      {
        int key_handle;
        byte key_usage;
        PublicKey public_key;
        PrivateKey private_key;

        byte[] symmetric_key;
        HashMap<String,Boolean> endorsed_algorithms = new HashMap<String,Boolean> ();

        X509Certificate[] certificate_path;

        String friendly_name;

        boolean device_pin_protected;
        
        byte[] pin_value;
        short error_counter;
        PINPolicy pin_policy;

        HashMap<String,Extension> extensions = new HashMap<String,Extension> ();

        KeyEntry (Provisioning owner, String id) throws SKSException
          {
            super (owner, id);
            key_handle = next_key_handle++;
            keys.put (key_handle, this);
          }
        
        void verifyPIN (byte[] pin) throws SKSException
          {
            // TODO
          }
        
        MacBuilder getEECertMacBuilder (byte[] method) throws SKSException
          {
            if (certificate_path == null)
              {
                owner.abort ("EE certificate missing", SKSException.ERROR_OPTION);
              }
            MacBuilder mac_builder = owner.getMacBuilderForMethodCall (method);
            try
              {
                mac_builder.addArray (certificate_path[0].getEncoded ());
              }
            catch (GeneralSecurityException e)
              {
              }
            return mac_builder;
          }
      }
    
    /////////////////////////////////////////////////////////////////////////////////////////////
    // See "BaseType" for "addExtensionData" in the SKS specification
    /////////////////////////////////////////////////////////////////////////////////////////////
    static final byte BASE_TYPE_EXTENSION           = 0x00;
    static final byte BASE_TYPE_ENCRYPTED_EXTENSION = 0x01;
    static final byte BASE_TYPE_PROPERTY_BAG        = 0x02;
    static final byte BASE_TYPE_LOGOTYPE            = 0x03;

    class Extension
      {
        byte[] qualifier;
        byte[] extension_data;
        byte base_type;
      }
    
    class PINPolicy extends NameSpace
      {
        int pin_policy_handle;
        
        PUKPolicy puk_policy;
        byte format;
        boolean user_defined;
        
        PINPolicy (Provisioning owner, String id) throws SKSException
          {
            super (owner, id);
            pin_policy_handle = next_pin_handle++;
            pin_policies.put (pin_policy_handle, this);
          }
      }
    
    class PUKPolicy extends NameSpace
      {
        int puk_policy_handle;
        
        byte[] value;
        byte format;
        short retry_limit;
        short error_counter;

        PUKPolicy (Provisioning owner, String id) throws SKSException
          {
            super (owner, id);
            puk_policy_handle = next_puk_handle++;
            puk_policies.put (puk_policy_handle, this);
          }
      }

    class Provisioning
      {
        HashMap<String,Boolean> names = new HashMap<String,Boolean> ();
        String client_session_id;
        String server_session_id;
        String issuer_uri;
        byte[] session_key;
        int provisioning_handle;
        boolean open = true;
        short mac_sequence_counter;
        
        Provisioning ()
          {
            provisioning_handle = next_prov_handle++;
            provisionings.put (provisioning_handle, this);
          }
        
        void verifyMac (MacBuilder actual_mac, byte[] claimed_mac) throws SKSException
          {
            if (ArrayUtil.compare (actual_mac.getResult (),  claimed_mac))
              {
                return;
              }
            abort ("MAC error", SKSException.ERROR_MAC);
          }
        
        void abort (String message, int exception_type) throws SKSException
          {
            abortProvisioningSession (provisioning_handle);
            bad (message, exception_type);
          }
    
        void abort (String message) throws SKSException
          {
            abort (message, SKSException.ERROR_INTERNAL);
          }

        byte[] encrypt (byte[] data) throws SKSException, GeneralSecurityException
          {
            byte[] key = getMacBuilder (new byte[0]).addVerbatim (KDF_ENCRYPTION_KEY).getResult ();
            Cipher crypt = Cipher.getInstance ("AES/CBC/PKCS5Padding");
            byte[] iv = new byte[16];
            new SecureRandom ().nextBytes (iv);
            crypt.init (Cipher.ENCRYPT_MODE, new SecretKeySpec (key, "AES"), new IvParameterSpec (iv));
            return ArrayUtil.add (iv, crypt.doFinal (data));
          }

        byte[] decrypt (byte[] data) throws SKSException
          {
            byte[] key = getMacBuilder (new byte[0]).addVerbatim (KDF_ENCRYPTION_KEY).getResult ();
            try
              {
                Cipher crypt = Cipher.getInstance ("AES/CBC/PKCS5Padding");
                crypt.init (Cipher.DECRYPT_MODE, new SecretKeySpec (key, "AES"), new IvParameterSpec (data, 0, 16));
                return crypt.doFinal (data, 16, data.length - 16);
              }
            catch (GeneralSecurityException e)
              {
                throw new SKSException (e, SKSException.ERROR_INTERNAL);
              }
          }

        MacBuilder getMacBuilder (byte[] key_modifier) throws SKSException
          {
            try
              {
                return new MacBuilder (ArrayUtil.add (session_key, key_modifier));
              }
            catch (GeneralSecurityException e)
              {
                throw new SKSException ("Internal error");
              }
          }

        MacBuilder getMacBuilderForMethodCall (byte[] method) throws SKSException
          {
            short q = mac_sequence_counter++;
            return getMacBuilder (ArrayUtil.add (method, new byte[]{(byte)(q >>> 8), (byte)q}));
          }
      }
    
    class MacBuilder
      {
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
            catch (UnsupportedEncodingException e)
              {
                bad ("Interal UTF-8");
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

    
    /////////////////////////////////////////////////////////////////////////////////////////////
    // Algorithm Support
    /////////////////////////////////////////////////////////////////////////////////////////////

    static class Algorithm
      {
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
    
    static final int ALG_SYM_ENC  = 0x00001;
    static final int ALG_IV_REQ   = 0x00002;
    static final int ALG_SYML_128 = 0x00004;
    static final int ALG_SYML_192 = 0x00008;
    static final int ALG_SYML_256 = 0x00010;
    static final int ALG_HMAC     = 0x00020;
    static final int ALG_ASYM_ENC = 0x00040;
    static final int ALG_ASYM_SGN = 0x00080;
    static final int ALG_RSA_KEY  = 0x00100;
    static final int ALG_ECC_KEY  = 0x00200;
    static final int ALG_ECC_CRV  = 0x00400;
    static final int ALG_HASH_160 = 0x14000;
    static final int ALG_HASH_256 = 0x20000;
    static final int ALG_HASH_DIV = 0x01000;
    
    static final String ALGORITHM_KEY_ATTEST_1         = "http://xmlns.webpki.org/keygen2/1.0#algorithm.ka1";
    
    static final String ALGORITHM_SESSION_KEY_ATTEST_1 = "http://xmlns.webpki.org/keygen2/1.0#algorithm.sk1";
    
    static final short[] rsa_key_sizes = new short[]{1024, 2048};

    static
      {
        //////////////////////////////////////////////////////////////////////////////////////
        //  Symmetric key encryption
        //////////////////////////////////////////////////////////////////////////////////////
        addAlgorithm ("http://www.w3.org/2001/04/xmlenc#aes128-cbc",
                      "AES/CBC/PKCS5Padding",
                      ALG_SYM_ENC | ALG_IV_REQ | ALG_SYML_128);

        addAlgorithm ("http://www.w3.org/2001/04/xmlenc#aes192-cbc",
                      "AES/CBC/PKCS5Padding",
                      ALG_SYM_ENC | ALG_IV_REQ | ALG_SYML_192);

        addAlgorithm ("http://www.w3.org/2001/04/xmlenc#aes256-cbc",
                      "AES/CBC/PKCS5Padding",
                      ALG_SYM_ENC | ALG_IV_REQ | ALG_SYML_256);

        addAlgorithm ("http://xmlns.webpki.org/keygen2/1.0#algorithm.aes.ecb.nopad",
                      "AES/ECB/NoPadding",
                      ALG_SYM_ENC | ALG_SYML_128 | ALG_SYML_192 | ALG_SYML_256);

        addAlgorithm ("http://xmlns.webpki.org/keygen2/1.0#algorithm.aes.ecb.pkcs5",
                      "AES/ECB/PKCS5Padding",
                      ALG_SYM_ENC | ALG_SYML_128 | ALG_SYML_192 | ALG_SYML_256);

        //////////////////////////////////////////////////////////////////////////////////////
        //  HMAC Operations
        //////////////////////////////////////////////////////////////////////////////////////
        addAlgorithm ("http://www.w3.org/2000/09/xmldsig#hmac-sha1", "HmacSHA1", ALG_HMAC);

        addAlgorithm ("http://www.w3.org/2001/04/xmldsig-more#hmac-sha256", "HmacSHA256", ALG_HMAC);

        //////////////////////////////////////////////////////////////////////////////////////
        //  Asymmetric Key Encryption
        //////////////////////////////////////////////////////////////////////////////////////
        addAlgorithm ("http://www.w3.org/2001/04/xmlenc#rsa-1_5",
                      "RSA/ECB/PKCS1Padding",
                      ALG_ASYM_ENC | ALG_RSA_KEY);

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
        //  Session Keys
        //////////////////////////////////////////////////////////////////////////////////////
        addAlgorithm (ALGORITHM_SESSION_KEY_ATTEST_1, null, 0);

        //////////////////////////////////////////////////////////////////////////////////////
        //  Key Attestations
        //////////////////////////////////////////////////////////////////////////////////////
        addAlgorithm (ALGORITHM_KEY_ATTEST_1, null, 0);

        //////////////////////////////////////////////////////////////////////////////////////
        //  Elliptic Curves
        //////////////////////////////////////////////////////////////////////////////////////
        addAlgorithm ("urn:oid:1.2.840.10045.3.1.7", "P-256", ALG_ECC_CRV);
      }
    

    /////////////////////////////////////////////////////////////////////////////////////////////
    // Utility Functions
    /////////////////////////////////////////////////////////////////////////////////////////////

    Provisioning getOpenProvisioningSession (int provisioning_handle) throws SKSException
      {
        Provisioning provisioning = provisionings.get (provisioning_handle);
        if (provisioning == null)
          {
            bad ("No such provisioning sess:" + provisioning_handle, SKSException.ERROR_NO_SESSION);
          }
        if (!provisioning.open)
          {
            bad ("Session not open:" +  provisioning_handle, SKSException.ERROR_NO_SESSION);
          }
        return provisioning;
      }
    
    int getShort (byte[] buffer, int index)
      {
        return ((buffer[index++] << 8) & 0xFFFF) + (buffer[index] & 0xFF);
      }
    
    KeyEntry getOpenKey (int key_handle) throws SKSException
      {
        KeyEntry ke = keys.get (key_handle);
        if (ke == null)
          {
            bad ("Key not found: " + key_handle, SKSException.ERROR_NO_KEY);
          }
        if (!ke.owner.open)
          {
            bad ("Key " + key_handle + " not belonging to open sess: " + ke.owner.provisioning_handle, SKSException.ERROR_NO_KEY);
          }
        return ke;
      }
    
    KeyEntry getStdKey (int key_handle) throws SKSException
      {
        KeyEntry ke = keys.get (key_handle);
        if (ke == null)
          {
            bad ("Key not found: " + key_handle, SKSException.ERROR_NO_KEY);
          }
        if (ke.owner.open)
          {
            bad ("Key " + key_handle + " still in provisioning", SKSException.ERROR_NO_KEY);
          }
        return ke;
      }
    
    EnumeratedKey getKey (Iterator<KeyEntry> iter)
      {
        while (iter.hasNext ())
          {
            KeyEntry ke = iter.next ();
            if (!ke.owner.open)
              {
                return new EnumeratedKey (ke.key_handle, ke.owner.provisioning_handle);
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
                return new EnumeratedProvisioningSession (provisioning.provisioning_handle, provisioning.client_session_id, provisioning.server_session_id);
              }
          }
        return new EnumeratedProvisioningSession ();
      }
    
    X509Certificate[] getDeviceCertificatePath () throws KeyStoreException, IOException
      {
        return new X509Certificate[]{(X509Certificate)TPMKeyStore.getTPMKeyStore ().getCertificate ("mykey")};
      }

    void bad (String message) throws SKSException
      {
        throw new SKSException (message); 
      }

    void bad (String message, int option) throws SKSException
      {
        throw new SKSException (message, option); 
      }
    
    Algorithm getAlgorithm (String algorithm_uri) throws SKSException
      {
        Algorithm alg = algorithms.get (algorithm_uri);
        if (alg == null)
          {
            bad ("Unsupported algorithm: " + algorithm_uri);
          }
        return alg;
      }

    /////////////////////////////////////////////////////////////////////////////////////////////
    // PKCS #1 Signature Support Data
    /////////////////////////////////////////////////////////////////////////////////////////////
    static final byte[] DIGEST_INFO_SHA1   = new byte[] {(byte)0x30, (byte)0x21, (byte)0x30, (byte)0x09, (byte)0x06,
                                                         (byte)0x05, (byte)0x2b, (byte)0x0e, (byte)0x03, (byte)0x02,
                                                         (byte)0x1a, (byte)0x05, (byte)0x00, (byte)0x04, (byte)0x14};
    static final byte[] DIGEST_INFO_SHA256 = new byte[] {(byte)0x30, (byte)0x31, (byte)0x30, (byte)0x0d, (byte)0x06,
                                                         (byte)0x09, (byte)0x60, (byte)0x86, (byte)0x48, (byte)0x01,
                                                         (byte)0x65, (byte)0x03, (byte)0x04, (byte)0x02, (byte)0x01,
                                                         (byte)0x05, (byte)0x00, (byte)0x04, (byte)0x20};



    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                             signHashedData                                 //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public byte[] signHashedData (int key_handle,
                                  String signature_algorithm,
                                  byte[] pin,
                                  byte[] hashed_data) throws SKSException
      {
        KeyEntry key_entry = getStdKey (key_handle);
        key_entry.verifyPIN (pin);
        Algorithm alg = getAlgorithm (signature_algorithm);
        if ((alg.mask & ALG_ASYM_SGN) == 0)
          {
            bad ("Not an asymmetric key signature algorithm: " + signature_algorithm);
          }
        int hash_len = (alg.mask / ALG_HASH_DIV) & 0xFF;
        if (hash_len > 0 && hash_len != hashed_data.length)
          {
            bad ("Wrong length of \"HashedData\": " + hashed_data.length);
          }
        if ((key_entry.key_usage & (KEY_USAGE_SIGNATURE | 
                                    KEY_USAGE_AUTHENTICATION |
                                    KEY_USAGE_UNIVERSAL)) == 0)
          {
            bad ("\"KeyUsage\" for key[" + key_handle + "] does not permit \"signHashedData\"");
          }
        if (key_entry.public_key instanceof RSAPublicKey ^ ((alg.mask & ALG_RSA_KEY) != 0))
          {
            bad ("\"SignatureAlgorithm\" for key[" + key_handle + "] does not match key type");
          }
        try
          {
            if (key_entry.public_key instanceof RSAPublicKey && hash_len > 0)
              {
                hashed_data = ArrayUtil.add (hash_len == 20 ? DIGEST_INFO_SHA1 : DIGEST_INFO_SHA256, hashed_data);
              }
            Signature signature = Signature.getInstance (alg.jce_name, "BC");
            signature.initSign (key_entry.private_key);
            signature.update (hashed_data);
            return signature.sign ();
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
            X509Certificate[] certificate_path = getDeviceCertificatePath ();
            return new DeviceInfo (certificate_path,
                                   rsa_key_sizes,
                                   algorithms.keySet ().toArray (new String[0]));
          }
        catch (Exception e)
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
    //                            getKeyAttributes                                //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public KeyAttributes getKeyAttributes (int key_handle) throws SKSException
      {
        return new KeyAttributes (getStdKey (key_handle).certificate_path);
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                         abortProvisioningSession                           //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public void abortProvisioningSession (int provisioning_handle) throws SKSException
      {
        Provisioning provisioning = getOpenProvisioningSession (provisioning_handle);
        provisionings.remove (provisioning_handle);
        deleteObject (keys, provisioning);
        deleteObject (pin_policies, provisioning);
        deleteObject (puk_policies, provisioning);
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                        closeProvisioningSession                            //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public byte[] closeProvisioningSession (int provisioning_handle, byte[] mac) throws SKSException
      {
        Provisioning provisioning = getOpenProvisioningSession (provisioning_handle);
        ///////////////////////////////////////////////////////////////////////////////////
        // Verify incoming MAC
        ///////////////////////////////////////////////////////////////////////////////////
        MacBuilder close_mac = provisioning.getMacBuilderForMethodCall (METHOD_CLOSE_PROVISIONING_SESSION);
        close_mac.addString (provisioning.client_session_id);
        close_mac.addString (provisioning.server_session_id);
        close_mac.addString (provisioning.issuer_uri);
        provisioning.verifyMac (close_mac, mac);
        for (String id : provisioning.names.keySet ())
          {
            if (!provisioning.names.get(id))
              {
                provisioning.abort ("Unreferenced object ID: " + id);
              }
          }
        for (KeyEntry key_entry : keys.values ())
          {
            if (key_entry.owner == provisioning)
              {
                if (key_entry.certificate_path == null)
                  {
                    provisioning.abort ("Missing \"setCertificatePath\" for key: " + key_entry.id);
                  }
              }
          }
// TODO - check status of a lot of stuff and perform atomic updates

        ///////////////////////////////////////////////////////////////////////////////////
        // Generate a final attestation
        ///////////////////////////////////////////////////////////////////////////////////
        MacBuilder close_attestation = provisioning.getMacBuilder (KDF_DEVICE_ATTESTATION);
        close_attestation.addVerbatim (CRYPTO_STRING_SUCCESS);
        close_attestation.addShort (provisioning.mac_sequence_counter);
        byte[] attest = close_attestation.getResult ();
        
        ///////////////////////////////////////////////////////////////////////////////////
        // We are done, close the show for this time
        ///////////////////////////////////////////////////////////////////////////////////
        provisioning.open = false;
        return attest;
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                        createProvisioningSession                           //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public ProvisioningSession createProvisioningSession (String session_key_algorithm,
                                                          String server_session_id,
                                                          ECPublicKey server_ephemeral_key,
                                                          String issuer_uri,
                                                          boolean updatable,
                                                          int client_time,
                                                          int session_life_time,
                                                          short session_key_limit) throws SKSException
      {
        if (!session_key_algorithm.equals (ALGORITHM_SESSION_KEY_ATTEST_1))
          {
            bad ("Bad \"SessionKeyAlgorithm\": " + session_key_algorithm);
          }
        byte[] session_attestation = null;
        byte[] session_key = null;
        ECPublicKey client_ephemeral_key = null;
        String client_session_id = "C-" + Long.toHexString (new Date().getTime()) + Long.toHexString(new SecureRandom().nextLong()); 
        try
          {
            ///////////////////////////////////////////////////////////////////////////////////
            // Create client ephemeral key
            ///////////////////////////////////////////////////////////////////////////////////
            KeyPairGenerator generator = KeyPairGenerator.getInstance ("EC", "BC");
            ECGenParameterSpec eccgen = new ECGenParameterSpec ("P-256");
            generator.initialize (eccgen, new SecureRandom ());
            java.security.KeyPair kp = generator.generateKeyPair ();

            ///////////////////////////////////////////////////////////////////////////////////
            // Apply the SP800-56A C(2, 0, ECC CDH) algorithm
            ///////////////////////////////////////////////////////////////////////////////////
            client_ephemeral_key = (ECPublicKey) kp.getPublic ();
            KeyAgreement key_agreement = KeyAgreement.getInstance ("ECDHC", "BC");
            key_agreement.init (kp.getPrivate ());
            key_agreement.doPhase (server_ephemeral_key, true);
            byte[] Z = key_agreement.generateSecret ();

            ///////////////////////////////////////////////////////////////////////////////////
            // But use a custom KDF 
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
            ska.addString (client_session_id);
            ska.addString (server_session_id);
            ska.addString (issuer_uri);
            ska.addArray (server_ephemeral_key.getEncoded ());
            ska.addArray (client_ephemeral_key.getEncoded ());
            ska.addBool (updatable);
            ska.addInt (client_time);
            ska.addInt (session_life_time);
            ska.addShort (session_key_limit);
            byte[] session_key_attest = ska.getResult ();
            
            ///////////////////////////////////////////////////////////////////////////////////
            // Sign attestation
            ///////////////////////////////////////////////////////////////////////////////////
            Signature signer = Signature.getInstance ("SHA256withRSA", "BC");
            signer.initSign ((PrivateKey) TPMKeyStore.getTPMKeyStore ().getKey ("mykey", TPMKeyStore.getSignerPassword ().toCharArray ()));
            signer.update (session_key_attest);
            session_attestation = signer.sign ();
          }
        catch (Exception e)
          {
            throw new SKSException (e, SKSException.ERROR_CRYPTO);
          }
        Provisioning p = new Provisioning ();
        p.server_session_id = server_session_id;
        p.client_session_id = client_session_id;
        p.issuer_uri = issuer_uri;
        p.session_key = session_key;
        return new ProvisioningSession (p.provisioning_handle,
                                        client_session_id,
                                        session_attestation,
                                        client_ephemeral_key);
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
        return getOpenProvisioningSession (provisioning_handle).getMacBuilder (KDF_EXTERNAL_SIGNATURE).addVerbatim (data).getResult ();
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                              getKeyHandle                                  //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public int getKeyHandle (int provisioning_handle, String id) throws SKSException
      {
        Provisioning provisioning = getOpenProvisioningSession (provisioning_handle);
        for (KeyEntry key_entry : keys.values ())
          {
            if (key_entry.owner == provisioning && key_entry.id.equals (id))
              {
                return key_entry.key_handle;
              }
          }
        provisioning.abort ("Key " + id + " missing");
        return 0;  // For compiler...
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                              addExtension                                  //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public void addExtension (int key_handle, 
                              byte base_type,
                              byte[] qualifier,
                              String extension_type,
                              byte[] extension_data,
                              byte[] mac) throws SKSException
      {
        KeyEntry key_entry = getOpenKey (key_handle);
        if (key_entry.extensions.get (extension_type) != null)
          {
            key_entry.owner.abort ("Duplicate \"ExtensionType\": " + extension_type, SKSException.ERROR_OPTION);
          }
        MacBuilder ext_mac = key_entry.getEECertMacBuilder (METHOD_ADD_EXTENSION);
        ext_mac.addByte (base_type);
        ext_mac.addArray (qualifier);
        ext_mac.addString (extension_type);
        ext_mac.addBlob (extension_data);
        key_entry.owner.verifyMac (ext_mac, mac);
        Extension extension = new Extension ();
        extension.base_type = base_type;
        extension.qualifier = qualifier;
        extension.extension_data = base_type == BASE_TYPE_ENCRYPTED_EXTENSION ? key_entry.owner.decrypt (extension_data) : extension_data;
        key_entry.extensions.put (extension_type, extension);
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                            setSymmetricKey                                 //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public void setSymmetricKey (int key_handle,
                                 byte[] encrypted_symmetric_key,
                                 String[] endorsed_algorithms,
                                 byte[] mac) throws SKSException
      {
        KeyEntry key_entry = getOpenKey (key_handle);
        if (key_entry.symmetric_key != null)
          {
            key_entry.owner.abort ("Duplicate symmetric key: " + key_entry.id, SKSException.ERROR_OPTION);
          }
        if (key_entry.key_usage != KEY_USAGE_SYMMETRIC_KEY)
          {
            key_entry.owner.abort ("Wrong key usage for symmetric key: " + key_entry.id, SKSException.ERROR_OPTION);
          }
        MacBuilder sym_mac = key_entry.getEECertMacBuilder (METHOD_SET_SYMMETRIC_KEY);
        sym_mac.addArray (encrypted_symmetric_key);
        key_entry.symmetric_key = key_entry.owner.decrypt (encrypted_symmetric_key);
        for (String algorithm : endorsed_algorithms)
          {
            sym_mac.addString (algorithm);
            if (key_entry.endorsed_algorithms.put (algorithm, true) != null)
              {
                key_entry.owner.abort ("Duplicate algorithm: " + algorithm, SKSException.ERROR_OPTION);
              }
            Algorithm alg = algorithms.get (algorithm);
            if (alg == null || (alg.mask & (ALG_SYM_ENC | ALG_HMAC)) == 0)
              {
                key_entry.owner.abort ((alg == null ? "Unsupported" : "Incorrect") + " algorithm: " + algorithm, SKSException.ERROR_OPTION);
              }
            if ((alg.mask & ALG_SYM_ENC) != 0)
              {
                int l = key_entry.symmetric_key.length;
                if (l == 16) l = ALG_SYML_128;
                else if (l == 24) l = ALG_SYML_192;
                else if (l == 32) l = ALG_SYML_256;
                else l = 0;
                if ((l & alg.mask) == 0)
                  {
                    key_entry.owner.abort ("Wrong key size (" + key_entry.symmetric_key.length +
                                           ") for algorithm: " + algorithm, SKSException.ERROR_OPTION);
                  }
              }
          }
        key_entry.owner.verifyMac (sym_mac, mac);
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
        KeyEntry key_entry = getOpenKey (key_handle);
        if (key_entry.certificate_path != null)
          {
            key_entry.owner.abort ("Duplicate \"setCertificatePath\" for key: " + key_entry.id, SKSException.ERROR_OPTION);
          }
        ///////////////////////////////////////////////////////////////////////////////////
        // Verify incoming MAC
        ///////////////////////////////////////////////////////////////////////////////////
        MacBuilder set_certificate_mac = key_entry.owner.getMacBuilderForMethodCall (METHOD_SET_CERTIFICATE_PATH);
        try
          {
            set_certificate_mac.addArray (key_entry.public_key.getEncoded ());
            set_certificate_mac.addString (key_entry.id);
            for (X509Certificate certificate : certificate_path)
              {
                set_certificate_mac.addArray (certificate.getEncoded ());
              }
          }
        catch (GeneralSecurityException e)
          {
            key_entry.owner.abort ("Internal error: " + e.getMessage ());
          }
        key_entry.owner.verifyMac (set_certificate_mac, mac);

        ///////////////////////////////////////////////////////////////////////////////////
        // Done.  Perform the actual task we were meant to do
        ///////////////////////////////////////////////////////////////////////////////////
        key_entry.certificate_path = certificate_path.clone ();
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                              createKeyPair                                 //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public KeyPair createKeyPair (int provisioning_handle, 
                                  String id,
                                  String attestation_algorithm,
                                  byte[] server_seed,
                                  int pin_policy_handle,
                                  byte[] pin_value,
                                  byte biometric_protection,
                                  boolean private_key_backup,
                                  byte export_policy,
                                  boolean updatable,
                                  byte delete_policy,
                                  boolean enable_pin_caching,
                                  boolean import_private_key,
                                  byte key_usage,
                                  String friendly_name,
                                  byte[] key_algorithm,
                                  byte[] mac) throws SKSException
      {
        Provisioning provisioning = getOpenProvisioningSession (provisioning_handle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Validate input as much as possible
        ///////////////////////////////////////////////////////////////////////////////////
        if (!attestation_algorithm.equals (ALGORITHM_KEY_ATTEST_1))
          {
            provisioning.abort ("Unsupported \"AttestationAlgorithm\": " + attestation_algorithm, SKSException.ERROR_ALGORITHM);
          }
        if (server_seed.length != 32)
          {
            provisioning.abort ("\"ServerSeed\" length error: " + server_seed.length);
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Get proper PIN policy ID
        ///////////////////////////////////////////////////////////////////////////////////
        PINPolicy pin_policy = null;
        boolean device_pin_protected = false;
        boolean decrypt_pin = false;
        String pin_policy_id = CRYPTO_STRING_NOT_AVAILABLE;
        if (pin_policy_handle != 0)
          {
            if (pin_policy_handle == 0xFFFFFFFF)
              {
                pin_policy_id = CRYPTO_STRING_DEVICE_PIN;
                device_pin_protected = true;
              }
            else
              {
                pin_policy = pin_policies.get (pin_policy_handle);
                if (pin_policy == null || pin_policy.owner != provisioning)
                  {
                    provisioning.abort ("No such PIN policy in this session: " + pin_policy_handle);
                  }
                pin_policy_id = pin_policy.id;
                provisioning.names.put (pin_policy_id, true); // Referenced
                decrypt_pin = !pin_policy.user_defined;
              }
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Prepare for verifying incoming MAC
        ///////////////////////////////////////////////////////////////////////////////////
        MacBuilder key_pair_mac = provisioning.getMacBuilderForMethodCall (METHOD_CREATE_KEY_PAIR);
        key_pair_mac.addString (id);
        key_pair_mac.addString (attestation_algorithm);
        key_pair_mac.addArray (server_seed);
        key_pair_mac.addString (pin_policy_id);
        if (decrypt_pin)
          {
            key_pair_mac.addArray (pin_value);
            pin_value = provisioning.decrypt (pin_value);
          }
        else
          {
            key_pair_mac.addString (CRYPTO_STRING_NOT_AVAILABLE);
          }
        // TODO if (pin_policy != null) check that pin_value is following the policy
        key_pair_mac.addByte (key_usage);
        key_pair_mac.addVerbatim (key_algorithm);

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify incoming MAC
        ///////////////////////////////////////////////////////////////////////////////////
        provisioning.verifyMac (key_pair_mac, mac);

        ///////////////////////////////////////////////////////////////////////////////////
        // Decode key algorithm specifier
        ///////////////////////////////////////////////////////////////////////////////////
        boolean rsa = key_algorithm.length > 0 && key_algorithm[0] == RSA_KEY;
        AlgorithmParameterSpec alg_par_spec = null;
        if (rsa)
          {
            if (key_algorithm.length != 7)
              {
                provisioning.abort ("Bad RSA KeyAlgorithm format", SKSException.ERROR_OPTION);
              }
            int size = getShort (key_algorithm, 1);
            boolean found = false;
            for (short rsa_key_size : rsa_key_sizes)
              {
                if (size == rsa_key_size)
                  {
                    found = true;
                    break;
                  }
              }
            if (!found)
              {
                provisioning.abort ("RSA size unsupported: " + size, SKSException.ERROR_OPTION);
              }
            int exponent = (getShort (key_algorithm, 3) << 16) + getShort (key_algorithm, 5);
            alg_par_spec = new RSAKeyGenParameterSpec (size, 
                                                       exponent == 0 ? RSAKeyGenParameterSpec.F4 : BigInteger.valueOf (exponent));
          }
        else
          {
            if (key_algorithm.length < 10 || key_algorithm[0] != ECC_KEY ||
                getShort (key_algorithm, 1) != (key_algorithm.length - 3))
              {
                provisioning.abort ("Bad ECC KeyAlgorithm format", SKSException.ERROR_OPTION);
              }
            StringBuffer ec_uri = new StringBuffer ();
            for (int i = 3; i < key_algorithm.length; i++)
              {
                ec_uri.append ((char) key_algorithm[i]);
              }
            Algorithm alg = algorithms.get (ec_uri.toString ());
            if (alg == null || (alg.mask & ALG_ECC_CRV) == 0)
              {
                provisioning.abort ("Unsupported EC curve: " + ec_uri, SKSException.ERROR_OPTION);
              }
            alg_par_spec = new ECGenParameterSpec (alg.jce_name);
          }

        try
          {
            ///////////////////////////////////////////////////////////////////////////////////
            // Generate the desired key-pair
            ///////////////////////////////////////////////////////////////////////////////////
            SecureRandom secure_random = new SecureRandom (server_seed); 
            KeyPairGenerator kpg = KeyPairGenerator.getInstance (rsa ? "RSA" : "EC", "BC");
            kpg.initialize (alg_par_spec, secure_random);
            java.security.KeyPair key_pair = kpg.generateKeyPair ();
            PublicKey public_key = key_pair.getPublic ();   
            PrivateKey private_key = key_pair.getPrivate ();

            ///////////////////////////////////////////////////////////////////////////////////
            // If key backup was request, wrap a copy of key
            ///////////////////////////////////////////////////////////////////////////////////
            byte[] encrypted_private_key = private_key_backup ? provisioning.encrypt (private_key.getEncoded ()) : null;

            ///////////////////////////////////////////////////////////////////////////////////
            // Create attestation data
            ///////////////////////////////////////////////////////////////////////////////////
            MacBuilder key_attestation = provisioning.getMacBuilder (KDF_DEVICE_ATTESTATION);
            key_attestation.addString (id);
            key_attestation.addArray (public_key.getEncoded ());
            if (private_key_backup)
              {
                key_attestation.addArray (encrypted_private_key);
              }

            ///////////////////////////////////////////////////////////////////////////////////
            // Finally, create a key entry
            ///////////////////////////////////////////////////////////////////////////////////
            KeyEntry key_entry = new KeyEntry (provisioning, id);
            provisioning.names.put (id, true); // Referenced
            key_entry.pin_policy = pin_policy;
            key_entry.friendly_name = friendly_name;
            key_entry.pin_value = pin_value;
            key_entry.public_key = public_key;   
            key_entry.private_key = import_private_key ? null : private_key;  // To enable the duplicate import test...
            key_entry.key_usage = key_usage;
            key_entry.device_pin_protected = device_pin_protected;
            return new KeyPair (public_key,
                                key_attestation.getResult (),
                                encrypted_private_key,
                                key_entry.key_handle);
          }
        catch (GeneralSecurityException e)
          {
            provisioning.abort (e.getMessage ());
          }
        return null; // For the compiler only...
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
                                byte min_length,
                                byte max_length,
                                byte input_method,
                                byte[] mac) throws SKSException
      {
        Provisioning provisioning = getOpenProvisioningSession (provisioning_handle);
        String puk_policy_id = CRYPTO_STRING_NOT_AVAILABLE;
        PUKPolicy puk_policy = null;
        if (puk_policy_handle != 0)
          {
            puk_policy = puk_policies.get (puk_policy_handle);
            if (puk_policy == null || puk_policy.owner != provisioning)
              {
                provisioning.abort ("No such PUK policy in this session: " + puk_policy_handle);
              }
            puk_policy_id = puk_policy.id;
            provisioning.names.put (puk_policy_id, true); // Referenced
          }
        MacBuilder pin_policy_mac = provisioning.getMacBuilderForMethodCall (METHOD_CREATE_PIN_POLICY);
        pin_policy_mac.addString (id);
        pin_policy_mac.addString (puk_policy_id);
        pin_policy_mac.addBool (user_defined);
        pin_policy_mac.addBool (user_modifiable);
        pin_policy_mac.addByte (format);
        pin_policy_mac.addShort (retry_limit);
        pin_policy_mac.addByte (grouping);
        pin_policy_mac.addByte (pattern_restrictions);
        pin_policy_mac.addShort (min_length);
        pin_policy_mac.addShort (max_length);
        pin_policy_mac.addByte (input_method);
        provisioning.verifyMac (pin_policy_mac, mac);
        PINPolicy pin_policy = new PINPolicy (provisioning, id);
        pin_policy.puk_policy = puk_policy;
        pin_policy.format = format;
        pin_policy.user_defined = user_defined;
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
                                byte[] encrypted_value,
                                byte format,
                                short retry_limit,
                                byte[] mac) throws SKSException
      {
        Provisioning provisioning = getOpenProvisioningSession (provisioning_handle);
        MacBuilder puk_policy_mac = provisioning.getMacBuilderForMethodCall (METHOD_CREATE_PUK_POLICY);
        puk_policy_mac.addString (id);
        puk_policy_mac.addArray (encrypted_value);
        puk_policy_mac.addByte (format);
        puk_policy_mac.addShort (retry_limit);
        provisioning.verifyMac (puk_policy_mac, mac);
        PUKPolicy puk_policy = new PUKPolicy (provisioning, id);
        puk_policy.value = provisioning.decrypt (encrypted_value);
        puk_policy.format = format;
        puk_policy.retry_limit = retry_limit;
        return puk_policy.puk_policy_handle;
      }

  }
