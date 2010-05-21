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
import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;

import java.util.Date;
import java.util.EnumSet;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.webpki.crypto.CertificateUtil;
import org.webpki.crypto.ECDomains;
import org.webpki.crypto.MacAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.keygen2.APIDescriptors;
import org.webpki.keygen2.CryptoConstants;
import org.webpki.keygen2.InputMethod;
import org.webpki.keygen2.KeyAlgorithmData;
import org.webpki.keygen2.KeyGen2URIs;
import org.webpki.keygen2.KeyUsage;
import org.webpki.keygen2.PINGrouping;
import org.webpki.keygen2.PassphraseFormat;
import org.webpki.keygen2.PatternRestriction;
import org.webpki.keygen2.ServerSessionKeyInterface;

import org.webpki.sks.KeyPair;
import org.webpki.sks.ProvisioningSession;
import org.webpki.sks.SKSException;
import org.webpki.sks.SecureKeyStore;

import org.webpki.util.ArrayUtil;
import org.webpki.util.DebugFormatter;

public class ProvSess
  {
    class SoftHSM implements ServerSessionKeyInterface
      {
        ////////////////////////////////////////////////////////////////////////////////////////
        // Private and secret keys would in a HSM implementation be represented as handles
        ////////////////////////////////////////////////////////////////////////////////////////
        ECPrivateKey server_ec_private_key;
        
        byte[] session_key;
  
        @Override
        public ECPublicKey generateEphemeralKey () throws IOException, GeneralSecurityException
          {
            KeyPairGenerator generator = KeyPairGenerator.getInstance ("EC", "BC");
            ECGenParameterSpec eccgen = new ECGenParameterSpec ("P-256");
            generator.initialize (eccgen, new SecureRandom ());
            java.security.KeyPair kp = generator.generateKeyPair();
            server_ec_private_key = (ECPrivateKey) kp.getPrivate ();
            return (ECPublicKey) kp.getPublic ();
          }
  
        @Override
        public void generateAndVerifySessionKey (ECPublicKey client_ephemeral_key,
                                                 byte[] kdf_data,
                                                 byte[] session_key_mac_data,
                                                 X509Certificate device_certificate,
                                                 byte[] session_attestation) throws IOException, GeneralSecurityException
          {
  
            // SP800-56A C(2, 0, ECC CDH)
            KeyAgreement key_agreement = KeyAgreement.getInstance ("ECDHC", "BC");
            key_agreement.init (server_ec_private_key);
            key_agreement.doPhase (client_ephemeral_key, true);
            byte[] Z = key_agreement.generateSecret ();
  
            // The custom KDF
            Mac mac = Mac.getInstance (MacAlgorithms.HMAC_SHA256.getJCEName ());
            mac.init (new SecretKeySpec (Z, "RAW"));
            session_key = mac.doFinal (kdf_data);
            
            // The session key signature
            mac = Mac.getInstance (MacAlgorithms.HMAC_SHA256.getJCEName ());
            mac.init (new SecretKeySpec (session_key, "RAW"));
            byte[] session_key_attest = mac.doFinal (session_key_mac_data);
  
            PublicKey device_public_key = device_certificate.getPublicKey ();
            SignatureAlgorithms signature_algorithm = device_public_key instanceof RSAPublicKey ?
                SignatureAlgorithms.RSA_SHA256 : SignatureAlgorithms.ECDSA_SHA256;

            // Verify that the session key signature was signed by the device key
            Signature verifier = Signature.getInstance (signature_algorithm.getJCEName (), "BC");
            verifier.initVerify (device_public_key);
            verifier.update (session_key_attest);
            if (!verifier.verify (session_attestation))
              {
                throw new IOException ("Verify provisioning signature failed");
              }
          }
  
        @Override
        public byte[] mac (byte[] data, byte[] key_modifier) throws IOException, GeneralSecurityException
          {
            Mac mac = Mac.getInstance (MacAlgorithms.HMAC_SHA256.getJCEName ());
            mac.init (new SecretKeySpec (ArrayUtil.add (session_key, key_modifier), "RAW"));
            return mac.doFinal (data);
          }
  
        @Override
        public byte[] decrypt (byte[] data) throws IOException, GeneralSecurityException
          {
            byte[] key = mac (CryptoConstants.CRYPTO_STRING_ENCRYPTION, new byte[0]);
            Cipher crypt = Cipher.getInstance ("AES/CBC/PKCS5Padding");
            crypt.init (Cipher.DECRYPT_MODE, new SecretKeySpec (key, "AES"), new IvParameterSpec (data, 0, 16));
            return crypt.doFinal (data, 16, data.length - 16);
          }
  
        @Override
        public byte[] encrypt (byte[] data) throws IOException, GeneralSecurityException
          {
            byte[] key = mac (CryptoConstants.CRYPTO_STRING_ENCRYPTION, new byte[0]);
            Cipher crypt = Cipher.getInstance ("AES/CBC/PKCS5Padding");
            byte[] iv = new byte[16];
            new SecureRandom ().nextBytes (iv);
            crypt.init (Cipher.ENCRYPT_MODE, new SecretKeySpec (key, "AES"), new IvParameterSpec (iv));
            return ArrayUtil.add (iv, crypt.doFinal (data));
          }
      }
    
    SoftHSM server_sess_key = new SoftHSM ();

    static final byte[] KEY_BACKUP_TEST_STRING = new byte[]{'S','u','c','c','e','s','s',' ','o','r',' ','n','t','?'};
    
    String session_key_algorithm = KeyGen2URIs.ALGORITHMS.SESSION_KEY_1;
    
    static final String ISSUER_URI = "http://issuer.example.com/provsess";
    
    boolean session_updatable_flag = true;
    
    Date client_time;
    
    int provisioning_handle;
    
    short session_key_limit = 50;
    
    int session_life_time = 10000;
    
    String server_session_id;
    
    String client_session_id;
    
    ECPublicKey server_ephemeral_key;
    
    short mac_sequence_counter;
    
    SecureKeyStore sks;
    
    class MacGenerator
      {
        private ByteArrayOutputStream baos;
        
        MacGenerator ()
          {
            baos = new ByteArrayOutputStream ();
          }
        
        private byte[] short2bytes (int s)
          {
            return new byte[]{(byte)(s >>> 8), (byte)s};
          }
  
        private byte[] int2bytes (int i)
          {
            return new byte[]{(byte)(i >>> 24), (byte)(i >>> 16), (byte)(i >>> 8), (byte)i};
          }
  
        void addBlob (byte[] data) throws IOException
          {
            baos.write (int2bytes (data.length));
            baos.write (data);
          }
  
        void addArray (byte[] data) throws IOException
          {
            baos.write(short2bytes (data.length));
            baos.write (data);
          }
        
        void addString (String string) throws IOException
          {
            addArray (string.getBytes ("UTF-8"));
          }
        
        void addInt (int i) throws IOException
          {
            baos.write (int2bytes (i));
          }
        
        void addShort (int s) throws IOException
          {
            baos.write (short2bytes (s));
          }
        
        void addByte (byte b)
          {
            baos.write (b);
          }
        
        void addBool (boolean flag)
          {
            baos.write (flag ? (byte) 0x01 : (byte) 0x00);
          }
        
        byte[] getResult ()
          {
            return baos.toByteArray ();
          }
       
      }

    private byte[] getMACSequenceCounterAndUpdate ()
      {
        int q = mac_sequence_counter++;
        return  new byte[]{(byte)(q >>> 8), (byte)(q &0xFF)};
      }

    byte[] mac (byte[] data, APIDescriptors method) throws IOException, GeneralSecurityException
      {
        return server_sess_key.mac (data, ArrayUtil.add (method.getBinary (), getMACSequenceCounterAndUpdate ()));
      }
    
    byte[] attest (byte[] data) throws IOException, GeneralSecurityException
      {
        return server_sess_key.mac (data, CryptoConstants.CRYPTO_STRING_DEVICE_ATTEST); 
      }
    
    void bad (String message) throws IOException
      {
        throw new IOException (message);
      }
  

    ///////////////////////////////////////////////////////////////////////////////////
    // Create provisioning session
    ///////////////////////////////////////////////////////////////////////////////////
    public ProvSess (Device device) throws GeneralSecurityException, IOException
      {
        sks = device.sks;
        server_session_id = "S-" + Long.toHexString (new Date().getTime()) + Long.toHexString(new SecureRandom().nextLong());
        client_time = new Date ();
           ProvisioningSession sess = 
                device.sks.createProvisioningSession (session_key_algorithm,
                                                      server_session_id,
                                                      server_ephemeral_key = server_sess_key.generateEphemeralKey (),
                                                      ISSUER_URI,
                                                      session_updatable_flag,
                                                      (int)(client_time.getTime () / 1000),
                                                      session_life_time,
                                                      session_key_limit);
           client_session_id = sess.getClientSessionID ();
           provisioning_handle = sess.getProvisioningHandle ();
           
           MacGenerator kdf = new MacGenerator ();
           kdf.addString (client_session_id);
           kdf.addString (server_session_id);
           kdf.addString (ISSUER_URI);
           kdf.addArray (device.device_info.getDeviceCertificatePath ()[0].getEncoded ());

           MacGenerator session_key_mac_data = new MacGenerator ();
           session_key_mac_data.addString (client_session_id);
           session_key_mac_data.addString (server_session_id);
           session_key_mac_data.addString (ISSUER_URI);
           session_key_mac_data.addArray (server_ephemeral_key.getEncoded ());
           session_key_mac_data.addArray (sess.getClientEphemeralKey ().getEncoded ());
           session_key_mac_data.addBool (session_updatable_flag);
           session_key_mac_data.addInt ((int) (client_time.getTime () / 1000));
           session_key_mac_data.addInt (session_life_time);
           session_key_mac_data.addShort (session_key_limit);

           server_sess_key.generateAndVerifySessionKey (sess.getClientEphemeralKey (),
                                                        kdf.getResult (),
                                                        session_key_mac_data.getResult (),
                                                        device.device_info.getDeviceCertificatePath ()[0],
                                                        sess.getSessionAttestation ());
     }
    
    public void closeSession () throws IOException, GeneralSecurityException
      {
        MacGenerator close = new MacGenerator ();
        close.addString (client_session_id);
        close.addString (server_session_id);
        close.addString (ISSUER_URI);
        byte[] result = sks.closeProvisioningSession (provisioning_handle, 
                                                      mac (close.getResult (),
                                                           APIDescriptors.CLOSE_PROVISIONING_SESSION));
        if (!ArrayUtil.compare (attest (ArrayUtil.add (CryptoConstants.CRYPTO_STRING_SUCCESS, 
                                                       getMACSequenceCounterAndUpdate ())),
                                result))
          {
            bad ("Final attestation failed!");
          }
      }
    
    public void abortSession () throws IOException
      {
        sks.abortProvisioningSession (provisioning_handle);
      }

    byte[] getPassphraseBytes (PassphraseFormat format, String passphrase) throws IOException
      {
        if (format == PassphraseFormat.BINARY)
          {
            return DebugFormatter.getByteArrayFromHex (passphrase);
          }
        return passphrase.getBytes ("UTF-8");
      }
    
    public PUKPol createPUKPolicy (String id, PassphraseFormat format, int retry_limit, String puk_value) throws IOException, GeneralSecurityException
      {
        PUKPol puk_policy = new PUKPol ();
        byte[] encrypted_value = server_sess_key.encrypt (getPassphraseBytes (format, puk_value));
        MacGenerator puk_policy_mac = new MacGenerator ();
        puk_policy_mac.addString (id);
        puk_policy_mac.addArray (encrypted_value);
        puk_policy_mac.addByte (format.getSKSValue ());
        puk_policy_mac.addShort (retry_limit);
        puk_policy.id = id;
        puk_policy.puk_policy_handle = sks.createPUKPolicy (provisioning_handle, 
                                                            id,
                                                            encrypted_value, 
                                                            format.getSKSValue (), 
                                                            (short)retry_limit, 
                                                            mac (puk_policy_mac.getResult (), APIDescriptors.CREATE_PUK_POLICY));
        return puk_policy;
      }
    
    public PINPol createPINPolicy (String id, PassphraseFormat format, int min_length, int max_length, int retry_limit, PUKPol puk_policy) throws IOException, GeneralSecurityException
      {
        PINPol pin_policy = new PINPol ();
        boolean user_defined = true;
        boolean user_modifiable = true;
        PINGrouping grouping = PINGrouping.NONE;
        Set<PatternRestriction> pattern_restrictions = EnumSet.noneOf (PatternRestriction.class);
        InputMethod input_method = InputMethod.ANY;
        int puk_policy_handle = puk_policy == null ? 0 : puk_policy.puk_policy_handle;
        MacGenerator pin_policy_mac = new MacGenerator ();
        pin_policy_mac.addString (id);
        pin_policy_mac.addString (puk_policy == null ? CryptoConstants.CRYPTO_STRING_NOT_AVAILABLE : puk_policy.id);
        pin_policy_mac.addBool (user_defined);
        pin_policy_mac.addBool (user_modifiable);
        pin_policy_mac.addByte (format.getSKSValue ());
        pin_policy_mac.addShort (retry_limit);
        pin_policy_mac.addByte (grouping.getSKSValue ());
        pin_policy_mac.addByte (PatternRestriction.getSKSValue (pattern_restrictions));
        pin_policy_mac.addShort (min_length);
        pin_policy_mac.addShort (max_length);
        pin_policy_mac.addByte (input_method.getSKSValue ());
        pin_policy.id = id;
        pin_policy.user_defined = user_defined;
        pin_policy.pin_policy_handle = sks.createPINPolicy (provisioning_handle,
                                                            id, 
                                                            puk_policy_handle,
                                                            user_defined,
                                                            user_modifiable,
                                                            format.getSKSValue (),
                                                            (short)retry_limit,
                                                            grouping.getSKSValue (),
                                                            PatternRestriction.getSKSValue (pattern_restrictions), 
                                                            (byte)min_length, 
                                                            (byte)max_length, 
                                                            input_method.getSKSValue (), 
                                                            mac (pin_policy_mac.getResult (), APIDescriptors.CREATE_PIN_POLICY));
        return pin_policy;
      }
    
    
    public GenKey createRSAKey (String id,
                                int rsa_size,
                                String pin_value,
                                PINPol pin_policy,
                                KeyUsage key_usage) throws SKSException, IOException, GeneralSecurityException
      {
        byte[] server_seed = new byte[32];
        new SecureRandom ().nextBytes (server_seed);
        return createKey (id,
                          KeyGen2URIs.ALGORITHMS.KEY_ATTESTATION_1,
                          server_seed,
                          pin_policy,
                          pin_value,
                          (byte) 0 /* biometric_protection */,
                          false /* boolean private_key_backup */,
                          (byte)0 /* export_policy */,
                          true /* updatable */,
                          (byte)0 /* delete_policy */,
                          false /* enable_pin_caching */,
                          false /* import_private_key */,
                          key_usage,
                          "" /* friendly_name */,
                          new KeyAlgorithmData.RSA (2048, 0));
      }
    
    public GenKey createECKey (String id,
                               String pin_value,
                               PINPol pin_policy,
                               KeyUsage key_usage) throws SKSException, IOException, GeneralSecurityException
      {
        byte[] server_seed = new byte[32];
        new SecureRandom ().nextBytes (server_seed);
        return createKey (id,
        KeyGen2URIs.ALGORITHMS.KEY_ATTESTATION_1,
        server_seed,
        pin_policy,
        pin_value,
        (byte) 0 /* biometric_protection */,
        false /* boolean private_key_backup */,
        (byte)0 /* export_policy */,
        true /* updatable */,
        (byte)0 /* delete_policy */,
        false /* enable_pin_caching */,
        false /* import_private_key */,
        key_usage,
        "" /* friendly_name */,
        new KeyAlgorithmData.EC (ECDomains.P_256));
      }

    public GenKey createKey (String id,
                             String attestation_algorithm,
                             byte[] server_seed,
                             PINPol pin_policy,
                             String pin_value,
                             byte biometric_protection,
                             boolean private_key_backup,
                             byte export_policy,
                             boolean updatable,
                             byte delete_policy,
                             boolean enable_pin_caching,
                             boolean import_private_key,
                             KeyUsage key_usage,
                             String friendly_name,
                             KeyAlgorithmData key_algorithm) throws SKSException, IOException, GeneralSecurityException
      {
        MacGenerator key_pair_mac = new MacGenerator ();
        key_pair_mac.addString (id);
        key_pair_mac.addString (attestation_algorithm);
        key_pair_mac.addArray (server_seed);
        byte[] encrypted_pin_value = new byte[0];
        if (pin_policy != null)
          {
            encrypted_pin_value = getPassphraseBytes (pin_policy.format, pin_value);
            if (!pin_policy.user_defined)
              {
                encrypted_pin_value = server_sess_key.encrypt (encrypted_pin_value);
              }
          }
        key_pair_mac.addString (pin_policy == null ? 
                                      CryptoConstants.CRYPTO_STRING_NOT_AVAILABLE 
                                                   :
                                      pin_policy.id);
        if (pin_policy == null || pin_policy.user_defined)
          {
            key_pair_mac.addString (CryptoConstants.CRYPTO_STRING_NOT_AVAILABLE);
          }
        else
          {
            key_pair_mac.addArray (encrypted_pin_value);
          }
        key_pair_mac.addByte (key_usage.getSKSValue ());
        if (key_algorithm instanceof KeyAlgorithmData.RSA)
          {
            key_pair_mac.addByte (CryptoConstants.RSA_KEY);
            key_pair_mac.addShort (((KeyAlgorithmData.RSA)key_algorithm).getKeySize ());
            key_pair_mac.addInt (((KeyAlgorithmData.RSA)key_algorithm).getFixedExponent ());
          }
        else
          {
            key_pair_mac.addByte (CryptoConstants.ECC_KEY);
            key_pair_mac.addString (((KeyAlgorithmData.EC)key_algorithm).getNamedCurve ().getURI ());
          }
        KeyPair key_pair = sks.createKeyPair (provisioning_handle, 
                                              id,
                                              attestation_algorithm, 
                                              server_seed,
                                              pin_policy == null ? 0 : pin_policy.pin_policy_handle, 
                                              encrypted_pin_value, 
                                              biometric_protection, 
                                              private_key_backup, 
                                              export_policy, 
                                              updatable, 
                                              delete_policy, 
                                              enable_pin_caching, 
                                              import_private_key, 
                                              key_usage.getSKSValue (), 
                                              friendly_name, 
                                              key_algorithm.getSKSValue (), 
                                              mac (key_pair_mac.getResult (), APIDescriptors.CREATE_KEY_PAIR));
        MacGenerator key_attestation = new MacGenerator ();
        key_attestation.addString (id);
        key_attestation.addArray (key_pair.getPublicKey ().getEncoded ());
        if (private_key_backup)
          {
            key_attestation.addArray (key_pair.getEncryptedPrivateKey ());
            verifyPrivateKeyBackup (key_pair.getEncryptedPrivateKey (), key_pair.getPublicKey ());
            }
         if (!ArrayUtil.compare (attest (key_attestation.getResult ()), key_pair.getKeyAttestation ()))
           {
             bad ("Failed key attest");
           }
        GenKey key = new GenKey ();
        key.id = id;
        key.key_handle = key_pair.getKeyHandle ();
        key.public_key = key_pair.getPublicKey ();
        key.prov_sess = this;
        return key;
      }

    void verifyPrivateKeyBackup (byte[] encrypted_private_key, PublicKey public_key) throws IOException, GeneralSecurityException
      {
        PKCS8EncodedKeySpec key_spec = new PKCS8EncodedKeySpec (server_sess_key.decrypt (encrypted_private_key));
        boolean rsa = public_key instanceof RSAPublicKey;
        PrivateKey private_key = KeyFactory.getInstance (rsa ? "RSA" : "EC").generatePrivate (key_spec);
        Signature sign = Signature.getInstance ((rsa ? SignatureAlgorithms.RSA_SHA256 : SignatureAlgorithms.ECDSA_SHA256).getJCEName ());
        sign.initSign (private_key);
        sign.update (KEY_BACKUP_TEST_STRING);
        byte[] key_archival_verify = sign.sign ();
        Signature verify = Signature.getInstance ((rsa ? SignatureAlgorithms.RSA_SHA256 : SignatureAlgorithms.ECDSA_SHA256).getJCEName ());
        verify.initVerify (public_key);
        verify.update (KEY_BACKUP_TEST_STRING);
        if (!verify.verify (key_archival_verify))
          {
            throw new GeneralSecurityException ("Archived private key validation failed");
          }
      }
    
    void setCertificate (int key_handle, String id, PublicKey public_key, X509Certificate[] certificate_path) throws IOException, GeneralSecurityException
      {
        MacGenerator set_certificate = new MacGenerator ();
        set_certificate.addArray (public_key.getEncoded ());
        set_certificate.addString (id);
        certificate_path = CertificateUtil.getSortedPath (certificate_path);
        for (X509Certificate certificate : certificate_path)
          {
            set_certificate.addArray (certificate.getEncoded ());
          }
        sks.setCertificatePath (key_handle,
                                certificate_path,
                                mac (set_certificate.getResult (), APIDescriptors.SET_CERTIFICATE_PATH));
      }

  }
