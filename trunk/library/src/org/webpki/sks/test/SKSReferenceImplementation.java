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
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

import java.util.Date;
import java.util.Iterator;
import java.util.HashMap;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.webpki.crypto.ECDomains;
import org.webpki.crypto.MacAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;

import org.webpki.keygen2.APIDescriptors;
import org.webpki.keygen2.CryptoConstants;
import org.webpki.keygen2.InputMethod;
import org.webpki.keygen2.KeyGen2URIs;
import org.webpki.keygen2.KeyUsage;
import org.webpki.keygen2.KeyInitializationRequestDecoder;
import org.webpki.keygen2.PINGrouping;
import org.webpki.keygen2.PassphraseFormat;
import org.webpki.keygen2.PatternRestriction;
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

public class SKSReferenceImplementation implements SecureKeyStore
  {
    int next_key_handle = 1;

    int next_prov_handle = 1;
    
    int next_pin_handle = 1;

    int next_puk_handle = 1;


    
    abstract class NameSpace
      {
        String id;
        
        Provisioning owner;
        
        NameSpace (Provisioning owner, String id) throws SKSException
          {
            if (owner.names.get (id) != null)
              {
                owner.abort ("Duplicate id:" + id);
              }
            owner.names.put (id, true);
            this.owner = owner;
            this.id = id;
          }
      
      }
    
    class KeyEntry extends NameSpace
      {
        int key_handle;

        PublicKey public_key;
        PrivateKey private_key;

        byte[] symmetric_key;
        String[] endorsed_algorithms;

        X509Certificate[] certificate_path;

        String friendly_name;
        KeyUsage key_usage;

        boolean device_pin_protected;
        
        byte[] pin_value;
        
        PINPolicy pin_policy_owner;

        HashMap<String,Extension> extensions = new HashMap<String,Extension> ();

        KeyEntry (Provisioning owner, String id) throws SKSException
          {
            super (owner, id);
            key_handle = next_key_handle++;
            keys.put (key_handle, this);
          }
        
        MacBuilder getEECertMacBuilder (APIDescriptors method) throws SKSException
          {
            if (certificate_path == null)
              {
                owner.abort ("EE certificate missing", SKSException.ERROR_OPTION);
              }
            MacBuilder mac_builder = owner.getMacBuilder (method);
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

    class Extension
      {
        byte[] qualifier;
        byte[] extension_data;
        byte basic_type;
      }
    
    class PINPolicy extends NameSpace
      {
        int pin_policy_handle;
        
        PUKPolicy puk_owner;
        
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
        PassphraseFormat format;
        short retry_limit;

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

        void testMac (MacBuilder actual_mac, byte[] claimed_mac) throws SKSException
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
            throw new SKSException (message, exception_type);
          }
    
        void abort (String message) throws SKSException
          {
             abort (message, SKSException.ERROR_INTERNAL);
          }

        byte[] encrypt (byte[] data) throws SKSException, GeneralSecurityException
          {
            byte[] key = getMacBuilder (new byte[0]).addVerbatim (CryptoConstants.CRYPTO_STRING_ENCRYPTION).getResult ();
            Cipher crypt = Cipher.getInstance ("AES/CBC/PKCS5Padding");
            byte[] iv = new byte[16];
            new SecureRandom ().nextBytes (iv);
            crypt.init (Cipher.ENCRYPT_MODE, new SecretKeySpec (key, "AES"), new IvParameterSpec (iv));
            return ArrayUtil.add (iv, crypt.doFinal (data));
          }

        byte[] decrypt (byte[] data) throws SKSException
          {
            byte[] key = getMacBuilder (new byte[0]).addVerbatim (CryptoConstants.CRYPTO_STRING_ENCRYPTION).getResult ();
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

        MacBuilder getMacBuilder (APIDescriptors method) throws SKSException
          {
            short q = mac_sequence_counter++;
            return getMacBuilder (ArrayUtil.add (method.getBinary (), new byte[]{(byte)(q >>> 8), (byte)q}));
          }
      }
    
    
    class MacBuilder
      {
        Mac mac;
        
        MacBuilder (byte[] key) throws GeneralSecurityException
          {
            mac = Mac.getInstance (MacAlgorithms.HMAC_SHA256.getJCEName ());
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
                throw new SKSException ("Interal UTF-8");
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
   
    HashMap<Integer,KeyEntry> keys = new HashMap<Integer,KeyEntry> ();

    HashMap<Integer,Provisioning> provisionings = new HashMap<Integer,Provisioning> ();

    HashMap<Integer,PINPolicy> pin_policies = new HashMap<Integer,PINPolicy> ();
    
    HashMap<Integer,PUKPolicy> puk_policies = new HashMap<Integer,PUKPolicy> ();
    
    Provisioning getOpenProvisioningSession (int provisioning_handle) throws SKSException
      {
        Provisioning prov = provisionings.get (provisioning_handle);
        if (prov == null)
          {
            throw new SKSException ("No such prov sess:" + provisioning_handle, SKSException.ERROR_NO_SESSION);
          }
        if (!prov.open)
          {
            throw new SKSException ("Session not open:" +  provisioning_handle, SKSException.ERROR_NO_SESSION);
          }
        return prov;
      }
    
    KeyEntry getOpenKey (int key_handle) throws SKSException
      {
        KeyEntry ke = keys.get (key_handle);
        if (ke == null)
          {
            throw new SKSException ("Key not found:" + key_handle, SKSException.ERROR_NO_KEY);
          }
        if (!ke.owner.open)
          {
            throw new SKSException ("Key:" + key_handle + " not beloning to open sess:" + ke.owner.provisioning_handle, SKSException.ERROR_NO_KEY);
          }
        return ke;
      }
    
    KeyEntry getStdKey (int key_handle) throws SKSException
      {
        KeyEntry ke = keys.get (key_handle);
        if (ke == null)
          {
            throw new SKSException ("Key not found:" + key_handle, SKSException.ERROR_NO_KEY);
          }
        if (ke.owner.open)
          {
            throw new SKSException ("Key:" + key_handle + " still in provisioning", SKSException.ERROR_NO_KEY);
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

    EnumeratedProvisioningSession getProvisioning (Iterator<Provisioning> iter, boolean provisioning_state)
      {
        while (iter.hasNext ())
          {
            Provisioning prov = iter.next ();
            if (prov.open == provisioning_state)
              {
                return new EnumeratedProvisioningSession (prov.provisioning_handle, prov.client_session_id, prov.server_session_id);
              }
          }
        return new EnumeratedProvisioningSession ();
      }
    
    X509Certificate[] getDeviceCertificatePath () throws KeyStoreException, IOException
      {
        return new X509Certificate[]{(X509Certificate)TPMKeyStore.getTPMKeyStore ().getCertificate ("mykey")};
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
            return new DeviceInfo (certificate_path);
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
        Provisioning prov = getOpenProvisioningSession (provisioning_handle);
        provisionings.remove (provisioning_handle);
        Iterator<KeyEntry> list = keys.values ().iterator ();
        while (list.hasNext ())
          {
            KeyEntry key_entry = list.next ();
            if (key_entry.owner == prov)
              {
                list.remove ();
              }
          }
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                        closeProvisioningSession                            //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public byte[] closeProvisioningSession (int provisioning_handle, byte[] mac) throws SKSException
      {
        Provisioning prov = getOpenProvisioningSession (provisioning_handle);
        ///////////////////////////////////////////////////////////////////////////////////
        // Verify incoming MAC
        ///////////////////////////////////////////////////////////////////////////////////
        MacBuilder close_mac = prov.getMacBuilder (APIDescriptors.CLOSE_PROVISIONING_SESSION);
        close_mac.addString (prov.client_session_id);
        close_mac.addString (prov.server_session_id);
        close_mac.addString (prov.issuer_uri);
        prov.testMac (close_mac, mac);
// TODO - check status of a lot of stuff and perform atomic updates

        ///////////////////////////////////////////////////////////////////////////////////
        // Generate a final attestation
        ///////////////////////////////////////////////////////////////////////////////////
        MacBuilder close_attestation = prov.getMacBuilder (CryptoConstants.CRYPTO_STRING_DEVICE_ATTEST);
        close_attestation.addVerbatim (CryptoConstants.CRYPTO_STRING_SUCCESS);
        close_attestation.addShort (prov.mac_sequence_counter);
        byte[] attest = close_attestation.getResult ();
        
        ///////////////////////////////////////////////////////////////////////////////////
        // We are done, close the show for this time
        ///////////////////////////////////////////////////////////////////////////////////
        prov.open = false;
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
            Signature signer = Signature.getInstance (SignatureAlgorithms.RSA_SHA256.getJCEName (), "BC");
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
        return getOpenProvisioningSession (provisioning_handle).getMacBuilder (CryptoConstants.CRYPTO_STRING_SIGNATURE).addVerbatim (data).getResult ();
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                              getKeyHandle                                  //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public int getKeyHandle (int provisioning_handle, String id) throws SKSException
      {
        Provisioning prov = getOpenProvisioningSession (provisioning_handle);
        for (KeyEntry key_entry : keys.values ())
          {
            if (key_entry.owner == prov && key_entry.id.equals (id))
              {
                return key_entry.key_handle;
              }
          }
        prov.abort ("Key: " +id + "missing");
        return 0;  // For compiler...
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                              addExtension                                  //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public void addExtension (int key_handle, 
                              byte basic_type,
                              byte[] qualifier,
                              String extension_type,
                              byte[] extension_data,
                              byte[] mac) throws SKSException
      {
        KeyEntry key_entry = getOpenKey (key_handle);
        if (key_entry.extensions.get (extension_type) != null)
          {
            key_entry.owner.abort ("Duplicate extension:" + extension_type, SKSException.ERROR_OPTION);
          }
        MacBuilder ext_mac = key_entry.getEECertMacBuilder (APIDescriptors.ADD_EXTENSION);
        ext_mac.addByte (basic_type);
        ext_mac.addArray (qualifier);
        ext_mac.addString (extension_type);
        ext_mac.addBlob (extension_data);
        key_entry.owner.testMac (ext_mac, mac);
        Extension extension = new Extension ();
        extension.basic_type = basic_type;
        extension.qualifier = qualifier;
        extension.extension_data = basic_type == 0x01 ? key_entry.owner.decrypt (extension_data) : extension_data;
        key_entry.extensions.put (extension_type, extension);
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                            setSymmetricKey                                 //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public void setSymmetricKey (int key_handle, byte[] encrypted_symmetric_key, String[] endorsed_algorithms, byte[] mac) throws SKSException
      {
        KeyEntry key_entry = getOpenKey (key_handle);
        if (key_entry.symmetric_key != null)
          {
            key_entry.owner.abort ("Duplicate symmetric key:" + key_handle, SKSException.ERROR_OPTION);
          }
        if (key_entry.key_usage != KeyUsage.SYMMETRIC_KEY)
          {
            key_entry.owner.abort ("Wrong key usage for symmetric key:" + key_handle, SKSException.ERROR_OPTION);
          }
        MacBuilder sym_mac = key_entry.getEECertMacBuilder (APIDescriptors.SET_SYMMETRIC_KEY);
        sym_mac.addArray (encrypted_symmetric_key);
// TODO verify against supported sym alg...
        for (String algorithm : endorsed_algorithms)
          {
            sym_mac.addString (algorithm);
          }
        key_entry.owner.testMac (sym_mac, mac);
        key_entry.symmetric_key = key_entry.owner.decrypt (encrypted_symmetric_key);
        key_entry.endorsed_algorithms = endorsed_algorithms;
      }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                           setCertificatePath                               //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public void setCertificatePath (int key_handle, X509Certificate[] certificate_path, byte[] mac) throws SKSException
      {
        KeyEntry key_entry = getOpenKey (key_handle);
        if (key_entry.certificate_path != null)
          {
            key_entry.owner.abort ("Multiple cert insert:" + key_handle, SKSException.ERROR_OPTION);
          }
        ///////////////////////////////////////////////////////////////////////////////////
        // Verify incoming MAC
        ///////////////////////////////////////////////////////////////////////////////////
        MacBuilder set_certificate_mac = key_entry.owner.getMacBuilder (APIDescriptors.SET_CERTIFICATE_PATH);
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
            key_entry.owner.abort ("Internal error:" + e.getMessage ());
          }
        key_entry.owner.testMac (set_certificate_mac, mac);

        ///////////////////////////////////////////////////////////////////////////////////
        // Done.  Perform the actual task we were meant to do
        ///////////////////////////////////////////////////////////////////////////////////
        key_entry.certificate_path = certificate_path;
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
                                  KeyUsage key_usage,
                                  String friendly_name,
                                  KeyInitializationRequestDecoder.KeyAlgorithmData key_algorithm,
                                  byte[] mac) throws SKSException
      {
        Provisioning prov = getOpenProvisioningSession (provisioning_handle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Validate input as much as possible
        ///////////////////////////////////////////////////////////////////////////////////
        for (KeyEntry ke : keys.values ())
          {
            if (ke.owner == prov && ke.id.equals (id))
              {
                prov.abort ("key id already defined:" + id + " for prov sess:" + provisioning_handle);
              }
          }
        if (!attestation_algorithm.equals (KeyGen2URIs.ALGORITHMS.KEY_ATTESTATION_1))
          {
            prov.abort ("Unsupported algorithm:" + attestation_algorithm, SKSException.ERROR_ALGORITHM);
          }
        if (server_seed.length != 32)
          {
            prov.abort ("server_seed length error:" + server_seed.length);
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Get proper PIN policy ID
        ///////////////////////////////////////////////////////////////////////////////////
        PINPolicy pin_policy_owner = null;
        boolean device_pin_protected = false;
        boolean decrypt_pin = false;
        String pin_policy_id = CryptoConstants.CRYPTO_STRING_NOT_AVAILABLE;
        if (pin_policy_handle != 0)
          {
            if (pin_policy_handle == 0xFFFFFFFF)
              {
                pin_policy_id = CryptoConstants.CRYPTO_STRING_PIN_DEVICE;
                device_pin_protected = true;
              }
            else
              {
                pin_policy_owner = pin_policies.get (pin_policy_handle);
                if (pin_policy_owner == null || pin_policy_owner.owner != prov)
                  {
                    prov.abort ("No such PIN policy in this session:" + pin_policy_handle);
                  }
                pin_policy_id = pin_policy_owner.id;
                decrypt_pin = !pin_policy_owner.user_defined;
              }
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Prepare for verifying incoming MAC
        ///////////////////////////////////////////////////////////////////////////////////
        MacBuilder key_pair_mac = prov.getMacBuilder (APIDescriptors.CREATE_KEY_PAIR);
        key_pair_mac.addString (id);
        key_pair_mac.addArray (server_seed);
        key_pair_mac.addString (pin_policy_id);
        if (decrypt_pin)
          {
            key_pair_mac.addArray (pin_value);
          }
        else
          {
            key_pair_mac.addString (CryptoConstants.CRYPTO_STRING_NOT_AVAILABLE);
          }
        key_pair_mac.addByte (key_usage.getSKSValue ());

        ///////////////////////////////////////////////////////////////////////////////////
        // Decode key algorithm specifier
        ///////////////////////////////////////////////////////////////////////////////////
        boolean rsa = key_algorithm instanceof KeyInitializationRequestDecoder.RSA;
        if (!rsa && !(key_algorithm instanceof KeyInitializationRequestDecoder.EC))
          {
            prov.abort ("RSA or ECC expected", SKSException.ERROR_OPTION);
          }
        AlgorithmParameterSpec alg_par_spec = null;
        if (rsa)
          {
            key_pair_mac.addByte (CryptoConstants.RSA_KEY);
            int size = ((KeyInitializationRequestDecoder.RSA)key_algorithm).getKeySize ();
            if (size != 1024 && size != 2048)
              {
                prov.abort ("RSA size unsupported:" + size, SKSException.ERROR_OPTION);
              }
            int exponent = ((KeyInitializationRequestDecoder.RSA)key_algorithm).getFixedExponent ();
            alg_par_spec = new RSAKeyGenParameterSpec (size, 
                                                       exponent == 0 ? RSAKeyGenParameterSpec.F4 : BigInteger.valueOf (exponent));
            key_pair_mac.addShort (size);
            key_pair_mac.addInt (exponent);
          }
        else
          {
            key_pair_mac.addByte (CryptoConstants.ECC_KEY);
            ECDomains ec = ((KeyInitializationRequestDecoder.EC)key_algorithm).getNamedCurve ();
            if (ec != ECDomains.P_256)
              {
                prov.abort ("Unsupported EC curve:" + ec.getURI (), SKSException.ERROR_OPTION);
              }
            alg_par_spec = new ECGenParameterSpec (ec.getJCEName ());
            key_pair_mac.addString (ec.getURI ());
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify incoming MAC
        ///////////////////////////////////////////////////////////////////////////////////
        prov.testMac (key_pair_mac, mac);
        try
          {
            ///////////////////////////////////////////////////////////////////////////////////
            // Generate the desired key-pair
            ///////////////////////////////////////////////////////////////////////////////////
            SecureRandom secure_random = new SecureRandom (server_seed); 
            KeyPairGenerator kpg = KeyPairGenerator.getInstance (rsa ? "RSA" : "EC");
            kpg.initialize (alg_par_spec, secure_random);
            java.security.KeyPair key_pair = kpg.generateKeyPair ();
            PublicKey public_key = key_pair.getPublic ();   
            PrivateKey private_key = key_pair.getPrivate ();

            ///////////////////////////////////////////////////////////////////////////////////
            // If key backup was request, wrap a copy of key
            ///////////////////////////////////////////////////////////////////////////////////
            byte[] encrypted_private_key = null;
            if (private_key_backup)
              {
                encrypted_private_key = prov.encrypt (private_key.getEncoded ());
              }

            ///////////////////////////////////////////////////////////////////////////////////
            // Create attestation data
            ///////////////////////////////////////////////////////////////////////////////////
            MacBuilder key_attestation = prov.getMacBuilder (CryptoConstants.CRYPTO_STRING_DEVICE_ATTEST);
            key_attestation.addString (id);
            key_attestation.addArray (public_key.getEncoded ());
            if (private_key_backup)
              {
                key_attestation.addArray (encrypted_private_key);
              }

            ///////////////////////////////////////////////////////////////////////////////////
            // Finally, create a key entry
            ///////////////////////////////////////////////////////////////////////////////////
            KeyEntry key_entry = new KeyEntry (prov, id);
            key_entry.pin_policy_owner = pin_policy_owner;
            key_entry.friendly_name = friendly_name;
            key_entry.pin_value = decrypt_pin ? prov.decrypt (pin_value) : pin_value;
            key_entry.public_key = public_key;   
            key_entry.private_key = private_key;
            key_entry.key_usage = key_usage;
            key_entry.device_pin_protected = device_pin_protected;
            return new KeyPair (public_key, key_attestation.getResult (), encrypted_private_key);
          }
        catch (GeneralSecurityException e)
          {
            prov.abort (e.getMessage ());
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
                                PassphraseFormat format,
                                short retry_limit,
                                PINGrouping grouping,
                                Set<PatternRestriction> pattern_restrictions,
                                byte min_length,
                                byte max_length,
                                InputMethod input_method,
                                byte[] mac) throws SKSException
      {
        Provisioning prov = getOpenProvisioningSession (provisioning_handle);
        String puk_policy_id = CryptoConstants.CRYPTO_STRING_NOT_AVAILABLE;
        PUKPolicy puk_policy = null;
        if (puk_policy_handle != 0)
          {
            puk_policy = puk_policies.get (puk_policy_handle);
            if (puk_policy == null || puk_policy.owner != prov)
              {
                prov.abort ("No such PUK policy in this session:" + puk_policy_handle);
              }
            puk_policy_id = puk_policy.id;
          }
        MacBuilder pin_policy_mac = prov.getMacBuilder (APIDescriptors.CREATE_PIN_POLICY);
        pin_policy_mac.addString (id);
        pin_policy_mac.addString (puk_policy_id);
        pin_policy_mac.addBool (user_defined);
        pin_policy_mac.addBool (user_modifiable);
        pin_policy_mac.addByte (format.getSKSValue ());
        pin_policy_mac.addShort (retry_limit);
        pin_policy_mac.addByte (grouping.getSKSValue ());
        pin_policy_mac.addByte (PatternRestriction.getSKSValue (pattern_restrictions));
        pin_policy_mac.addShort (min_length);
        pin_policy_mac.addShort (max_length);
        pin_policy_mac.addByte (input_method.getSKSValue ());
        prov.testMac (pin_policy_mac, mac);
        PINPolicy pin_policy = new PINPolicy (prov, id);
        pin_policy.puk_owner = puk_policy;
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
                                PassphraseFormat format,
                                short retry_limit,
                                byte[] mac) throws SKSException
      {
        Provisioning prov = getOpenProvisioningSession (provisioning_handle);
        MacBuilder puk_policy_mac = prov.getMacBuilder (APIDescriptors.CREATE_PUK_POLICY);
        puk_policy_mac.addString (id);
        puk_policy_mac.addArray (encrypted_value);
        puk_policy_mac.addByte (format.getSKSValue ());
        puk_policy_mac.addShort (retry_limit);
        prov.testMac (puk_policy_mac, mac);
        PUKPolicy puk_policy = new PUKPolicy (prov, id);
        puk_policy.value = prov.decrypt (encrypted_value);
        puk_policy.format = format;
        puk_policy.retry_limit = retry_limit;
        return puk_policy.puk_policy_handle;
      }

  }
