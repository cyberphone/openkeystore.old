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
package org.webpki.keygen2.test;

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
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

import java.util.Date;
import java.util.Iterator;
import java.util.LinkedHashMap;

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
import org.webpki.keygen2.KeyGen2URIs;
import org.webpki.keygen2.KeyUsage;
import org.webpki.keygen2.KeyInitializationRequestDecoder;

import org.webpki.sks.DeviceInfo;
import org.webpki.sks.EnumeratedKey;
import org.webpki.sks.EnumeratedProvisioningSession;
import org.webpki.sks.KeyAttributes;
import org.webpki.sks.KeyPair;
import org.webpki.sks.ProvisioningSession;
import org.webpki.sks.SKSException;
import org.webpki.sks.SecureKeyStore;

import org.webpki.util.ArrayUtil;

public class SKSTestImplementation implements SecureKeyStore
  {
    private int next_key_handle = 1;

    private int next_prov_handle = 1;


    private class KeyEntry
      {
        PublicKey public_key;
        PrivateKey private_key;
        X509Certificate[] certificate_path;
        String id;
        String friendly_name;
        int key_handle;
        Provisioning owner;

        KeyEntry (Provisioning owner)
          {
            this.owner = owner;
            key_handle = next_key_handle++;
            keys.put (key_handle, this);
          }
      }

    private class Provisioning
      {
        String client_session_id;
        String server_session_id;
        String issuer_uri;
        byte[] session_key;
        int provisioning_handle;
        boolean open = true;
        int mac_sequence_counter;
        
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

        byte[] decrypt (byte[] data) throws SKSException, GeneralSecurityException
          {
            byte[] key = getMacBuilder (new byte[0]).addVerbatim (CryptoConstants.CRYPTO_STRING_ENCRYPTION).getResult ();
            Cipher crypt = Cipher.getInstance ("AES/CBC/PKCS5Padding");
            crypt.init (Cipher.DECRYPT_MODE, new SecretKeySpec (key, "AES"), new IvParameterSpec (data, 0, 16));
            return crypt.doFinal (data, 16, data.length - 16);
          }

        private MacBuilder getMacBuilder (byte[] key_modifier) throws SKSException
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

        private MacBuilder getMacBuilder (APIDescriptors method) throws SKSException
          {
            int q = mac_sequence_counter++;
            return getMacBuilder (ArrayUtil.add (method.getBinary (), new byte[]{(byte)(q >>> 8), (byte)q}));
          }
      }
    
    
    private class MacBuilder
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
        
        void addString (String string) throws UnsupportedEncodingException
          {
            addArray (string.getBytes ("UTF-8"));
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
   
    private LinkedHashMap<Integer,KeyEntry> keys = new LinkedHashMap<Integer,KeyEntry> ();

    private LinkedHashMap<Integer,Provisioning> provisionings = new LinkedHashMap<Integer,Provisioning> ();
   
    private Provisioning getOpenProvisioningSession (int provisioning_handle) throws SKSException
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
    
    private KeyEntry getOpenKey (int key_handle) throws SKSException
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
    
    private KeyEntry getStdKey (int key_handle) throws SKSException
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
    
    private EnumeratedKey getKey (Iterator<KeyEntry> iter, boolean provisioning_state)
      {
        while (iter.hasNext ())
          {
            KeyEntry ke = iter.next ();
            if (ke.owner.open == provisioning_state)
              {
                return new EnumeratedKey (ke.key_handle, ke.id, ke.owner.provisioning_handle);
              }
          }
        return new EnumeratedKey ();
      }

    private EnumeratedProvisioningSession getProvisioning (Iterator<Provisioning> iter, boolean provisioning_state)
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
    
    private X509Certificate[] getDeviceCertificatePath () throws KeyStoreException, IOException
      {
        return new X509Certificate[]{(X509Certificate)TPMKeyStore.getTPMKeyStore ().getCertificate ("mykey")};
      }


    @Override
    public KeyPair createKeyPair (int provisioning_handle, 
                                  String attestation_algorithm,
                                  byte[] server_seed,
                                  String id,
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
        boolean rsa = key_algorithm instanceof KeyInitializationRequestDecoder.RSA;
        if (!rsa && !(key_algorithm instanceof KeyInitializationRequestDecoder.EC))
          {
            prov.abort ("RSA or ECC expected", SKSException.ERROR_OPTION);
          }
        try
          {
            ///////////////////////////////////////////////////////////////////////////////////
            // Verify incoming MAC
            ///////////////////////////////////////////////////////////////////////////////////
            MacBuilder key_pair_mac = prov.getMacBuilder (APIDescriptors.CREATE_KEY_PAIR);
            key_pair_mac.addString (id);
            key_pair_mac.addArray (server_seed);
            prov.testMac (key_pair_mac, mac);

            ///////////////////////////////////////////////////////////////////////////////////
            // Generate the desired key-pair
            ///////////////////////////////////////////////////////////////////////////////////
            SecureRandom secure_random = new SecureRandom (server_seed); 
            KeyPairGenerator kpg = KeyPairGenerator.getInstance (rsa ? "RSA" : "EC");
            if (rsa)
              {
                int size = ((KeyInitializationRequestDecoder.RSA)key_algorithm).getKeySize ();
                if (size != 1024 && size != 2048)
                  {
                    prov.abort ("RSA size unsupported:" + size, SKSException.ERROR_OPTION);
                  }
                BigInteger exponent = ((KeyInitializationRequestDecoder.RSA)key_algorithm).getFixedExponent ();
                if (exponent == null)
                  {
                    kpg.initialize (size, secure_random);
                  }
                else
                  {
                    kpg.initialize (new RSAKeyGenParameterSpec (size, exponent), secure_random);
                  }
              }
            else
              {
                ECDomains ec = ((KeyInitializationRequestDecoder.EC)key_algorithm).getNamedCurve ();
                if (ec != ECDomains.P_256)
                  {
                    prov.abort ("Unsupported EC curve:" + ec.getURI (), SKSException.ERROR_OPTION);
                  }
                ECGenParameterSpec eccgen = new ECGenParameterSpec (ec.getJCEName ());
                kpg.initialize (eccgen, secure_random);
              }
            java.security.KeyPair key_pair = kpg.generateKeyPair ();
            PublicKey public_key = key_pair.getPublic ();   
            PrivateKey private_key = key_pair.getPrivate ();

            ///////////////////////////////////////////////////////////////////////////////////
            // If private key backup was request, wrap a copy of private key
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
            KeyEntry ke = new KeyEntry (prov);
            ke.id = id;
            ke.friendly_name = friendly_name;
            ke.public_key = public_key;   
            ke.private_key = private_key;
            return new KeyPair (public_key, key_attestation.getResult (), encrypted_private_key);
          }
        catch (GeneralSecurityException e)
          {
            prov.abort (e.getMessage ());
          }
        catch (UnsupportedEncodingException e)
          {
            prov.abort (e.getMessage ());
          }
        return null; // For the compiler only...
      }

    @Override
    public void abortProvisioningSession (int provisioning_handle) throws SKSException
      {
        Provisioning prov = getOpenProvisioningSession (provisioning_handle);
        provisionings.remove (provisioning_handle);
        Iterator<KeyEntry> list = keys.values ().iterator ();
        while (list.hasNext ())
          {
            KeyEntry ke = list.next ();
            if (ke.owner == prov)
              {
                list.remove ();
              }
          }
      }

    @Override
    public EnumeratedKey enumerateKeys (int key_handle, boolean provisioning_state) throws SKSException
      {
        if (key_handle == EnumeratedKey.INIT)
          {
            return getKey (keys.values ().iterator (), provisioning_state);
          }
        Iterator<KeyEntry> list = keys.values ().iterator ();
        while (list.hasNext ())
          {
            if (list.next ().key_handle == key_handle)
              {
                return getKey (list, provisioning_state);
              }
          }
        return new EnumeratedKey ();
      }

    @Override
    public void setCertificatePath (int key_handle, X509Certificate[] certificate_path, byte[] mac) throws SKSException
      {
        KeyEntry ke = getOpenKey (key_handle);
        if (ke.certificate_path != null)
          {
            ke.owner.abort ("Multiple cert insert:" + key_handle, SKSException.ERROR_OPTION);
          }
        ///////////////////////////////////////////////////////////////////////////////////
        // Verify incoming MAC
        ///////////////////////////////////////////////////////////////////////////////////
        MacBuilder set_certificate_mac = ke.owner.getMacBuilder (APIDescriptors.SET_CERTIFICATE_PATH);
        try
          {
            set_certificate_mac.addArray (ke.public_key.getEncoded ());
            set_certificate_mac.addString (ke.id);
            for (X509Certificate certificate : certificate_path)
              {
                set_certificate_mac.addArray (certificate.getEncoded ());
              }
          }
        catch (Exception e)
          {
            ke.owner.abort ("Internal error:" + e.getMessage ());
          }
        ke.owner.testMac (set_certificate_mac, mac);

        ///////////////////////////////////////////////////////////////////////////////////
        // Done.  Perform the actual task we were meant to do
        ///////////////////////////////////////////////////////////////////////////////////
        ke.certificate_path = certificate_path;
      }

    @Override
    public byte[] closeProvisioningSession (int provisioning_handle, byte[] mac) throws SKSException
      {
        Provisioning prov = getOpenProvisioningSession (provisioning_handle);
        try
          {
            ///////////////////////////////////////////////////////////////////////////////////
            // Verify incoming MAC
            ///////////////////////////////////////////////////////////////////////////////////
            MacBuilder close_mac = prov.getMacBuilder (APIDescriptors.CLOSE_SESSION);
            close_mac.addString (prov.client_session_id);
            close_mac.addString (prov.server_session_id);
            close_mac.addString (prov.issuer_uri);
            prov.testMac (close_mac, mac);

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
        catch (UnsupportedEncodingException e)
          {
            throw new SKSException (e, SKSException.ERROR_INTERNAL);
          }
      }

    @Override
    public ProvisioningSession createProvisioningSession (String session_key_algorithm,
                                                          String server_session_id,
                                                          ECPublicKey server_ephemeral_key,
                                                          String issuer_uri,
                                                          boolean updatable,
                                                          int client_time,
                                                          int session_life_time,
                                                          int session_key_limit) throws SKSException
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
            ska.addInt (client_time);
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

    @Override
    public EnumeratedProvisioningSession enumerateProvisioningSessions (int provisioning_handle,
                                                                        boolean provisioning_state) throws SKSException
      {
        if (provisioning_handle == EnumeratedProvisioningSession.INIT)
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
        return new EnumeratedProvisioningSession ();
      }

    @Override
    public KeyAttributes getKeyAttributes (int key_handle) throws SKSException
      {
        return new KeyAttributes (getStdKey (key_handle).certificate_path);
      }

    @Override
    public byte[] signProvisioningSessionData (int provisioning_handle, byte[] data) throws SKSException
      {
        return getOpenProvisioningSession (provisioning_handle).getMacBuilder (CryptoConstants.CRYPTO_STRING_SIGNATURE).addVerbatim (data).getResult ();
      }

  }
