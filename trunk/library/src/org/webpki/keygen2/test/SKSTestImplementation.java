package org.webpki.keygen2.test;

import java.io.IOException;

import java.io.UnsupportedEncodingException;

import java.math.BigInteger;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
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
import org.webpki.sks.KeyPairResult;
import org.webpki.sks.ProvisioningSessionResult;
import org.webpki.sks.SKSException;
import org.webpki.sks.SecureKeyStore;

import org.webpki.util.ArrayUtil;

public class SKSTestImplementation implements SecureKeyStore
  {
    private int next_key_handle = 1;

    private int next_prov_handle = 1;


    private class KeyData
      {
        PublicKey public_key;
        PrivateKey private_key;
        X509Certificate[] certificate_path;
        String id;
        String friendly_name;
        int key_handle;
        Provisioning owner;

        KeyData (Provisioning owner)
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

        byte[] mac (byte[] data, byte[] key_modifier) throws SKSException
          {
            try
              {
                Mac mac = Mac.getInstance (MacAlgorithms.HMAC_SHA256.getJCEName ());
                mac.init (new SecretKeySpec (ArrayUtil.add (session_key, key_modifier), "RAW"));
                return mac.doFinal (data);
              }
            catch (GeneralSecurityException e)
              {
              }
            abort ("MAC error", SKSException.ERROR_MAC);
            return null;  // For compiler only..
          }
        
        byte[] seqCounter2 ()
          {
            return short2bytes (mac_sequence_counter++);
          }
        
        void testMac (byte[] data, APIDescriptors method, byte[] claimed_mac) throws SKSException
          {
            if (ArrayUtil.compare (mac (data, ArrayUtil.add (method.getBinary (), seqCounter2 ())),  claimed_mac))
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
    
       byte[] attest (byte[] data) throws SKSException
          {
            return mac (data, CryptoConstants.CRYPTO_STRING_DEVICE_ATTEST);
          }

        byte[] encrypt (byte[] data) throws SKSException, GeneralSecurityException
          {
            byte[] key = mac (CryptoConstants.CRYPTO_STRING_ENCRYPTION, new byte[0]);
            Cipher crypt = Cipher.getInstance ("AES/CBC/PKCS5Padding");
            byte[] iv = new byte[16];
            new SecureRandom ().nextBytes (iv);
            crypt.init (Cipher.ENCRYPT_MODE, new SecretKeySpec (key, "AES"), new IvParameterSpec (iv));
            return ArrayUtil.add (iv, crypt.doFinal (data));
          }

        byte[] decrypt (byte[] data) throws SKSException, GeneralSecurityException
          {
            byte[] key = mac (CryptoConstants.CRYPTO_STRING_ENCRYPTION, new byte[0]);
            Cipher crypt = Cipher.getInstance ("AES/CBC/PKCS5Padding");
            crypt.init (Cipher.DECRYPT_MODE, new SecretKeySpec (key, "AES"), new IvParameterSpec (data, 0, 16));
            return crypt.doFinal (data, 16, data.length - 16);
          }
      }
   
    private LinkedHashMap<Integer,KeyData> keys = new LinkedHashMap<Integer,KeyData> ();

    private LinkedHashMap<Integer,Provisioning> provisionings = new LinkedHashMap<Integer,Provisioning> ();
   
    private Provisioning getOpenProvisioning (int provisioning_handle) throws SKSException
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
    
    private KeyData getOpenKey (int key_handle) throws SKSException
      {
        KeyData kd = keys.get (key_handle);
        if (kd == null)
          {
            throw new SKSException ("Key not found:" + key_handle, SKSException.ERROR_NO_KEY);
          }
        if (!kd.owner.open)
          {
            throw new SKSException ("Key:" + key_handle + " not beloning to open sess:" + kd.owner.provisioning_handle, SKSException.ERROR_NO_KEY);
          }
        return kd;
      }
    
    private byte[] short2bytes (int s)
      {
        return new byte[]{(byte)(s >>> 8), (byte)s};
      }

    private byte[] int2bytes (int i)
      {
        return new byte[]{(byte)(i >>> 24), (byte)(i >>> 16), (byte)(i >>> 8), (byte)i};
      }

    private byte[] str2bytes (String string) throws UnsupportedEncodingException
      {
        return string.getBytes ("UTF-8");
      }

    private byte[] bool2bytes (boolean flag) throws UnsupportedEncodingException
      {
        return new byte[]{flag ? (byte)0x01 : (byte)0x00};
      }
  
   private KeyData getStdKey (int key_handle) throws SKSException
      {
        KeyData kd = keys.get (key_handle);
        if (kd == null)
          {
            throw new SKSException ("Key not found:" + key_handle, SKSException.ERROR_NO_KEY);
          }
        if (kd.owner.open)
          {
            throw new SKSException ("Key:" + key_handle + " still in provisioning", SKSException.ERROR_NO_KEY);
          }
        return kd;
      }
    
    private EnumeratedKey getKey (Iterator<KeyData> iter, boolean provisioning_state)
      {
        while (iter.hasNext ())
          {
            KeyData kd = iter.next ();
            if (kd.owner.open == provisioning_state)
              {
                return new EnumeratedKey (kd.key_handle, kd.id, kd.owner.provisioning_handle);
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
    public KeyPairResult createKeyPair (int provisioning_handle, 
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
                                        KeyInitializationRequestDecoder.KeyAlgorithmData key_algorithm) throws SKSException
      {
        Provisioning prov = getOpenProvisioning (provisioning_handle);
        for (KeyData kd : keys.values ())
          {
            if (kd.owner == prov && kd.id.equals (id))
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
        try
          {
            SecureRandom secure_random = new SecureRandom (server_seed); 
            boolean rsa = key_algorithm instanceof KeyInitializationRequestDecoder.RSA;
            if (!rsa && !(key_algorithm instanceof KeyInitializationRequestDecoder.EC))
              {
                prov.abort ("RSA or ECC expected", SKSException.ERROR_OPTION);
              }
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
            KeyPair key_pair = kpg.generateKeyPair ();
            PublicKey public_key = key_pair.getPublic ();   
            PrivateKey private_key = key_pair.getPrivate ();
            byte[] encrypted_private_key = private_key_backup ? prov.encrypt (private_key.getEncoded ()) : null;
            byte[] key_attestation = ArrayUtil.add (str2bytes (id), public_key.getEncoded ());
            key_attestation = ArrayUtil.add (key_attestation, server_seed);
            key_attestation = ArrayUtil.add (key_attestation, bool2bytes (private_key_backup));
            if (private_key_backup)
              {
                key_attestation = ArrayUtil.add (key_attestation, encrypted_private_key);
              }
            KeyData kd = new KeyData (prov);
            kd.id = id;
            kd.friendly_name = friendly_name;
            kd.public_key = public_key;   
            kd.private_key = private_key;
            return new KeyPairResult (public_key,
                                      prov.attest (key_attestation),
                                      encrypted_private_key);
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
        Provisioning prov = getOpenProvisioning (provisioning_handle);
        provisionings.remove (provisioning_handle);
        Iterator<KeyData> list = keys.values ().iterator ();
        while (list.hasNext ())
          {
            KeyData kd = list.next ();
            if (kd.owner == prov)
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
        Iterator<KeyData> list = keys.values ().iterator ();
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
        KeyData kd = getOpenKey (key_handle);
        byte[] data = null;
        if (kd.certificate_path != null)
          {
            kd.owner.abort ("Multiple cert insert:" + key_handle, SKSException.ERROR_OPTION);
          }
        try
          {
            data = ArrayUtil.add (kd.public_key.getEncoded (), str2bytes (kd.id));
            for (X509Certificate certificate : certificate_path)
              {
                data = ArrayUtil.add (data, certificate.getEncoded ());
              }
          }
        catch (Exception e)
          {
            kd.owner.abort ("Internal error:" + e.getMessage ());
          }
        kd.owner.testMac (data, APIDescriptors.SET_CERTIFICATE_PATH, mac);
        kd.certificate_path = certificate_path;
      }

    @Override
    public byte[] closeProvisioningSession (int provisioning_handle, byte[] mac) throws SKSException
      {
        Provisioning prov = getOpenProvisioning (provisioning_handle);
        try
          {
            byte[] arg = str2bytes (new StringBuffer (prov.client_session_id)
                                             .append (prov.server_session_id)
                                             .append (prov.issuer_uri).toString ());
            prov.testMac (arg, APIDescriptors.CLOSE_SESSION, mac);
            byte[] attest = prov.attest (ArrayUtil.add (CryptoConstants.CRYPTO_STRING_SUCCESS, prov.seqCounter2 ()));
            prov.open = false;
            return attest;
          }
        catch (UnsupportedEncodingException e)
          {
            throw new SKSException (e, SKSException.ERROR_INTERNAL);
          }
      }

    @Override
    public ProvisioningSessionResult createProvisioningSession (String session_key_algorithm,
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
            KeyPair kp = generator.generateKeyPair ();

            ///////////////////////////////////////////////////////////////////////////////////
            // Do the ECDHC operation
            ///////////////////////////////////////////////////////////////////////////////////
            client_ephemeral_key = (ECPublicKey) kp.getPublic ();
            KeyAgreement key_agreement = KeyAgreement.getInstance ("ECDHC", "BC");
            key_agreement.init (kp.getPrivate ());
            key_agreement.doPhase (server_ephemeral_key, true);
            byte[] Z = key_agreement.generateSecret ();

            ///////////////////////////////////////////////////////////////////////////////////
            // The custom KDF 
            ///////////////////////////////////////////////////////////////////////////////////
            byte[] csi = str2bytes (new StringBuffer (client_session_id)
                                             .append (server_session_id)
                                             .append (issuer_uri).toString ());
            byte[] kdf_data = ArrayUtil.add (csi, getDeviceCertificatePath ()[0].getEncoded ());
            Mac mac = Mac.getInstance (MacAlgorithms.HMAC_SHA256.getJCEName ());
            mac.init (new SecretKeySpec (Z, "RAW"));
            session_key = mac.doFinal (kdf_data);

            ///////////////////////////////////////////////////////////////////////////////////
            // SessionKey attested data
            ///////////////////////////////////////////////////////////////////////////////////
            byte[] data = ArrayUtil.add (csi, 
                                         ArrayUtil.add (server_ephemeral_key.getEncoded (),
                                                        client_ephemeral_key.getEncoded ()));
            data = ArrayUtil.add (data, int2bytes (client_time));
            mac = Mac.getInstance (MacAlgorithms.HMAC_SHA256.getJCEName ());
            mac.init (new SecretKeySpec (session_key, "RAW"));
            byte[] session_key_attest = mac.doFinal (data);
            
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
        return new ProvisioningSessionResult (p.provisioning_handle,
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
        return getOpenProvisioning (provisioning_handle).mac (data, CryptoConstants.CRYPTO_STRING_SIGNATURE);
      }

  }
