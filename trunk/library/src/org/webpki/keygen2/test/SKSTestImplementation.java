package org.webpki.keygen2.test;

import java.io.IOException;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

import java.util.Date;
import java.util.Iterator;
import java.util.LinkedHashMap;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.webpki.crypto.ECDomains;
import org.webpki.crypto.test.ECKeys;
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
    int next_key_handle = 1;
    int next_prov_handle = 1;

    class KeyData
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

    class Provisioning
      {
        Provisioning ()
          {
            provisioning_handle = next_prov_handle++;
            provisionings.put (provisioning_handle, this);
          }
        String client_session_id;
        String server_session_id;
        String issuer_uri;
        byte[] session_key;
        int provisioning_handle;
        boolean open = true;
      }
    
    LinkedHashMap<Integer,KeyData> keys = new LinkedHashMap<Integer,KeyData> ();
    LinkedHashMap<Integer,Provisioning> provisionings = new LinkedHashMap<Integer,Provisioning> ();
    
    private static final byte[] ENCRYPTION = new byte[]{'E','n','c','r','y','p','t','i','o','n',' ','K','e','y'};
    private static final byte[] ATTESTATION = new byte[]{'D','e','v','i','c','e',' ','A','t','t','e','s','t','a','t','i','o','n'};
    
    private byte[] FAKE_session_key = new byte[]{0,2,5,3,3,3,8,2,3,12,2,4,4,5};
    
    private byte[] mac (byte[] key_add, byte[] data) throws GeneralSecurityException
      {
        Mac mac = Mac.getInstance ("HmacSHA256");
        byte[] key = ArrayUtil.add (FAKE_session_key, key_add);
        mac.init (new SecretKeySpec (key, "RAW"));  // Note: any length is OK in HMAC
        return mac.doFinal (data);
      }

    private byte[] attest (byte[] data) throws GeneralSecurityException
      {
        return mac (ATTESTATION, data);
      }

    private byte[] encrypt (byte[] data) throws GeneralSecurityException
      {
        byte[] key = mac (new byte[0], ENCRYPTION);
        Cipher crypt = Cipher.getInstance ("AES/CBC/PKCS5Padding");
        byte[] iv = new byte[16];
        SecureRandom.getInstance ("SHA1PRNG").nextBytes (iv);
        crypt.init (Cipher.ENCRYPT_MODE, new SecretKeySpec (key, "AES"), new IvParameterSpec (iv));
        return ArrayUtil.add (iv, crypt.doFinal (data));
      }
    
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
    
    private KeyData getOpenKey (int provisioning_handle, int key_handle) throws SKSException
      {
        Provisioning prov = getOpenProvisioning (provisioning_handle);
        KeyData kd = keys.get (key_handle);
        if (kd == null)
          {
            throw new SKSException ("Key not found:" + key_handle, SKSException.ERROR_NO_KEY);
          }
        if (kd.owner != prov)
          {
            throw new SKSException ("Key:" + key_handle + " not owned by sess:" + provisioning_handle, SKSException.ERROR_NO_KEY);
          }
        return kd;
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
    
    private void abort (int provisioning_handle, String message) throws SKSException
      {
        abortProvisioningSession (provisioning_handle);
        throw new SKSException (message, SKSException.ERROR_INTERNAL);
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
        return new EnumeratedKey (EnumeratedKey.EXIT, null, 0);
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
        return new EnumeratedProvisioningSession (EnumeratedProvisioningSession.EXIT, null, null);
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
                abort (provisioning_handle, "key id already defined:" + id + " for prov sess:" + provisioning_handle);
              }
          }
        if (!attestation_algorithm.equals (KeyGen2URIs.ALGORITHMS.KEY_ATTESTATION_1))
          {
            throw new SKSException ("Unsupported algorithm:" + attestation_algorithm, SKSException.ERROR_ALGORITHM);
          }
// TODO
/*
        if (server_seed.length != 32)
          {
            throw new SKSException ("server_seed length error:" + server_seed.length, SKSException.ERROR_OPTION);
          }
*/
        KeyData kd = new KeyData (prov);
        kd.id = id;
        kd.friendly_name = friendly_name;
        try
          {
            boolean rsa = key_algorithm instanceof KeyInitializationRequestDecoder.RSA;
            if (!rsa && !(key_algorithm instanceof KeyInitializationRequestDecoder.EC))
              {
                throw new SKSException ("RSA or ECC expected");
              }
            KeyPairGenerator kpg = KeyPairGenerator.getInstance (rsa ? "RSA" : "EC");
            if (rsa)
              {
                int size = ((KeyInitializationRequestDecoder.RSA)key_algorithm).getKeySize ();
                if (size != 1024 && size != 2048)
                  {
                    throw new SKSException ("RSA size unsupported:" + size);
                  }
                BigInteger exponent = ((KeyInitializationRequestDecoder.RSA)key_algorithm).getFixedExponent ();
                if (exponent == null)
                  {
                    kpg.initialize (size);
                  }
                else
                  {
                    kpg.initialize (new RSAKeyGenParameterSpec (size, exponent));
                  }
              }
            else
              {
                ECDomains ec = ((KeyInitializationRequestDecoder.EC)key_algorithm).getNamedCurve ();
                if (ec != ECDomains.P_256)
                  {
                    throw new SKSException ("Unsupported EC curve:" + ec.getURI ());
                  }
                ECGenParameterSpec eccgen = new ECGenParameterSpec (ec.getJCEName ());
                kpg.initialize (eccgen);
              }
            KeyPair key_pair = kpg.generateKeyPair ();
            kd.public_key = key_pair.getPublic ();   
            kd.private_key = key_pair.getPrivate ();
            return new KeyPairResult (kd.public_key,
                                      attest (new byte[]{4,5}),
                                      private_key_backup ? encrypt (kd.private_key.getEncoded ()) : null);
          }
        catch (GeneralSecurityException e)
          {
            throw new SKSException (e, SKSException.ERROR_CRYPTO);
          }
      }

    @Override
    public void abortProvisioningSession (int provisioning_handle) throws SKSException
      {
        Provisioning prov = getOpenProvisioning (provisioning_handle);
        provisionings.remove (provisioning_handle);
        for (KeyData kd : keys.values ())
          {
            if (kd.owner == prov)
              {
                keys.remove (kd.key_handle);
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
                if (list.hasNext ())
                  {
                    return getKey (list, provisioning_state);
                  }
              }
          }
        return new EnumeratedKey (EnumeratedKey.EXIT, null, 0);
      }

    @Override
    public void setCertificatePath (int provisioning_handle, int key_handle, X509Certificate[] certificate_path, byte[] mac) throws SKSException
      {
        KeyData kd = getOpenKey (provisioning_handle, key_handle);
        // TODO MAC
        if (kd.certificate_path != null)
          {
            throw new SKSException ("Multiple cert insert:" + key_handle, SKSException.ERROR_OPTION);
          }
        kd.certificate_path = certificate_path;
      }

    @Override
    public byte[] closeProvisioningSession (int provisioning_handle) throws SKSException
      {
        Provisioning prov = getOpenProvisioning (provisioning_handle);
        prov.open = false;
        // TODO real attest...
        return new byte[]{4,7,8};
      }

    @Override
    public ProvisioningSessionResult createProvisioningSession (String session_key_algorithm,
                                                                String server_session_id,
                                                                ECPublicKey server_ephemeral_key,
                                                                String issuer_uri,
                                                                boolean updatable,
                                                                Date client_time,
                                                                int session_life_time,
                                                                int session_key_limit) throws SKSException
      {
        Provisioning p = new Provisioning ();
        p.server_session_id = server_session_id;
        p.client_session_id = "C-" + Long.toHexString (new Date().getTime()) + Long.toHexString(new SecureRandom().nextLong());
        return new ProvisioningSessionResult (p.provisioning_handle,
                                              p.client_session_id,
                                              new byte[]{4,5,6}, /* Session Attestation */
                                              ECKeys.PUBLIC_KEY2);
      }

    @Override
    public DeviceInfo getDeviceInfo () throws SKSException
      {
        try
          {
            return new DeviceInfo (new X509Certificate[]{(X509Certificate)TPMKeyStore.getTPMKeyStore ().getCertificate ("mykey")});
          }
        catch (KeyStoreException e)
          {
            throw new SKSException (e, SKSException.ERROR_CRYPTO);
          }
        catch (IOException e)
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
                if (list.hasNext ())
                  {
                    return getProvisioning (list, provisioning_state);
                  }
              }
          }
        return new EnumeratedProvisioningSession (EnumeratedProvisioningSession.EXIT, null, null);
      }

    @Override
    public KeyAttributes getKeyAttributes (int key_handle) throws SKSException
      {
        return new KeyAttributes (getStdKey (key_handle).certificate_path);
      }

  }
