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

import org.webpki.keygen2.APIDescriptors;
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
import org.webpki.sks.SessionKeyOperations;

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
        int mac_sequence_counter;
        
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
            abort (provisioning_handle, "MAC error");
            return null;  // For compiler only..
          }
        
        byte[] seqCounter2 ()
          {
            int q = mac_sequence_counter++;
            return new byte[]{(byte)(q >>> 8), (byte)(q &0xFF)};
          }
        
        void testMac (byte[] data, APIDescriptors method, byte[] claimed_mac) throws SKSException
          {
            if (ArrayUtil.compare (mac (data, ArrayUtil.add (method.getBinary (), seqCounter2 ())),  claimed_mac))
              {
                return;
              }
            abort (provisioning_handle, "MAC error");
          }
        
        byte[] attest (byte[] data) throws SKSException
          {
            return mac (data, SessionKeyOperations.ATTEST_MODIFIER);
          }

        byte[] encrypt (byte[] data) throws SKSException, GeneralSecurityException
          {
            byte[] key = mac (new byte[0], SessionKeyOperations.ENCRYPTION_MODIFIER);
            Cipher crypt = Cipher.getInstance ("AES/CBC/PKCS5Padding");
            byte[] iv = new byte[16];
            SecureRandom.getInstance ("SHA1PRNG").nextBytes (iv);
            crypt.init (Cipher.ENCRYPT_MODE, new SecretKeySpec (key, "AES"), new IvParameterSpec (iv));
            return ArrayUtil.add (iv, crypt.doFinal (data));
          }
      }
    
    LinkedHashMap<Integer,KeyData> keys = new LinkedHashMap<Integer,KeyData> ();
    LinkedHashMap<Integer,Provisioning> provisionings = new LinkedHashMap<Integer,Provisioning> ();
   
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
                                      prov.attest (new byte[]{4,5}),
                                      private_key_backup ? prov.encrypt (kd.private_key.getEncoded ()) : null);
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
                if (list.hasNext ())
                  {
                    return getKey (list, provisioning_state);
                  }
              }
          }
        return new EnumeratedKey (EnumeratedKey.EXIT, null, 0);
      }

    @Override
    public void setCertificatePath (int key_handle, X509Certificate[] certificate_path, byte[] mac) throws SKSException
      {
        KeyData kd = getOpenKey (key_handle);
        byte[] data = null;
        if (kd.certificate_path != null)
          {
            throw new SKSException ("Multiple cert insert:" + key_handle, SKSException.ERROR_OPTION);
          }
        try
          {
            data = ArrayUtil.add (ArrayUtil.add (kd.public_key.getEncoded (), kd.id.getBytes ("UTF-8")),
                                  certificate_path[0].getEncoded ());
          }
        catch (Exception e)
          {
            abort (kd.owner.provisioning_handle, "Internal error:" + e.getMessage ());
          }
        kd.owner.testMac (data, APIDescriptors.SET_CERTIFICATE_PATH, mac);
        kd.certificate_path = certificate_path;
      }

    @Override
    public byte[] closeProvisioningSession (int provisioning_handle, byte[] mac) throws SKSException
      {
        Provisioning prov = getOpenProvisioning (provisioning_handle);
        byte[] attest = null;
        try
          {
            byte[] arg = new StringBuffer (prov.client_session_id)
                                  .append (prov.server_session_id)
                                  .append (prov.issuer_uri).toString ().getBytes ("UTF-8");
            prov.testMac (arg, APIDescriptors.CLOSE_SESSION, mac);
            attest = prov.attest (ArrayUtil.add (SessionKeyOperations.SUCCESS_MODIFIER, prov.seqCounter2 ()));
          }
        catch (UnsupportedEncodingException e)
          {
          }
        prov.open = false;
        return attest;
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
        byte[] session_key = null;
        ECPublicKey client_ephemeral_key = null;
        p.server_session_id = server_session_id;
        p.client_session_id = "C-" + Long.toHexString (new Date().getTime()) + Long.toHexString(new SecureRandom().nextLong());
        p.issuer_uri = issuer_uri;
        try
          {
            byte[] kdf_data = new StringBuffer (p.client_session_id).append (server_session_id).append (issuer_uri).toString ().getBytes ("UTF-8");
            KeyPairGenerator generator = KeyPairGenerator.getInstance ("EC", "BC");
            ECGenParameterSpec eccgen = new ECGenParameterSpec ("P-256");
            generator.initialize (eccgen, new SecureRandom ());
            KeyPair kp = generator.generateKeyPair();
            client_ephemeral_key = (ECPublicKey) kp.getPublic ();
            KeyAgreement ka = KeyAgreement.getInstance ("ECDHC", "BC");
            ka.init (kp.getPrivate ());
            ka.doPhase (server_ephemeral_key, true);
            Mac mac = Mac.getInstance (MacAlgorithms.HMAC_SHA256.getJCEName ());
            mac.init (new SecretKeySpec (ka.generateSecret (), "RAW"));
            session_key = mac.doFinal (kdf_data);
          }
        catch (GeneralSecurityException e)
          {
            throw new SKSException (e, SKSException.ERROR_CRYPTO);
          }
        catch (UnsupportedEncodingException e)
          {
            throw new SKSException (e, SKSException.ERROR_CRYPTO);
          }
        p.session_key = session_key;
        return new ProvisioningSessionResult (p.provisioning_handle,
                                              p.client_session_id,
                                              new byte[]{4,5,6}, /* Session Attestation */
                                              client_ephemeral_key);
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
