package org.webpki.sks.ws.client;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.xml.ws.Holder;

import javax.xml.ws.BindingProvider;

import org.webpki.crypto.CertificateInfo;
import org.webpki.crypto.CertificateUtil;
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

public class SKSWSClient implements SecureKeyStore
  {
    private static final String DEFAULT_URL_PROPERTY = "org.webpki.sks.ws.client.url";
    
    private SKSWSProxy proxy;
    
    private String port;
    
    
    public SKSWSClient (String port)
      {
        this.port = port;
      }

    public SKSWSClient ()
      {
        this (System.getProperty (DEFAULT_URL_PROPERTY));
      }

    private PublicKey createPublicKeyFromBlob (byte[] blob) throws GeneralSecurityException
      {
        X509EncodedKeySpec ks = new X509EncodedKeySpec (blob);
        KeyFactory kf = null;
        try
          {
            kf = KeyFactory.getInstance ("RSA");
            return kf.generatePublic(ks);
          }
        catch (GeneralSecurityException e1)
          {
            kf = KeyFactory.getInstance ("EC");
            return kf.generatePublic(ks);
          }
      }
    
    private ECPublicKey getECPublicKey (byte[] blob) throws GeneralSecurityException
      {
        PublicKey public_key = createPublicKeyFromBlob (blob);
        if (public_key instanceof ECPublicKey)
          {
            return (ECPublicKey) public_key;
          }
        throw new GeneralSecurityException ("Expected EC key");
      }

    /**
     * Factory method. Each WS call should use this method.
     * 
     * @return A handle to a fresh WS instance
     */
    private SKSWSProxy getSKSWS ()
      {
        if (proxy == null)
          {
            synchronized (this)
              {
                SKSWS service = new SKSWS ();
                SKSWSProxy temp_proxy = service.getSKSWSPort ();
                if (port != null)
                  {
                    Map<String,Object> request_object = ((BindingProvider) temp_proxy).getRequestContext ();
                    request_object.put (BindingProvider.ENDPOINT_ADDRESS_PROPERTY, port);
                  }
                proxy = temp_proxy;
              }
          }
        return proxy;
      }

    private static void bad (String msg)
      {
        throw new RuntimeException (msg); 
      }
    

    @Override
    public ProvisioningSession createProvisioningSession (String algorithm, 
                                                          String server_session_id,
                                                          ECPublicKey server_ephemeral_key,
                                                          String issuer_uri,
                                                          PublicKey key_management_key,
                                                          int client_time,
                                                          int session_life_time,
                                                          short session_key_limit) throws SKSException
      {
        try
          {
            Holder<String> client_session_id = new Holder<String> ();
            Holder<byte[]>client_ephemeral_key = new Holder<byte[]> ();
            Holder<byte[]>attestation = new Holder<byte[]> ();
            Holder<Integer>provisioning_handle = new Holder<Integer> ();
            getSKSWS ().createProvisioningSession (algorithm,
                                                   server_session_id,
                                                   server_ephemeral_key.getEncoded (),
                                                   issuer_uri,
                                                   key_management_key == null ? null : key_management_key.getEncoded (),
                                                   client_time,
                                                   session_life_time,
                                                   session_key_limit,
                                                   client_session_id,
                                                   client_ephemeral_key,
                                                   attestation,
                                                   provisioning_handle);
            return new ProvisioningSession (provisioning_handle.value, 
                                            client_session_id.value,
                                            attestation.value,
                                            getECPublicKey (client_ephemeral_key.value));
          }
        catch (SKSException_Exception e)
          {
            throw new SKSException (e.getFaultInfo ().getMessage (), e.getFaultInfo ().getError ());
          }
        catch (GeneralSecurityException e)
          {
            throw new SKSException (e);
          }
      }


    @Override
    public byte[] closeProvisioningSession (int provisioning_handle, byte[] nonce, byte[] mac) throws SKSException
      {
        // TODO Auto-generated method stub
        return null;
      }

    @Override
    public EnumeratedProvisioningSession enumerateProvisioningSessions (EnumeratedProvisioningSession eps, boolean provisioning_state) throws SKSException
      {
        // TODO Auto-generated method stub
        return null;
      }

    @Override
    public byte[] signProvisioningSessionData (int provisioning_handle, byte[] data) throws SKSException
      {
        // TODO Auto-generated method stub
        return null;
      }

    @Override
    public KeyData createKeyEntry (int provisioning_handle, String id, String algorithm, byte[] server_seed, boolean device_pin_protection, int pin_policy_handle, byte[] pin_value, boolean enable_pin_caching, byte biometric_protection, byte export_protection, byte delete_protection, byte app_usage, String friendly_name, boolean private_key_backup, byte[] key_specifier, String[] endorsed_algorithms, byte[] mac) throws SKSException
      {
        // TODO Auto-generated method stub
        return null;
      }

    @Override
    public int getKeyHandle (int provisioning_handle, String id) throws SKSException
      {
        // TODO Auto-generated method stub
        return 0;
      }

    @Override
    public void abortProvisioningSession (int provisioning_handle) throws SKSException
      {
        // TODO Auto-generated method stub
        
      }

    @Override
    public void setCertificatePath (int key_handle, X509Certificate[] certificate_path, byte[] mac) throws SKSException
      {
        // TODO Auto-generated method stub
        
      }

    @Override
    public void addExtension (int key_handle, String type, byte sub_type, byte[] qualifier, byte[] extension_data, byte[] mac) throws SKSException
      {
        // TODO Auto-generated method stub
        
      }

    @Override
    public void setSymmetricKey (int key_handle, byte[] symmetric_key, byte[] mac) throws SKSException
      {
        // TODO Auto-generated method stub
        
      }

    @Override
    public void restorePrivateKey (int key_handle, byte[] private_key, byte[] mac) throws SKSException
      {
        // TODO Auto-generated method stub
        
      }

    @Override
    public int createPINPolicy (int provisioning_handle, String id, int puk_policy_handle, boolean user_defined, boolean user_modifiable, byte format, short retry_limit, byte grouping, byte pattern_restrictions, short min_length, short max_length, byte input_method, byte[] mac) throws SKSException
      {
        // TODO Auto-generated method stub
        return 0;
      }

    @Override
    public int createPUKPolicy (int provisioning_handle, String id, byte[] value, byte format, short retry_limit, byte[] mac) throws SKSException
      {
        // TODO Auto-generated method stub
        return 0;
      }

    @Override
    public void pp_deleteKey (int provisioning_handle, int target_key_handle, byte[] authorization, byte[] mac) throws SKSException
      {
        // TODO Auto-generated method stub
        
      }

    @Override
    public void pp_unlockKey (int provisioning_handle, int target_key_handle, byte[] authorization, byte[] mac) throws SKSException
      {
        // TODO Auto-generated method stub
        
      }

    @Override
    public void pp_updateKey (int key_handle, int target_key_handle, byte[] authorization, byte[] mac) throws SKSException
      {
        // TODO Auto-generated method stub
        
      }

    @Override
    public void pp_cloneKeyProtection (int key_handle, int target_key_handle, byte[] authorization, byte[] mac) throws SKSException
      {
        // TODO Auto-generated method stub
        
      }

    @Override
    public KeyAttributes getKeyAttributes (int key_handle) throws SKSException
      {
        // TODO Auto-generated method stub
        return null;
      }

    @Override
    public EnumeratedKey enumerateKeys (EnumeratedKey ek) throws SKSException
      {
        // TODO Auto-generated method stub
        return null;
      }

    @Override
    public byte[] signHashedData (int key_handle, String algorithm, byte[] parameters, byte[] authorization, byte[] data) throws SKSException
      {
        // TODO Auto-generated method stub
        return null;
      }

    @Override
    public byte[] performHMAC (int key_handle, String algorithm, byte[] authorization, byte[] data) throws SKSException
      {
        // TODO Auto-generated method stub
        return null;
      }

    @Override
    public byte[] symmetricKeyEncrypt (int key_handle, String algorithm, boolean mode, byte[] iv, byte[] authorization, byte[] data) throws SKSException
      {
        // TODO Auto-generated method stub
        return null;
      }

    @Override
    public byte[] asymmetricKeyDecrypt (int key_handle, String algorithm, byte[] parameters, byte[] authorization, byte[] data) throws SKSException
      {
        // TODO Auto-generated method stub
        return null;
      }

    @Override
    public byte[] keyAgreement (int key_handle, String algorithm, byte[] parameters, byte[] authorization, PublicKey public_key) throws SKSException
      {
        // TODO Auto-generated method stub
        return null;
      }

    @Override
    public void deleteKey (int key_handle, byte[] authorization) throws SKSException
      {
        // TODO Auto-generated method stub
        
      }

    @Override
    public DeviceInfo getDeviceInfo () throws SKSException
      {
        // TODO Auto-generated method stub
        return null;
      }

    @Override
    public Extension getExtension (int key_handle, String type) throws SKSException
      {
        // TODO Auto-generated method stub
        return null;
      }

    @Override
    public KeyProtectionInfo getKeyProtectionInfo (int key_handle) throws SKSException
      {
        // TODO Auto-generated method stub
        return null;
      }

    @Override
    public void setProperty (int key_handle, String type, byte[] name, byte[] value) throws SKSException
      {
        // TODO Auto-generated method stub
        
      }

    @Override
    public void unlockKey (int key_handle, byte[] authorization) throws SKSException
      {
        // TODO Auto-generated method stub
        
      }

    @Override
    public void changePIN (int key_handle, byte[] authorization, byte[] new_pin) throws SKSException
      {
        // TODO Auto-generated method stub
        
      }

    @Override
    public void setPIN (int key_handle, byte[] authorization, byte[] new_pin) throws SKSException
      {
        // TODO Auto-generated method stub
        
      }

    @Override
    public byte[] exportKey (int key_handle, byte[] authorization) throws SKSException
      {
        // TODO Auto-generated method stub
        return null;
      }    

    /**
     * Test method. Use empty argument list for help.
     * 
     * @param args
     *            Command line arguments
     * @throws  
     * @throws SKSExceptionBean 
     */
    public static void main (String args[])
      {
        if (args.length != 1)
          {
            System.out.println ("SKSWSClient port\n if port is set to \"default\" the WSDL value is used\n" +
                                "port may also be set with the JVM -D" + DEFAULT_URL_PROPERTY + "=port");
            System.exit (3);
          }
        SKSWSClient client = args[0].equals ("default") ? new SKSWSClient () : new SKSWSClient (args[0]);
        SKSWSProxy proxy = client.getSKSWS ();
        System.out.println ("Version=" + proxy.getVersion ());
        /*

        System.out.println ("abortProvisioningSession testing...");
        try
          {
            proxy.abortProvisioningSession (5);
            bad ("Should have thrown");
          }
        catch (SKSException_Exception e)
          {
            if (e.getFaultInfo ().getError () != 4)
              {
                bad ("error ex");
              }
            if (!e.getFaultInfo ().getMessage ().equals ("bad"))
              {
                bad ("message ex");
              }
          }

        System.out.println ("getKeyProtectionInfo testing...");
        Holder<Byte> blah = new Holder<Byte> ();
        Holder<String> prot = new Holder<String> ();
        prot.value = "yes";
        Holder<List<byte[]>> certls = new Holder<List<byte[]>> ();
        try
          {
            if (proxy.getKeyProtectionInfo (4, prot, blah, certls) != 800)
              {
                bad ("return");
              }
            if (!prot.value.equals ("yes@"))
              {
                bad ("prot");
              }
            if (blah.value != 6)
              {
                bad ("blah");
              }
            if (certls.value == null || certls.value.size () != 2)
              {
                bad ("certs");
              }
            for (byte[] cert : certls.value)
              {
                System.out.println ("CERT=" + new CertificateInfo (CertificateUtil.getCertificateFromBlob (cert), false).getSubject ());
              }
          }
        catch (SKSException_Exception e)
          {
            bad (e.getMessage ());
          }
        catch (IOException e)
          {
            // TODO Auto-generated catch block
            e.printStackTrace();
          }
        System.out.println ("setCertificatePath testing...");
        try
          {
            proxy.setCertificatePath (8,certls.value, new byte[]{4,6});
            proxy.setCertificatePath (3,null, new byte[]{4,6,7});
          }
        catch (SKSException_Exception e)
          {
            bad (e.getMessage ());
          }
        System.out.println ("getCertPath testing...");
        try
          {
            List<byte[]> ret = proxy.getCertPath (true);
            if (ret.size () != 2)
              {
                bad("certs");
              }
            ret = proxy.getCertPath (false);
            if (!ret.isEmpty ())
              {
                bad("certs");
              }
          }
        catch (SKSException_Exception e)
          {
            bad (e.getMessage ());
          }
          */
    }

  }
