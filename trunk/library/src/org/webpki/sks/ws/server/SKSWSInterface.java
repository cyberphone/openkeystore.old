package org.webpki.sks.ws.server;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;

import javax.jws.WebService;
import javax.jws.WebMethod;
import javax.jws.WebParam;
import javax.jws.WebResult;
import javax.xml.ws.Endpoint;

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
import org.webpki.sks.ws.common.WSKeyProtectionInfo;


@WebService
public class SKSWSInterface
  {
    static SecureKeyStore sks;
    
    @WebMethod
    public String getVersion ()
      {
        return "1.0";
      }
/*
    
    // WSMETH
    public void abortProvisioningSession (int provisioning_handle) throws SKSException
      {
        // TODO Auto-generated method stub
        
      }

    // WSMETH
    public void addExtension (int key_handle, String type, byte sub_type, byte[] qualifier, byte[] extension_data, byte[] mac) throws SKSException
      {
        // TODO Auto-generated method stub
        
      }

    // WSMETH
    public byte[] asymmetricKeyDecrypt (int key_handle, String algorithm, byte[] parameters, byte[] authorization, byte[] data) throws SKSException
      {
        // TODO Auto-generated method stub
        return null;
      }

    // WSMETH
    public void changePIN (int key_handle, byte[] authorization, byte[] new_pin) throws SKSException
      {
        // TODO Auto-generated method stub
        
      }

    // WSMETH
    public byte[] closeProvisioningSession (int provisioning_handle, byte[] nonce, byte[] mac) throws SKSException
      {
        // TODO Auto-generated method stub
        return null;
      }

    // WSMETH
    public KeyData createKeyEntry (int provisioning_handle, String id, String algorithm, byte[] server_seed, boolean device_pin_protection, int pin_policy_handle, byte[] pin_value, byte biometric_protection, boolean private_key_backup, byte export_protection, byte delete_protection, boolean enable_pin_caching, byte app_usage, String friendly_name, byte[] key_specifier, String[] endorsed_algorithms, byte[] mac) throws SKSException
      {
        // TODO Auto-generated method stub
        return null;
      }

    // WSMETH
    public int createPINPolicy (int provisioning_handle, String id, int puk_policy_handle, boolean user_defined, boolean user_modifiable, byte format, short retry_limit, byte grouping, byte pattern_restrictions, short min_length, short max_length, byte input_method, byte[] mac) throws SKSException
      {
        // TODO Auto-generated method stub
        return 0;
      }

    // WSMETH
    public int createPUKPolicy (int provisioning_handle, String id, byte[] value, byte format, short retry_limit, byte[] mac) throws SKSException
      {
        // TODO Auto-generated method stub
        return 0;
      }

    // WSMETH
    public ProvisioningSession createProvisioningSession (String algorithm, String server_session_id, ECPublicKey server_ephemeral_key, String issuer_uri, PublicKey key_management_key, int client_time, int session_life_time, short session_key_limit) throws SKSException
      {
        // TODO Auto-generated method stub
        return null;
      }

    // WSMETH
    public void deleteKey (int key_handle, byte[] authorization) throws SKSException
      {
        // TODO Auto-generated method stub
        
      }

    // WSMETH
    public EnumeratedKey enumerateKeys (EnumeratedKey ek) throws SKSException
      {
        // TODO Auto-generated method stub
        return null;
      }

    // WSMETH
    public EnumeratedProvisioningSession enumerateProvisioningSessions (EnumeratedProvisioningSession eps, boolean provisioning_state) throws SKSException
      {
        // TODO Auto-generated method stub
        return null;
      }

    // WSMETH
    public byte[] exportKey (int key_handle, byte[] authorization) throws SKSException
      {
        // TODO Auto-generated method stub
        return null;
      }

    // WSMETH
    public DeviceInfo getDeviceInfo () throws SKSException
      {
        // TODO Auto-generated method stub
        return null;
      }

    // WSMETH
    public Extension getExtension (int key_handle, String type) throws SKSException
      {
        // TODO Auto-generated method stub
        return null;
      }

    // WSMETH
    public KeyAttributes getKeyAttributes (int key_handle) throws SKSException
      {
        // TODO Auto-generated method stub
        return null;
      }
*/

    @WebMethod
    public int getKeyHandle (@WebParam(name="ProvisioningHandle") int provisioning_handle, 
                             @WebParam(name="ID") String id) throws SKSException
    {
      // TODO Auto-generated method stub
      return 3;
    }

    @WebMethod
    public WSKeyProtectionInfo getKeyProtectionInfo (@WebParam(name="KeyHandle") int key_handle) throws SKSException
      {
        // TODO Auto-generated method stub
//        return sks.getKeyProtectionInfo (key_handle);
        return null;
      }
 
 /*

    // WSMETH
    public byte[] keyAgreement (int key_handle, String algorithm, byte[] parameters, byte[] authorization, PublicKey public_key) throws SKSException
      {
        // TODO Auto-generated method stub
        return null;
      }

    // WSMETH
    public byte[] performHMAC (int key_handle, String algorithm, byte[] authorization, byte[] data) throws SKSException
      {
        // TODO Auto-generated method stub
        return null;
      }

    // WSMETH
    public void pp_cloneKeyProtection (int key_handle, int target_key_handle, byte[] authorization, byte[] mac) throws SKSException
      {
        // TODO Auto-generated method stub
        
      }

    // WSMETH
    public void pp_deleteKey (int provisioning_handle, int target_key_handle, byte[] authorization, byte[] mac) throws SKSException
      {
        // TODO Auto-generated method stub
        
      }

    // WSMETH
    public void pp_unlockKey (int provisioning_handle, int target_key_handle, byte[] authorization, byte[] mac) throws SKSException
      {
        // TODO Auto-generated method stub
        
      }

    // WSMETH
    public void pp_updateKey (int key_handle, int target_key_handle, byte[] authorization, byte[] mac) throws SKSException
      {
        // TODO Auto-generated method stub
        
      }

    // WSMETH
    public void restorePrivateKey (int key_handle, byte[] private_key, byte[] mac) throws SKSException
      {
        // TODO Auto-generated method stub
        
      }

    // WSMETH
    public void setCertificatePath (int key_handle, X509Certificate[] certificate_path, byte[] mac) throws SKSException
      {
        // TODO Auto-generated method stub
        
      }

    // WSMETH
    public void setPIN (int key_handle, byte[] authorization, byte[] new_pin) throws SKSException
      {
        // TODO Auto-generated method stub
        
      }

    // WSMETH
    public void setProperty (int key_handle, String type, byte[] name, byte[] value) throws SKSException
      {
        // TODO Auto-generated method stub
        
      }

    // WSMETH
    public void setSymmetricKey (int key_handle, byte[] symmetric_key, byte[] mac) throws SKSException
      {
        // TODO Auto-generated method stub
        
      }
    @WebMethod
    public byte[] signHashedData (int key_handle, String algorithm, byte[] parameters, byte[] authorization, byte[] data) throws SKSException
      {
        // TODO Auto-generated method stub
        return null;
      }

    // WSMETH
    public byte[] signProvisioningSessionData (int provisioning_handle, byte[] data) throws SKSException
      {
        // TODO Auto-generated method stub
        return null;
      }

    // WSMETH
    public byte[] symmetricKeyEncrypt (int key_handle, String algorithm, boolean mode, byte[] iv, byte[] authorization, byte[] data) throws SKSException
      {
        // TODO Auto-generated method stub
        return null;
      }

    // WSMETH
    public void unlockKey (int key_handle, byte[] authorization) throws SKSException
      {
        // TODO Auto-generated method stub
        
      }
*/
    public static void main(String[] args)
      {
        Endpoint.publish("http://localhost:8080/securekeystore", new SKSWSInterface ());        
      }


  }
