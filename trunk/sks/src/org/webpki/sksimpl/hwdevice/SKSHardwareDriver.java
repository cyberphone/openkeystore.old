package org.webpki.sksimpl.hwdevice;

import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;

import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;

import org.webpki.hlca.KeyAuthorizationCallback;

import org.webpki.sks.DeviceInfo;
import org.webpki.sks.EnumeratedKey;
import org.webpki.sks.EnumeratedProvisioningSession;
import org.webpki.sks.Extension;
import org.webpki.sks.KeyAttributes;
import org.webpki.sks.KeyPair;
import org.webpki.sks.ProvisioningSession;
import org.webpki.sks.SKSException;
import org.webpki.sks.SecureKeyStore;

import org.webpki.io.serial.SerialDeviceDriver;
import org.webpki.io.serial.SerialDeviceDriver.ByteArrayReturn;
import org.webpki.io.serial.SerialDeviceDriver.OutputBuffer;

public class SKSHardwareDriver extends SerialDeviceDriver implements SecureKeyStore
  {
    static final int CMD_GET_DEVICE_CERTIFICATE_PATH = 1;
    
    public SKSHardwareDriver (String port, int baud_rate) throws IOException
      {
        super (port, baud_rate);
        byte[] inp = new byte[10000];
        byte[] result = ((ByteArrayReturn) new OutputBuffer (this)
                                               .putByte (1)
                                               .putShort (10)
                                               .putArray (inp)
                                               .sendBuffer (new ByteArrayReturn ())).getArray ();
     }
    
    
    public SKSHardwareDriver () throws IOException
      {
        this (DeviceInitialization.serial_port_service.getPortID (),
              DeviceInitialization.serial_port_service.getBaudRate ());
      }


    @Override
    public void abortProvisioningSession (int arg0) throws SKSException
      {
        // TODO Auto-generated method stub
        
      }


    @Override
    public void addExtension (int arg0, byte arg1, byte[] arg2, String arg3, byte[] arg4, byte[] arg5) throws SKSException
      {
        // TODO Auto-generated method stub
        
      }


    @Override
    public byte[] asymmetricKeyDecrypt (int arg0, byte[] arg1, String arg2, byte[] arg3, byte[] arg4) throws SKSException
      {
        // TODO Auto-generated method stub
        return null;
      }


    @Override
    public byte[] closeProvisioningSession (int arg0, byte[] arg1) throws SKSException
      {
        // TODO Auto-generated method stub
        return null;
      }


    @Override
    public KeyPair createKeyPair (int arg0, String arg1, String arg2, byte[] arg3, int arg4, byte[] arg5, byte arg6, boolean arg7, byte arg8, byte arg9, boolean arg10, byte arg11, String arg12, byte[] arg13, byte[] arg14) throws SKSException
      {
        // TODO Auto-generated method stub
        return null;
      }


    @Override
    public int createPINPolicy (int arg0, String arg1, int arg2, boolean arg3, boolean arg4, byte arg5, short arg6, byte arg7, byte arg8, byte arg9, byte arg10, byte arg11, byte[] arg12) throws SKSException
      {
        // TODO Auto-generated method stub
        return 0;
      }


    @Override
    public int createPUKPolicy (int arg0, String arg1, byte[] arg2, byte arg3, short arg4, byte[] arg5) throws SKSException
      {
        // TODO Auto-generated method stub
        return 0;
      }


    @Override
    public ProvisioningSession createProvisioningSession (String arg0, String arg1, ECPublicKey arg2, String arg3, boolean arg4, int arg5, int arg6, short arg7) throws SKSException
      {
        // TODO Auto-generated method stub
        return null;
      }


    @Override
    public void deleteKey (int arg0, byte[] arg1) throws SKSException
      {
        // TODO Auto-generated method stub
        
      }


    @Override
    public EnumeratedKey enumerateKeys (EnumeratedKey arg0) throws SKSException
      {
        // TODO Auto-generated method stub
        return null;
      }


    @Override
    public EnumeratedProvisioningSession enumerateProvisioningSessions (EnumeratedProvisioningSession arg0, boolean arg1) throws SKSException
      {
        // TODO Auto-generated method stub
        return null;
      }


    @Override
    public DeviceInfo getDeviceInfo () throws SKSException
      {
        // TODO Auto-generated method stub
        return null;
      }


    @Override
    public Extension getExtension (int arg0, String arg1) throws SKSException
      {
        // TODO Auto-generated method stub
        return null;
      }


    @Override
    public KeyAttributes getKeyAttributes (int arg0) throws SKSException
      {
        // TODO Auto-generated method stub
        return null;
      }


    @Override
    public int getKeyHandle (int arg0, String arg1) throws SKSException
      {
        // TODO Auto-generated method stub
        return 0;
      }


    @Override
    public byte[] performHMAC (int arg0, String arg1, byte[] arg2, byte[] arg3) throws SKSException
      {
        // TODO Auto-generated method stub
        return null;
      }


    @Override
    public void pp_cloneKeyProtection (int arg0, int arg1, byte[] arg2) throws SKSException
      {
        // TODO Auto-generated method stub
        
      }


    @Override
    public void pp_deleteKey (int arg0, int arg1, byte[] arg2) throws SKSException
      {
        // TODO Auto-generated method stub
        
      }


    @Override
    public void pp_updateKey (int arg0, int arg1, byte[] arg2) throws SKSException
      {
        // TODO Auto-generated method stub
        
      }


    @Override
    public void restorePrivateKey (int arg0, byte[] arg1, byte[] arg2) throws SKSException
      {
        // TODO Auto-generated method stub
        
      }


    @Override
    public void setCertificatePath (int arg0, X509Certificate[] arg1, byte[] arg2) throws SKSException
      {
        // TODO Auto-generated method stub
        
      }


    @Override
    public void setProperty (int arg0, String arg1, String arg2, String arg3) throws SKSException
      {
        // TODO Auto-generated method stub
        
      }


    @Override
    public void setSymmetricKey (int arg0, byte[] arg1, String[] arg2, byte[] arg3) throws SKSException
      {
        // TODO Auto-generated method stub
        
      }


    @Override
    public byte[] signHashedData (int arg0, String arg1, byte[] arg2, byte[] arg3) throws SKSException
      {
        // TODO Auto-generated method stub
        return null;
      }


    @Override
    public byte[] signProvisioningSessionData (int arg0, byte[] arg1) throws SKSException
      {
        // TODO Auto-generated method stub
        return null;
      }


    @Override
    public byte[] symmetricKeyEncrypt (int arg0, boolean arg1, byte[] arg2, String arg3, byte[] arg4, byte[] arg5) throws SKSException
      {
        // TODO Auto-generated method stub
        return null;
      }


    @Override
    public void unlockKey (int arg0, byte[] arg1) throws SKSException
      {
        // TODO Auto-generated method stub
        
      }

  }
