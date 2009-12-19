package org.webpki.sks.hwdevice;

import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;

import java.security.cert.X509Certificate;

import org.webpki.crypto.AsymEncryptionAlgorithms;
import org.webpki.crypto.MacAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.crypto.SymEncryptionAlgorithms;

import org.webpki.io.serial.SerialDeviceDriver;
import org.webpki.io.serial.SerialDeviceDriver.ByteArrayReturn;
import org.webpki.io.serial.SerialDeviceDriver.OutputBuffer;

import org.webpki.keygen2.KeyGen2KeyUsage;
import org.webpki.keygen2.KeyOperationRequestDecoder.KeyAlgorithmData;

import org.webpki.sks.KeyAuthorizationCallback;
import org.webpki.sks.SecureKeyStore;

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
    public byte[] deviceKeyDecrypt (byte[] data, AsymEncryptionAlgorithms algorithm) throws IOException
      {
        // TODO Auto-generated method stub
        return null;
      }

    @Override
    public byte[] deviceKeyDigestSign (byte[] digest, SignatureAlgorithms algorithm) throws IOException
      {
        // TODO Auto-generated method stub
        return null;
      }

    @Override
    public AttestedKeyPair generateAttestedKeyPair (KeyAlgorithmData key_alg, String attestation_algorithm, boolean exportable, KeyGen2KeyUsage key_usage, byte[] nonce, byte[] opt_archival_public_key, String private_key_format_uri, SymEncryptionAlgorithms encrytion_algorithm, AsymEncryptionAlgorithms key_wrap_algorithm) throws IOException
      {
        // TODO Auto-generated method stub
        return null;
      }

    @Override
    public X509Certificate[] getDeviceCertificatePath () throws IOException
      {
        try
          {
            return new X509Certificate[]{(X509Certificate)org.webpki.crypto.test.DemoKeyStore.getMarionKeyStore ().getCertificate ("mykey")};
          }
        catch (GeneralSecurityException gse)
          {
            throw new IOException (gse);
          }
      }

    @Override
    public String getDeviceName ()
      {
        // TODO Auto-generated method stub
        return null;
      }

    @Override
    public boolean isSupported (String algorithm)
      {
        // TODO Auto-generated method stub
        return false;
      }

    @Override
    public byte[] privateKeyDecrypt (byte[] data, int key_id, AsymEncryptionAlgorithms algorithm, byte[] optional_pin, KeyAuthorizationCallback key_auth_callback) throws IOException
      {
        // TODO Auto-generated method stub
        return null;
      }

    @Override
    public byte[] privateKeyDigestSign (byte[] digest, int key_id, SignatureAlgorithms algorithm, byte[] optional_pin, KeyAuthorizationCallback key_auth_callback) throws IOException
      {
        // TODO Auto-generated method stub
        return null;
      }

    @Override
    public byte[] provisionPiggybackedSymmetricKey (String piggyback_mac_algorithm, byte[] encrypted_symmetric_key, byte[] private_key_handle, AsymEncryptionAlgorithms encryption_algorithm, String[] endorsed_algorithms, byte[] declared_mac, byte[] nonce) throws IOException
      {
        // TODO Auto-generated method stub
        return null;
      }

    @Override
    public byte[] sealPrivateKey (PrivateKey private_key, boolean exportable, KeyGen2KeyUsage key_usage) throws IOException
      {
        // TODO Auto-generated method stub
        return null;
      }

    @Override
    public byte[] sealSecretKey (byte[] secret_key, boolean exportable, String[] endorsed_algorithms) throws IOException
      {
        // TODO Auto-generated method stub
        return null;
      }

    @Override
    public byte[] symmetricKeyEncrypt (boolean encrypt_flag, byte[] data, int key_id, SymEncryptionAlgorithms algorithm, byte[] optional_iv, byte[] optional_pin, KeyAuthorizationCallback key_auth_callback) throws IOException
      {
        // TODO Auto-generated method stub
        return null;
      }

    @Override
    public byte[] symmetricKeyHMAC (byte[] data, int key_id, MacAlgorithms algorithm, byte[] optional_pin, KeyAuthorizationCallback key_auth_callback) throws IOException
      {
        // TODO Auto-generated method stub
        return null;
      }


    @Override
    public String[] getSupportedAlgorithms ()
      {
        // TODO Auto-generated method stub
        return null;
      }

  }
