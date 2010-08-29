package org.webpki.sksimpl.hwdevice;

import java.io.IOException;

import java.util.ServiceLoader;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;

import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;

import org.webpki.io.serial.SerialDeviceDriver;
import org.webpki.io.serial.SerialPortService;
import org.webpki.io.serial.SerialDeviceDriver.ByteArrayReturn;
import org.webpki.io.serial.SerialDeviceDriver.OutputBuffer;


public class DeviceInitialization extends SerialDeviceDriver
  {
    static SerialPortService serial_port_service = ServiceLoader.load (SerialPortService.class).iterator ().next ();
    
    private static final int LOCAL_COMMAND_CREATE_RSA_KEYS = 128;
    
    private static final int LOCAL_COMMAND_SET_DEVICE_CERT = 129;

    public DeviceInitialization (String port, int baud_rate)
      {
        super (port, baud_rate);
      }

    
    public DeviceInitialization () throws IOException
      {
        super (serial_port_service.getPortID (), serial_port_service.getBaudRate ());
      }
    
    
    public PublicKey createDeviceRSAKeyPair (byte[] seed) throws IOException, GeneralSecurityException
      {
        return KeyFactory.getInstance ("RSA").generatePublic
          (
            new X509EncodedKeySpec 
              (
                ((ByteArrayReturn) new OutputBuffer (this)
                                       .putByte (LOCAL_COMMAND_CREATE_RSA_KEYS)
                                       .putArray (seed)
                                       .sendBuffer (new ByteArrayReturn ())).getArray ()
              )
          );
      }


    public void setDeviceCertificate (X509Certificate certificate) throws IOException, GeneralSecurityException
      {
        new OutputBuffer (this)
            .putByte (LOCAL_COMMAND_SET_DEVICE_CERT)
            .putArray (certificate.getEncoded ())
            .sendBuffer (new VoidReturn ());
      }

  }

