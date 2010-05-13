package org.webpki.sks.test;

import org.webpki.sks.DeviceInfo;
import org.webpki.sks.SKSException;
import org.webpki.sks.SecureKeyStore;

public class Device
  {
    DeviceInfo device_info;
    
    SecureKeyStore sks;

    public Device (SecureKeyStore sks) throws SKSException
      {
        device_info = sks.getDeviceInfo ();
        this.sks = sks;
      }
  }
