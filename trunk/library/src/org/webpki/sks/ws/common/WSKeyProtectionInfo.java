package org.webpki.sks.ws.common;

import javax.jws.WebService;

import javax.xml.bind.annotation.XmlElement;

import org.webpki.sks.KeyProtectionInfo;
import org.webpki.sks.SKSException;
import org.webpki.sks.SecureKeyStore;

@WebService
public class WSKeyProtectionInfo
  {
    public WSKeyProtectionInfo ()
      {
      }
    
    public WSKeyProtectionInfo (KeyProtectionInfo kpi)
      {
        protection_status = kpi.isDevicePINProtected () ? SecureKeyStore.PROTECTION_STATUS_PIN_PROTECTED : 0;
      }

    private byte protection_status;
    

    @XmlElement(name="ProtectionStatus")
    public byte getProtectionStatus ()
      {
        return protection_status;
      }
    
    public void setProtectionStatus (byte protection_status)
      {
        this.protection_status = protection_status;
      }
    
  }
