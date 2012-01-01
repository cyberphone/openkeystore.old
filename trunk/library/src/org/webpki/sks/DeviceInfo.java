/*
 *  Copyright 2006-2012 WebPKI.org (http://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.webpki.sks;

import java.security.cert.X509Certificate;

public class DeviceInfo
  {
    ///////////////////////////////////////////////////////////////////////////////////
    // "DeviceType" constants
    ///////////////////////////////////////////////////////////////////////////////////
    public static final byte LOCATION_EXTERNAL           = 0x00;
    public static final byte LOCATION_EMBEDDED           = 0x01;
    public static final byte LOCATION_SOCKETED           = 0x02;
    public static final byte LOCATION_SIM                = 0x03;
    public static final byte LOCATION_MASK               = 0x03;
    
    public static final byte TYPE_SOFTWARE               = 0x00;
    public static final byte TYPE_HARDWARE               = 0x04;
    public static final byte TYPE_HSM                    = 0x08;
    public static final byte TYPE_CPU                    = 0x0C;
    public static final byte TYPE_MASK                   = 0x0C;
    
    short api_level;
    
    public short getAPILevel ()
      {
        return api_level;
      }
    
    private byte device_type;

    public byte getDeviceType ()
      {
        return device_type;
      }

    String update_url;
    
    public String getUpdateURL ()
      {
        return update_url;
      }

    String vendor_name;
    
    public String getVendorName ()
      {
        return vendor_name;
      }
    
    String vendor_description;
    
    public String getVendorDescription ()
      {
        return vendor_description;
      }
    
    X509Certificate[] certificate_path;
    
    public X509Certificate[] getCertificatePath ()
      {
        return certificate_path;
      }
    
    String[] supported_algorithms;
    
    public String[] getSupportedAlgorithms ()
      {
        return supported_algorithms;
      }

    boolean rsa_exponent_support;
    
    public boolean getRSAExponentSupport ()
      {
        return rsa_exponent_support;
      }
    
    short[] rsa_key_sizes;

    public short[] getRSAKeySizes ()
      {
        return rsa_key_sizes;
      }
    
    int crypto_data_size;
    
    public int getCryptoDataSize ()
      {
        return crypto_data_size;
      }
    
    int extension_data_size;
    
    public int getExtensionDataSize ()
      {
        return extension_data_size;
      }
    
    boolean device_pin_support;
    
    public boolean getDevicePINSupport ()
      {
        return device_pin_support;
      }
    
    boolean biometric_support;
    
    public boolean getBiometricSupport ()
      {
        return biometric_support;
      }
    
    String connection_port;
    /**
     * Holds an optional system-dependent string telling which logical
     * or physical port the SKS is connected to.  This information is
     * not gathered from the SKS device itself, but from the calling
     * environment.  Suitable strings include "USB:4", "COM3", "TCP:192.168.0.45",
     * "/dev/term3", "PCI:2", "Embedded", "SIM", "http://net-hsm/sks", etc.
     */
    public String getConnectionPort ()
      {
        return connection_port;
      }

    /**
     * 
     * @see #getConnectionPort()
     */
    public void setConnectionPort (String connection_port)
      {
        this.connection_port = connection_port;
      }

    
    public DeviceInfo (short api_level,
                       byte device_type,
                       String update_url,  // May be null
                       String vendor_name,
                       String vendor_description,
                       X509Certificate[] certificate_path,
                       String[] supported_algorithms,
                       boolean rsa_exponent_support,
                       short[] rsa_key_sizes,
                       int crypto_data_size,
                       int extension_data_size,
                       boolean device_pin_support,
                       boolean biometric_support)
      {
        this.api_level = api_level;
        this.device_type = device_type;
        this.update_url = update_url;
        this.vendor_name = vendor_name;
        this.vendor_description = vendor_description;
        this.certificate_path = certificate_path;
        this.supported_algorithms = supported_algorithms;
        this.rsa_exponent_support = rsa_exponent_support;
        this.rsa_key_sizes = rsa_key_sizes;
        this.crypto_data_size = crypto_data_size;
        this.extension_data_size = extension_data_size;
        this.device_pin_support = device_pin_support;
        this.biometric_support = biometric_support;
      }
  }
