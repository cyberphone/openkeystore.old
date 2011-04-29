/*
 *  Copyright 2006-2011 WebPKI.org (http://webpki.org).
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
    short api_level;
    
    public short getAPILevel ()
      {
        return api_level;
      }
    
    String update_url;
    
    public String getUpdateURL ()
      {
        return update_url;
      }

    public String vendor_name;
    
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
    
    String[] algorithms;
    
    public String[] getAlgorithms ()
      {
        return algorithms;
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
    
    
    public DeviceInfo (short api_level,
                       String update_url,  // May be null
                       String vendor_name,
                       String vendor_description,
                       X509Certificate[] certificate_path,
                       String[] algorithms,
                       boolean rsa_exponent_support,
                       short[] rsa_key_sizes,
                       int crypto_data_size,
                       int extension_data_size,
                       boolean device_pin_support,
                       boolean biometric_support)
      {
        this.api_level = api_level;
        this.update_url = update_url;
        this.vendor_name = vendor_name;
        this.vendor_description = vendor_description;
        this.certificate_path = certificate_path;
        this.algorithms = algorithms;
        this.rsa_exponent_support = rsa_exponent_support;
        this.rsa_key_sizes = rsa_key_sizes;
        this.crypto_data_size = crypto_data_size;
        this.extension_data_size = extension_data_size;
        this.device_pin_support = device_pin_support;
        this.biometric_support = biometric_support;
      }
  }
