/*
 *  Copyright 2006-2010 WebPKI.org (http://webpki.org).
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
    X509Certificate[] certificate_path;
    String[] algorithms;
    short[] rsa_key_sizes;
    
    public X509Certificate[] getDeviceCertificatePath ()
      {
        return certificate_path;
      }
    
    public short[] getRSAKeySizes ()
      {
        return rsa_key_sizes;
      }
    
    public String[] getAlgorithms ()
      {
        return algorithms;
      }
    
    public DeviceInfo (X509Certificate[] certificate_path,
                       short[] rsa_key_sizes,
                       String[] algorithms)
      {
        this.certificate_path = certificate_path;
        this.rsa_key_sizes = rsa_key_sizes;
        this.algorithms = algorithms;
      }

  }
