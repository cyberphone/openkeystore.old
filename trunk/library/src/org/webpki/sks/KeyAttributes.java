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
import java.util.HashSet;

public class KeyAttributes
  {
    static final byte KEY_USAGE_SIGNATURE                  = 0x01;
    static final byte KEY_USAGE_AUTHENTICATION             = 0x02;
    static final byte KEY_USAGE_ENCRYPTION                 = 0x04;
    static final byte KEY_USAGE_UNIVERSAL                  = 0x08;
    static final byte KEY_USAGE_TRANSPORT                  = 0x10;
    static final byte KEY_USAGE_SYMMETRIC_KEY              = 0x20;

    byte key_usage;
    
    X509Certificate[] certificate_path;
    
    HashSet<String> extension_types;
    
    public X509Certificate[] getCertificatePath ()
      {
        return certificate_path;
      }
    
    public boolean isSymmetric ()
      {
        return key_usage == KEY_USAGE_SYMMETRIC_KEY;
      }

    public HashSet<String> getExtensionTypes ()
      {
        return extension_types;
      }
    
    public KeyAttributes (byte key_usage,
                          X509Certificate[] certificate_path,
                          HashSet<String> extension_types)
      {
        this.key_usage = key_usage;
        this.certificate_path = certificate_path;
        this.extension_types = extension_types;
      }
  }
