/*
 *  Copyright 2006-2013 WebPKI.org (http://webpki.org).
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

import java.io.IOException;

public enum BiometricProtection
  {
    NONE             ("none",        SecureKeyStore.BIOMETRIC_PROTECTION_NONE),
    ALTERNATIVE      ("alternative", SecureKeyStore.BIOMETRIC_PROTECTION_ALTERNATIVE),
    COMBINED         ("combined",    SecureKeyStore.BIOMETRIC_PROTECTION_COMBINED),
    EXCLUSIVE        ("exclusive",   SecureKeyStore.BIOMETRIC_PROTECTION_EXCLUSIVE);

    private final String xml_name;       // As expressed in XML
    
    private final byte sks_value;        // As expressed in SKS

    private BiometricProtection (String xml_name, byte sks_value)
      {
        this.xml_name = xml_name;
        this.sks_value = sks_value;
      }


    public String getXMLName ()
      {
        return xml_name;
      }
    

    public byte getSKSValue ()
      {
        return sks_value;
      }


    public static BiometricProtection getBiometricProtectionFromString (String xml_name) throws IOException
      {
        for (BiometricProtection biom_type : BiometricProtection.values ())
          {
            if (xml_name.equals (biom_type.xml_name))
              {
                return biom_type;
              }
          }
        throw new IOException ("Unknown biometric type: " + xml_name);
      }

  }
