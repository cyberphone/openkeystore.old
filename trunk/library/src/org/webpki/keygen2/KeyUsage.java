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
package org.webpki.keygen2;

import java.io.IOException;


public enum KeyUsage
  {
    SIGNATURE                  ("signature",      (byte)0x01),
    AUTHENTICATION             ("authentication", (byte)0x02),
    ENCRYPTION                 ("encryption",     (byte)0x04),
    UNIVERSAL                  ("universal",      (byte)0x08),
    TRANSPORT                  ("transport",      (byte)0x10),
    SYMMETRIC_KEY              ("symmetric-key",  (byte)0x20);

    private final String xml_name;       // As expressed in XML
    
    private final byte sks_value;        // As expressed in SKS

    private KeyUsage (String xml_name, byte sks_value)
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


    public static KeyUsage getKeyUsageFromString (String xml_name) throws IOException
      {
        for (KeyUsage key_type : KeyUsage.values ())
          {
            if (xml_name.equals (key_type.xml_name))
              {
                return key_type;
              }
          }
        throw new IOException ("Unknown key-type: " + xml_name);
      }

  }
