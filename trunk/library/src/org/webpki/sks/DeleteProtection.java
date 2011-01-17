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

import java.io.IOException;

public enum DeleteProtection
  {
    NONE              ("none",          (byte)0x00),
    PIN               ("pin",           (byte)0x01),
    PUK               ("puk",           (byte)0x02),
    NON_DELETABLE     ("non-deletable", (byte)0x03);

    private final String xml_name;       // As expressed in XML
    
    private final byte sks_value;        // As expressed in SKS

    private DeleteProtection (String xml_name, byte sks_value)
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


    public static DeleteProtection getDeletePolicyFromString (String xml_name) throws IOException
      {
        for (DeleteProtection del_pol : DeleteProtection.values ())
          {
            if (xml_name.equals (del_pol.xml_name))
              {
                return del_pol;
              }
          }
        throw new IOException ("Unknown delete policy: " + xml_name);
      }

  }
