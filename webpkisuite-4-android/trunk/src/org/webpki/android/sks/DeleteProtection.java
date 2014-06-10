/*
 *  Copyright 2006-2014 WebPKI.org (http://webpki.org).
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
package org.webpki.android.sks;

import java.io.IOException;

public enum DeleteProtection
  {
    NONE           ("none",          SecureKeyStore.EXPORT_DELETE_PROTECTION_NONE),
    PIN            ("pin",           SecureKeyStore.EXPORT_DELETE_PROTECTION_PIN),
    PUK            ("puk",           SecureKeyStore.EXPORT_DELETE_PROTECTION_PUK),
    NON_DELETABLE  ("non-deletable", SecureKeyStore.EXPORT_DELETE_PROTECTION_NOT_ALLOWED);

    private final String name;       // As expressed in protocols
    
    private final byte sks_value;    // As expressed in SKS

    private DeleteProtection (String name, byte sks_value)
      {
        this.name = name;
        this.sks_value = sks_value;
      }


    public String getProtocolName ()
      {
        return name;
      }
    

    public byte getSKSValue ()
      {
        return sks_value;
      }


    public static DeleteProtection getDeletePolicyFromString (String name) throws IOException
      {
        for (DeleteProtection del_pol : DeleteProtection.values ())
          {
            if (name.equals (del_pol.name))
              {
                return del_pol;
              }
          }
        throw new IOException ("Unknown delete policy: " + name);
      }

  }
