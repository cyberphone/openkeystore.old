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
package org.webpki.sks;

import java.io.IOException;

public enum Grouping
  {
    NONE                     ("none",               SecureKeyStore.PIN_GROUPING_NONE),
    SHARED                   ("shared",             SecureKeyStore.PIN_GROUPING_SHARED),
    SIGNATURE_PLUS_STANDARD  ("signature+standard", SecureKeyStore.PIN_GROUPING_SIGN_PLUS_STD),
    UNIQUE                   ("unique",             SecureKeyStore.PIN_GROUPING_UNIQUE);

    private final String name;       // As expressed in protocols
    
    private final byte sks_value;    // As expressed in SKS

    private Grouping (String name, byte sks_value)
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


    public static Grouping getGroupingFromString (String name) throws IOException
      {
        for (Grouping option : Grouping.values ())
          {
            if (name.equals (option.name))
              {
                return option;
              }
          }
        throw new IOException ("Unknown group: " + name);
      }

  }
