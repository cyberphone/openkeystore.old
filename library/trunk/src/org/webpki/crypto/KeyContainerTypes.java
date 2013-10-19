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
package org.webpki.crypto;

import java.io.IOException;


public enum KeyContainerTypes 
  {
    SOFTWARE ("software"),
    EMBEDDED ("embedded"),  // TPM, SKS, TEE, TXT
    UICC     ("uicc"),      // SIM card
    SD_CARD  ("sdcard"),
    EXTERNAL ("external");  // Smart card, HSM
    
    String name;
    
    KeyContainerTypes (String name)
      {
        this.name = name;  
      }
    
    public String getName ()
      {
        return name;
      }

    public static KeyContainerTypes getKeyContainerType (String arg) throws IOException
      {
        for (KeyContainerTypes type : values ())
          {
            if (type.toString ().equalsIgnoreCase (arg))
              {
                return type;
              }
          }
        throw new IOException ("Bad container name: " + arg);
      }
  }
