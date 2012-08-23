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
package org.webpki.keygen2;

public interface KeyGen2URIs
  {
    public interface SPECIAL_ALGORITHMS
      {
        String KEY_ATTESTATION_1           = "http://xmlns.webpki.org/keygen2/1.0#algorithm.sks.k1";

        String SESSION_KEY_1               = "http://xmlns.webpki.org/keygen2/1.0#algorithm.sks.s1";

        String ECDH_RAW                    = "http://xmlns.webpki.org/keygen2/1.0#algorithm.ecdh.raw";

        String NONE                        = "http://xmlns.webpki.org/keygen2/1.0#algorithm.none";

      }

    public interface LOGOTYPES
      {
        String ICON                        = "http://xmlns.webpki.org/keygen2/1.0#logotype.icon";

        String CARD                        = "http://xmlns.webpki.org/keygen2/1.0#logotype.card";

        String LIST                        = "http://xmlns.webpki.org/keygen2/1.0#logotype.list";

        String APPLICATION                 = "http://xmlns.webpki.org/keygen2/1.0#logotype.application";
      }

    public interface CLIENT_ATTRIBUTES
      {
        String IMEI_NUMBER                 = "http://xmlns.webpki.org/keygen2/1.0#clientattribute.imei-number";
  
        String MAC_ADDRESS                 = "http://xmlns.webpki.org/keygen2/1.0#clientattribute.mac-address";
  
        String IP_ADDRESS                  = "http://xmlns.webpki.org/keygen2/1.0#clientattribute.ip-address";

        String OS_VENDOR                   = "http://xmlns.webpki.org/keygen2/1.0#clientattribute.os-vendor";

        String OS_VERSION                  = "http://xmlns.webpki.org/keygen2/1.0#clientattribute.os-version";
      }
  }
