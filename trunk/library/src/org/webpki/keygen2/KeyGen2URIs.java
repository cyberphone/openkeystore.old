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

public interface KeyGen2URIs
  {

    public interface ALGORITHMS
      {
        String KEY_ATTESTATION_1           = "http://xmlns.webpki.org/keygen2/1.0#algorithm.ka1";

        String SESSION_KEY_1               = "http://xmlns.webpki.org/keygen2/1.0#algorithm.sk1";
        
        String ECB_NOPAD                   = "http://xmlns.webpki.org/keygen2/1.0#algorithm.aes.ecb.nopad";
        
        String ECB_PKCS_5                  = "http://xmlns.webpki.org/keygen2/1.0#algorithm.aes.ecb.pkcs5";
        
        String RSA_NONE                    = "http://xmlns.webpki.org/keygen2/1.0#algorithm.rsa.none";
        
        String ECDSA_NONE                  = "http://xmlns.webpki.org/keygen2/1.0#algorithm.ecdsa.none";
        
        String NONE                        = "http://xmlns.webpki.org/keygen2/1.0#algorithm.none";

      }


    public interface LOGOTYPES
      {
        String ICON                        = "http://xmlns.webpki.org/keygen2/1.0#logotype.icon";

        String CARD                        = "http://xmlns.webpki.org/keygen2/1.0#logotype.card";

        String LIST                        = "http://xmlns.webpki.org/keygen2/1.0#logotype.list";

        String APPLICATION                 = "http://xmlns.webpki.org/keygen2/1.0#logotype.application";
      }

  }
