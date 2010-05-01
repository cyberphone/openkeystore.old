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

    public interface FORMATS
      {
        String PKCS8_PRIVATE_KEY_INFO      = "http://xmlns.webpki.org/keygen2/1.0#format.pkcs8";
      }


    public interface ALGORITHMS
      {
        String ANY                         = "http://xmlns.webpki.org/keygen2/1.0#algorithm.any";

        String KEY_ATTESTATION_1           = "http://xmlns.webpki.org/keygen2/1.0#algorithm.ka1";

        String SESSION_KEY_1               = "http://xmlns.webpki.org/keygen2/1.0#algorithm.sk1";

        String MAC_PIGGYBACK_1             = "http://xmlns.webpki.org/keygen2/1.0#algorithm.mac-piggyback-1";

        String MAC_PRESET_VALUES_1         = "http://xmlns.webpki.org/keygen2/1.0#algorithm.mac-preset-values-1";
      }


    public interface OTPPROVIDERS
      {
        String IETF_HOTP                   = "http://xmlns.webpki.org/keygen2/1.0#provider.ietf-hotp";

        String IETF_TOTP                   = "http://xmlns.webpki.org/keygen2/1.0#provider.ietf-totp";

        String IETF_OCRA                   = "http://xmlns.webpki.org/keygen2/1.0#provider.ietf-ocra";

        String RSA_SECURID                 = "http://www.rsasecurity.com/rsalabs/otps/schemas/2005/09/otps-wst#SecurID-AES";

        String RSA_SECURID_EVENT           = "http://www.rsa.com/names/2008/04/algorithms/SecurID#SecurID-AES128-Counter";
      }


    public interface LOGOTYPES
      {
        String ICON                        = "http://xmlns.webpki.org/keygen2/1.0#logotype.icon";

        String CARD                        = "http://xmlns.webpki.org/keygen2/1.0#logotype.card";

        String LIST                        = "http://xmlns.webpki.org/keygen2/1.0#logotype.list";

        String APPLICATION                 = "http://xmlns.webpki.org/keygen2/1.0#logotype.application";
      }

  }
