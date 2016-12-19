/*
 *  Copyright 2006-2016 WebPKI.org (http://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.webpki.json.encryption;

import java.io.IOException;

/**
 * JEF (JSON Encryption Format) key encryption algorithms
 */
public enum KeyEncryptionAlgorithms {

    JOSE_ECDH_ES_ALG_ID      ("ECDH-ES",      false),
    JOSE_RSA_OAEP_256_ALG_ID ("RSA-OAEP-256", true);

    String JsonName;
    boolean rsa;

    KeyEncryptionAlgorithms(String JsonName, boolean rsa) {
        this.JsonName = JsonName;
        this.rsa = rsa;
    }

    public boolean isRsa() {
        return rsa;
    }

    @Override
    public String toString() {
        return JsonName;
    }

    public static KeyEncryptionAlgorithms getAlgorithmFromString(String string) throws IOException {
        for (KeyEncryptionAlgorithms algorithm : KeyEncryptionAlgorithms.values()) {
            if (string.equals(algorithm.JsonName)) {
                return algorithm;
            }
        }
        throw new IOException("No such algorithm: " + string);
    }
}
