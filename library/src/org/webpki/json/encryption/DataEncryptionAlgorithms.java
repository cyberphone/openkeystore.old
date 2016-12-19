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
 * JEF (JSON Encryption Format) data encryption algorithms
 */
public enum DataEncryptionAlgorithms {

    JOSE_A128CBC_HS256_ALG_ID ("A128CBC-HS256", 32),
    JOSE_A256CBC_HS512_ALG_ID ("A256CBC-HS512", 64);

    String JsonName;
    int keyLength;

    DataEncryptionAlgorithms(String JsonName, int keyLength) {
        this.JsonName = JsonName;
        this.keyLength = keyLength;
    }

    public int getKeyLength() {
        return keyLength;
    }

    @Override
    public String toString() {
        return JsonName;
    }

    public static DataEncryptionAlgorithms getAlgorithmFromString(String string) throws IOException {
        for (DataEncryptionAlgorithms algorithm : DataEncryptionAlgorithms.values()) {
            if (string.equals(algorithm.JsonName)) {
                return algorithm;
            }
        }
        throw new IOException("No such algorithm: " + string);
    }
}
