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

import java.security.interfaces.ECPublicKey;

/**
 * Return object for ECDH and RSA encryptions.
 */
public class AsymmetricEncryptionResult {
    private byte[] dataEncryptionKey;
    private byte[] encryptedKeyData;
    private ECPublicKey ephemeralKey;

    AsymmetricEncryptionResult(byte[] dataEncryptionKey,
                               byte[] encryptedKeyData,
                               ECPublicKey ephemeralKey) {
        this.dataEncryptionKey = dataEncryptionKey;
        this.encryptedKeyData = encryptedKeyData;
        this.ephemeralKey = ephemeralKey;
    }

    public byte[] getDataEncryptionKey() {
        return dataEncryptionKey;
    }

    public byte[] getEncryptedKeyData() {
        return encryptedKeyData;
    }

    public ECPublicKey getEphemeralKey() {
        return ephemeralKey;
    }
}
