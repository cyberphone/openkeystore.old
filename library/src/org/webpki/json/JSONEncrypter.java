/*
 *  Copyright 2006-2018 WebPKI.org (http://webpki.org).
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
package org.webpki.json;

import java.io.IOException;
import java.io.Serializable;

import java.security.GeneralSecurityException;
import java.security.PublicKey;

import java.util.LinkedHashSet;

import org.webpki.crypto.AlgorithmPreferences;

/**
 * Support class for encryption generators.
 */
public abstract class JSONEncrypter implements Serializable {

    private static final long serialVersionUID = 1L;

    JSONObjectReader extensions;
    
    String keyId;

    boolean outputPublicKeyInfo = true;
    
    KeyEncryptionAlgorithms keyEncryptionAlgorithm;

    byte[] contentEncryptionKey;

    PublicKey publicKey;
    
    String remoteUrl;

    JSONRemoteKeys remoteKeyFormat;
    
    AlgorithmPreferences algorithmPreferences = AlgorithmPreferences.JOSE_ACCEPT_PREFER;

    JSONEncrypter() {
    }

    static class Header {

        ContentEncryptionAlgorithms contentEncryptionAlgorithm;

        KeyEncryptionAlgorithms globalKeyEncryptionAlgorithm;

        JSONObjectWriter encryptionWriter;

        byte[] contentEncryptionKey;
        
        LinkedHashSet<String> foundExtensions = new LinkedHashSet<String>();
        
        Header(ContentEncryptionAlgorithms contentEncryptionAlgorithm, JSONEncrypter encrypter) throws IOException {
            this.contentEncryptionAlgorithm = contentEncryptionAlgorithm;
            contentEncryptionKey = encrypter.contentEncryptionKey;
            globalKeyEncryptionAlgorithm = encrypter.keyEncryptionAlgorithm;
            encryptionWriter = new JSONObjectWriter();
            encryptionWriter.setString(JSONCryptoHelper.ENC_JSON, contentEncryptionAlgorithm.joseName);
            encryptionWriter.setString(JSONCryptoHelper.ALG_JSON, globalKeyEncryptionAlgorithm.joseName);
            if (globalKeyEncryptionAlgorithm.keyWrap) {
                contentEncryptionKey = EncryptionCore.generateRandom(contentEncryptionAlgorithm.keyLength);
            }
        }

        void createRecipient(JSONEncrypter encrypter, JSONObjectWriter currentRecipient)
        throws IOException, GeneralSecurityException {
            currentRecipient.setString(JSONCryptoHelper.ALG_JSON, encrypter.keyEncryptionAlgorithm.joseName);
            // Does any of the recipients have a different key encryption algorithm? 
            if (globalKeyEncryptionAlgorithm != encrypter.keyEncryptionAlgorithm) {
                encryptionWriter.root.properties.remove(JSONCryptoHelper.ALG_JSON);
                globalKeyEncryptionAlgorithm = null;
            }
            if (encrypter.keyId != null) {
                currentRecipient.setString(JSONCryptoHelper.KID_JSON, encrypter.keyId);
            }

            // "jku"/"x5u" and "jwk"/"x5c" are mutually exclusive
            if (encrypter.remoteUrl == null) {
                if (encrypter.outputPublicKeyInfo) {
                    encrypter.writeKeyData(currentRecipient);
                }
            } else {
                currentRecipient.setString(encrypter.remoteKeyFormat.jsonName, encrypter.remoteUrl);
            }

            // The encrypted key part (if any)
            if (encrypter.keyEncryptionAlgorithm != KeyEncryptionAlgorithms.JOSE_DIRECT_ALG_ID) {
                EncryptionCore.AsymmetricEncryptionResult asymmetricEncryptionResult =
                        encrypter.keyEncryptionAlgorithm.isRsa() ?
                            EncryptionCore.rsaEncryptKey(contentEncryptionKey,
                                                         encrypter.keyEncryptionAlgorithm,
                                                         contentEncryptionAlgorithm,
                                                         encrypter.publicKey)
                                                       :
                            EncryptionCore.senderKeyAgreement(contentEncryptionKey,
                                                              encrypter.keyEncryptionAlgorithm,
                                                              contentEncryptionAlgorithm,
                                                              encrypter.publicKey);
                contentEncryptionKey = asymmetricEncryptionResult.getDataEncryptionKey();
                if (!encrypter.keyEncryptionAlgorithm.isRsa()) {
                    currentRecipient
                        .setObject(JSONCryptoHelper.EPK_JSON,
                                   JSONObjectWriter
                                       .createCorePublicKey(asymmetricEncryptionResult.getEphemeralKey(),
                                                            AlgorithmPreferences.JOSE));
                }
                if (encrypter.keyEncryptionAlgorithm.isKeyWrap()) {
                    currentRecipient.setBinary(JSONCryptoHelper.ENCRYPTED_KEY_JSON,
                                               asymmetricEncryptionResult.getEncryptedKeyData());
                }
            }

            if (encrypter.extensions != null) {
                for (String property : encrypter.extensions.getProperties()) {
                    foundExtensions.add(property);
                    currentRecipient.setProperty(property, encrypter.extensions.getProperty(property));
                }
            }
        }

        void cleanRecipient(JSONObjectWriter recipient) {

            // All recipients use the same key encryption algorithm?  If so remove the local definition
            if (globalKeyEncryptionAlgorithm != null) {
                recipient.root.properties.remove(JSONCryptoHelper.ALG_JSON);
            }
        }

        JSONObjectWriter finalizeEncryption(byte[] unencryptedData) throws IOException, GeneralSecurityException {
            if (!foundExtensions.isEmpty()) {
                encryptionWriter.setStringArray(JSONCryptoHelper.CRIT_JSON,
                                                foundExtensions.toArray(new String[0]));
            }
            byte[] iv = EncryptionCore.createIv(contentEncryptionAlgorithm);
            EncryptionCore.SymmetricEncryptionResult symmetricEncryptionResult =
                EncryptionCore.contentEncryption(contentEncryptionAlgorithm,
                                                 contentEncryptionKey,
                                                 iv,
                                                 unencryptedData,
                                                 encryptionWriter.serializeToBytes(JSONCryptoHelper.cryptoSerialization));
            encryptionWriter.setBinary(JSONCryptoHelper.IV_JSON, iv);
            encryptionWriter.setBinary(JSONCryptoHelper.TAG_JSON, symmetricEncryptionResult.getTag());
            encryptionWriter.setBinary(JSONCryptoHelper.CIPHER_TEXT_JSON, symmetricEncryptionResult.getCipherText());
            return encryptionWriter;
        }
    }

    abstract void writeKeyData(JSONObjectWriter wr) throws IOException;

    /**
     * Set &quot;crit&quot; for this encryption object.
     * @param extensions JSON object holding the extension properties and associated values
     * @return this
     * @throws IOException &nbsp;
     */
    public JSONEncrypter setExtensions(JSONObjectWriter extensions) throws IOException {
        this.extensions = new JSONObjectReader(extensions);
        JSONCryptoHelper.checkExtensions(this.extensions.getProperties(), true);
        return this;
    }

    void setRemoteKey(String url, JSONRemoteKeys format) throws IOException {
        this.remoteUrl = JSONCryptoHelper.checkHttpsUrl(url);
        this.remoteKeyFormat = format;
    }

    /**
     * Set optional &quot;kid&quot; for this encryption object.
     * @param keyId The identifier
     * @return this
     */
    public JSONEncrypter setKeyId(String keyId) {
        this.keyId = keyId;
        return this;
    }

    /**
     * Set if public key information should be provided in the encryption object.
     * Note: default <code>true</code>.
     * @param flag <code>true</code> if such information is to be provided
     * @return this
     */
    public JSONEncrypter setOutputPublicKeyInfo(boolean flag) {
        this.outputPublicKeyInfo = flag;
        return this;
    }
}
