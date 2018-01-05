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

    byte[] dataEncryptionKey;

    PublicKey publicKey;
    
    String provider;

    String remoteUrl;

    JSONRemoteKeys remoteKeyFormat;
    
    AlgorithmPreferences algorithmPreferences = AlgorithmPreferences.JOSE_ACCEPT_PREFER;

    JSONEncrypter() {
    }

    static class EncryptionHeader {

        DataEncryptionAlgorithms dataEncryptionAlgorithm;

        KeyEncryptionAlgorithms globalKeyEncryptionAlgorithm;

        JSONObjectWriter encryptionWriter;

        byte[] dataEncryptionKey;
        
        String globalKeyId;

        EncryptionHeader(DataEncryptionAlgorithms dataEncryptionAlgorithm, JSONEncrypter encrypter) throws IOException {
            this.dataEncryptionAlgorithm = dataEncryptionAlgorithm;
            dataEncryptionKey = encrypter.dataEncryptionKey;
            globalKeyEncryptionAlgorithm = encrypter.keyEncryptionAlgorithm;
            encryptionWriter = new JSONObjectWriter();
            globalKeyId = encrypter.keyId;
            encryptionWriter.setString(JSONCryptoDecoder.ENC_JSON, dataEncryptionAlgorithm.joseName);
            if (globalKeyId != null) {
                encryptionWriter.setString(JSONCryptoDecoder.KID_JSON, globalKeyId);
            }
            if (globalKeyEncryptionAlgorithm != null) {
                encryptionWriter.setString(JSONCryptoDecoder.ALG_JSON, globalKeyEncryptionAlgorithm.joseName);
                if (globalKeyEncryptionAlgorithm.keyWrap) {
                    dataEncryptionKey = EncryptionCore.generateRandom(dataEncryptionAlgorithm.keyLength);
                }
            }
        }

        void createRecipient(JSONEncrypter encrypter, JSONObjectWriter currentRecipient)
        throws IOException, GeneralSecurityException {
            if (encrypter.keyEncryptionAlgorithm != null) {
                currentRecipient.setString(JSONCryptoDecoder.ALG_JSON,
                                           encrypter.keyEncryptionAlgorithm.joseName);
            }
            // Does any of the recipients have a different key encryption algorithm? 
            if (globalKeyEncryptionAlgorithm != encrypter.keyEncryptionAlgorithm) {
                encryptionWriter.root.properties.remove(JSONCryptoDecoder.ALG_JSON);
                globalKeyEncryptionAlgorithm = null;
            }
            if (encrypter.keyId != null) {
                currentRecipient.setString(JSONCryptoDecoder.KID_JSON, encrypter.keyId);
            }
            // Does any of the recipients have a different keyId? 
            if (globalKeyId != null && (encrypter.keyId == null || !globalKeyId.equals(encrypter.keyId))) {
                encryptionWriter.root.properties.remove(JSONCryptoDecoder.KID_JSON);
                globalKeyId = null;
            }
            if (encrypter.outputPublicKeyInfo) {
                encrypter.writeKeyData(currentRecipient);
            }
            if (encrypter.keyEncryptionAlgorithm != null) {
                EncryptionCore.AsymmetricEncryptionResult asymmetricEncryptionResult =
                        encrypter.keyEncryptionAlgorithm.isRsa() ?
                            EncryptionCore.rsaEncryptKey(dataEncryptionKey,
                                                         encrypter.keyEncryptionAlgorithm,
                                                         dataEncryptionAlgorithm,
                                                         encrypter.publicKey)
                                                       :
                            EncryptionCore.senderKeyAgreement(dataEncryptionKey,
                                                              encrypter.keyEncryptionAlgorithm,
                                                              dataEncryptionAlgorithm,
                                                              encrypter.publicKey);
                dataEncryptionKey = asymmetricEncryptionResult.getDataEncryptionKey();
                if (!encrypter.keyEncryptionAlgorithm.isRsa()) {
                    currentRecipient
                        .setObject(JSONCryptoDecoder.EPK_JSON,
                                   JSONObjectWriter
                                       .createCorePublicKey(asymmetricEncryptionResult.getEphemeralKey(),
                                                            AlgorithmPreferences.JOSE));
                }
                if (encrypter.keyEncryptionAlgorithm.isKeyWrap()) {
                    currentRecipient.setBinary(JSONCryptoDecoder.ENCRYPTED_KEY_JSON,
                                               asymmetricEncryptionResult.getEncryptedKeyData());
                }
            }

            if (encrypter.extensions != null) {
                currentRecipient.setStringArray(JSONCryptoDecoder.CRIT_JSON, encrypter.extensions.getProperties());
                for (String property : encrypter.extensions.getProperties()) {
                    currentRecipient.setProperty(property, encrypter.extensions.getProperty(property));
                }
            }
        }

        void cleanRecipient(JSONObjectWriter recipient) {

            // All recipients have the same keyId?  If so remove the local definition
            if (globalKeyId != null) {
                recipient.root.properties.remove(JSONCryptoDecoder.KID_JSON);
            }

            // All recipients use the same key encryption algorithm?  If so remove the local definition
            if (globalKeyEncryptionAlgorithm != null) {
                recipient.root.properties.remove(JSONCryptoDecoder.ALG_JSON);
            }
        }

        JSONObjectWriter finalizeEncryption(byte[] unencryptedData) throws IOException, GeneralSecurityException {
            byte[] iv = EncryptionCore.createIv(dataEncryptionAlgorithm);
            encryptionWriter.setBinary(JSONCryptoDecoder.IV_JSON, iv);
            EncryptionCore.SymmetricEncryptionResult symmetricEncryptionResult =
                EncryptionCore.contentEncryption(dataEncryptionAlgorithm,
                                                 dataEncryptionKey,
                                                 iv,
                                                 unencryptedData,
                                                 encryptionWriter.serializeToBytes(JSONOutputFormats.NORMALIZED));
            encryptionWriter.setBinary(JSONCryptoDecoder.TAG_JSON, symmetricEncryptionResult.getTag());
            encryptionWriter.setBinary(JSONCryptoDecoder.CIPHER_TEXT_JSON, symmetricEncryptionResult.getCipherText());
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
        JSONCryptoDecoder.checkExtensions(this.extensions.getProperties(), true);
        return this;
    }

    void setRemoteKey(String url, JSONRemoteKeys format) throws IOException {
        this.remoteUrl = JSONSignatureDecoder.checkHttpsUrl(url);
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
