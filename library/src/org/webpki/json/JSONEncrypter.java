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

        KeyEncryptionAlgorithms keyEncryptionAlgorithm;

        JSONObjectWriter encryptionWriter;

        JSONObjectReader extensions;
        
        byte[] dataEncryptionKey;
        
        String keyId;

        EncryptionHeader(DataEncryptionAlgorithms dataEncryptionAlgorithm, JSONEncrypter encrypter) throws IOException {
            this.dataEncryptionAlgorithm = dataEncryptionAlgorithm;
            dataEncryptionKey = encrypter.dataEncryptionKey;
            keyEncryptionAlgorithm = encrypter.keyEncryptionAlgorithm;
            encryptionWriter = new JSONObjectWriter();
            if ((extensions = encrypter.extensions) != null) {
                for (String property : extensions.getProperties()) {
                    encryptionWriter.setProperty(property, extensions.getProperty(property));
                }
            }
            keyId = encrypter.keyId;
            encryptionWriter.setString(JSONDecryptionDecoder.ENC_JSON, dataEncryptionAlgorithm.joseName);
            if (keyId != null) {
                encryptionWriter.setString(JSONSignatureDecoder.KID_JSON, keyId);
            }
            if (keyEncryptionAlgorithm != null) {
                encryptionWriter.setString(JSONSignatureDecoder.ALG_JSON, keyEncryptionAlgorithm.joseName);
                if (keyEncryptionAlgorithm.keyWrap) {
                    dataEncryptionKey = EncryptionCore.generateRandom(dataEncryptionAlgorithm.keyLength);
                }
            }
        }

        void createRecipient(JSONEncrypter encrypter, JSONObjectWriter currentRecipient) throws IOException, GeneralSecurityException {
            if (keyId != null && (encrypter.keyId == null || !keyId.equals(encrypter.keyId))) {
                encryptionWriter.root.properties.remove(JSONSignatureDecoder.KID_JSON);
                keyId = null;
            }
            if (encrypter.keyId != null) {
                currentRecipient.setString(JSONSignatureDecoder.KID_JSON, encrypter.keyId);
            }
            if (keyEncryptionAlgorithm != encrypter.keyEncryptionAlgorithm) {
                if (keyEncryptionAlgorithm != null) {
                    encryptionWriter.root.properties.remove(JSONSignatureDecoder.ALG_JSON);
                }
                keyEncryptionAlgorithm = null;
            }
            if (!(extensions == null ? "" : extensions.toString()).equals(
                    encrypter.extensions == null ? "" : encrypter.extensions.toString())) {
                throw new IOException("Extensions must be identical for each encryption specifier");
            }
            if (encrypter.outputPublicKeyInfo) {
                encrypter.writeKeyData(currentRecipient);
            }
            if (keyEncryptionAlgorithm != null) {
                EncryptionCore.AsymmetricEncryptionResult asymmetricEncryptionResult =
                        keyEncryptionAlgorithm.isRsa() ?
                            EncryptionCore.rsaEncryptKey(dataEncryptionKey,
                                                         keyEncryptionAlgorithm,
                                                         dataEncryptionAlgorithm,
                                                         encrypter.publicKey)
                                                       :
                            EncryptionCore.senderKeyAgreement(dataEncryptionKey,
                                                              keyEncryptionAlgorithm,
                                                              dataEncryptionAlgorithm,
                                                              encrypter.publicKey);
                dataEncryptionKey = asymmetricEncryptionResult.getDataEncryptionKey();
                if (!keyEncryptionAlgorithm.isRsa()) {
                    currentRecipient
                        .setObject(JSONDecryptionDecoder.EPK_JSON,
                                   JSONObjectWriter
                                       .createCorePublicKey(asymmetricEncryptionResult.getEphemeralKey(),
                                                            AlgorithmPreferences.JOSE));
                }
                if (keyEncryptionAlgorithm.isKeyWrap()) {
                    currentRecipient.setBinary(JSONDecryptionDecoder.ENCRYPTED_KEY_JSON,
                                               asymmetricEncryptionResult.getEncryptedKeyData());
                }
            }
        }

        void cleanRecipient(JSONObjectWriter recipient) {
            if (keyId != null) {
                recipient.root.properties.remove(JSONSignatureDecoder.KID_JSON);
            }
            if (keyEncryptionAlgorithm != null) {
                recipient.root.properties.remove(JSONSignatureDecoder.ALG_JSON);
            }
        }

        JSONObjectWriter finalizeEncryption(byte[] unencryptedData) throws IOException, GeneralSecurityException {
            if (extensions != null) {
                encryptionWriter.setStringArray(JSONSignatureDecoder.CRIT_JSON, extensions.getProperties());
            }
            EncryptionCore.SymmetricEncryptionResult symmetricEncryptionResult =
                EncryptionCore.contentEncryption(dataEncryptionAlgorithm,
                                                 dataEncryptionKey,
                                                 unencryptedData,
                                                 encryptionWriter.serializeToBytes(JSONOutputFormats.NORMALIZED));
            encryptionWriter.setBinary(JSONDecryptionDecoder.IV_JSON, symmetricEncryptionResult.getIv());
            encryptionWriter.setBinary(JSONDecryptionDecoder.TAG_JSON, symmetricEncryptionResult.getTag());
            encryptionWriter.setBinary(JSONDecryptionDecoder.CIPHER_TEXT_JSON, symmetricEncryptionResult.getCipherText());
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
        JSONDecryptionDecoder.checkExtensions(this.extensions.getProperties());
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
