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

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;

import java.security.interfaces.ECPublicKey;

import java.util.LinkedHashMap;
import java.util.Vector;

////////////////////////////////////////////////////////////////////////////////
// JEF is effectively a "remake" of a subset of JWE.  Why a remake?           //
// Because the encryption system (naturally) borrows heavily from JCS         //
// including using the normalization scheme.                                  //
//                                                                            //
// The supported algorithms are though JOSE compatible including their names. //
////////////////////////////////////////////////////////////////////////////////

/**
 * Holds parsed JEF (JSON Encryption Format) data.
 */
public class JSONDecryptionDecoder {

    /**
     * Decodes and hold all global data and options.
     */
    static class Holder {

        JSONCryptoDecoder.Options options;

        DataEncryptionAlgorithms dataEncryptionAlgorithm;

        byte[] authenticatedData;
        byte[] iv;
        byte[] tag;
        byte[] encryptedData;
        
        KeyEncryptionAlgorithms globalKeyEncryptionAlgorithm;
        String globalKeyId;

        Holder (JSONCryptoDecoder.Options options, 
                JSONObjectReader encryptionObject,
                boolean multiple) throws IOException {
            encryptionObject.clearReadFlags();
            this.options = options;
            if (multiple) {
                /////////////////////////////////////////////////////////////////////////////
                // For encryption objects with multiple recipients we allow global
                // "alg" and "kid".  Note: mixing local and global is not permitted
                /////////////////////////////////////////////////////////////////////////////
                if (encryptionObject.hasProperty(JSONCryptoDecoder.ALG_JSON)) {
                    globalKeyEncryptionAlgorithm = getOptionalAlgorithm(encryptionObject);
                }
                globalKeyId = encryptionObject.getStringConditional(JSONCryptoDecoder.KID_JSON);
            }

            ///////////////////////////////////////////////////////////////////////////////////////
            // Begin JEF normalization                                                           //
            //                                                                                   //
            // 1. Make a shallow copy of the encryption object property list                     //
            LinkedHashMap<String, JSONValue> savedProperties =                                   //
                    new LinkedHashMap<String, JSONValue>(encryptionObject.root.properties);      //
            //                                                                                   //
            // 2. Hide these properties from the serializer..                                    //
            encryptionObject.root.properties.remove(JSONCryptoDecoder.TAG_JSON);                 //
            encryptionObject.root.properties.remove(JSONCryptoDecoder.CIPHER_TEXT_JSON);         //
            //                                                                                   //
            // 3. Serialize ("JSON.stringify()")                                                 //
            authenticatedData = encryptionObject.serializeToBytes(JSONOutputFormats.NORMALIZED); //
            //                                                                                   //
            // 4. Restore encryption object property list                                        //
            encryptionObject.root.properties = savedProperties;                                  //
            //                                                                                   //
            // End JEF normalization                                                             //
            ///////////////////////////////////////////////////////////////////////////////////////

            // Collect mandatory elements
            dataEncryptionAlgorithm = DataEncryptionAlgorithms
                    .getAlgorithmFromId(encryptionObject.getString(JSONCryptoDecoder.ENC_JSON));
            iv = encryptionObject.getBinary(JSONCryptoDecoder.IV_JSON);
            tag = encryptionObject.getBinary(JSONCryptoDecoder.TAG_JSON);
            encryptedData = encryptionObject.getBinary(JSONCryptoDecoder.CIPHER_TEXT_JSON);
        }
    }

    LinkedHashMap<String,JSONCryptoDecoder.Extension> extensions = new LinkedHashMap<String,JSONCryptoDecoder.Extension>();

    private PublicKey publicKey;

    private ECPublicKey ephemeralPublicKey;  // For ECHD only

    private String keyId;

    private KeyEncryptionAlgorithms keyEncryptionAlgorithm;

    private byte[] encryptedKeyData;  // For RSA and ECDH+ only

    private boolean sharedSecretMode;

    private Holder holder;

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public boolean isSharedSecret() {
        return sharedSecretMode;
    }

    public JSONDecryptionDecoder require(boolean publicKeyEncryption) throws IOException {
        if (publicKeyEncryption == sharedSecretMode) {
            throw new IOException((publicKeyEncryption ? "Missing" : "Unexpected") + " public key");
        }
        return this;
    }

    public String getKeyId() {
        return keyId;
    }

    public DataEncryptionAlgorithms getDataEncryptionAlgorithm() {
        return holder.dataEncryptionAlgorithm;
    }

    public KeyEncryptionAlgorithms getKeyEncryptionAlgorithm() {
        return keyEncryptionAlgorithm;
    }

    private static KeyEncryptionAlgorithms getOptionalAlgorithm(JSONObjectReader reader) throws IOException {
        return reader.hasProperty(JSONCryptoDecoder.ALG_JSON) ? 
            KeyEncryptionAlgorithms.getAlgorithmFromId(reader.getString(JSONCryptoDecoder.ALG_JSON)) : null;
    }

    /**
     * Decodes a single encryption element.
     * @param holder
     * @param encryptionObject
     * @param last
     * @throws IOException
     */
    JSONDecryptionDecoder(Holder holder, 
                          JSONObjectReader encryptionObject,
                          boolean last) throws IOException {
        this.holder = holder;

        keyId = holder.options.getKeyId(encryptionObject);
        if (holder.globalKeyId != null && keyId != null) {
            throw new IOException("Mixing global/local \"" + JSONCryptoDecoder.KID_JSON + "\" not allowed");
        }

        keyEncryptionAlgorithm = getOptionalAlgorithm(encryptionObject);
        if (keyEncryptionAlgorithm == null) {
            keyEncryptionAlgorithm = holder.globalKeyEncryptionAlgorithm;
        } else if (holder.globalKeyEncryptionAlgorithm != null) {
            throw new IOException("Mixing global/local \"" + JSONCryptoDecoder.ALG_JSON + "\" not allowed");
        }

        if (keyEncryptionAlgorithm == null) {
            sharedSecretMode = true;
        } else {
            if (encryptionObject.hasProperty(JSONCryptoDecoder.JWK_JSON)) {
                publicKey = encryptionObject.getPublicKey(holder.options.algorithmPreferences);
            }
            if (keyEncryptionAlgorithm.isKeyWrap()) {
                encryptedKeyData = encryptionObject.getBinary(JSONCryptoDecoder.ENCRYPTED_KEY_JSON);
            }
            if (!keyEncryptionAlgorithm.isRsa()) {
                ephemeralPublicKey =
                        (ECPublicKey) encryptionObject
                            .getObject(JSONCryptoDecoder.EPK_JSON)
                                .getCorePublicKey(holder.options.algorithmPreferences);
            }
        }

        holder.options.getExtensions(encryptionObject, extensions);

        if (last) {
            encryptionObject.checkForUnread();
        }
    }

    private byte[] localDecrypt(byte[] dataDecryptionKey) throws IOException, GeneralSecurityException {
        return EncryptionCore.contentDecryption(holder.dataEncryptionAlgorithm,
                                                dataDecryptionKey,
                                                holder.encryptedData,
                                                holder.iv,
                                                holder.authenticatedData,
                                                holder.tag);
    }

    public byte[] getDecryptedData(byte[] dataDecryptionKey) throws IOException, GeneralSecurityException {
        require(false);
        return localDecrypt(dataDecryptionKey);
    }

    public byte[] getDecryptedData(PrivateKey privateKey) throws IOException, GeneralSecurityException {
        require(true);
        return localDecrypt(keyEncryptionAlgorithm.isRsa() ?
                EncryptionCore.rsaDecryptKey(keyEncryptionAlgorithm,
                                             encryptedKeyData,
                                             privateKey)
                                                           :
                EncryptionCore.receiverKeyAgreement(keyEncryptionAlgorithm,
                                                    holder.dataEncryptionAlgorithm,
                                                    ephemeralPublicKey,
                                                    privateKey,
                                                    encryptedKeyData));
    }

    public byte[] getDecryptedData(Vector<DecryptionKeyHolder> decryptionKeys)
    throws IOException, GeneralSecurityException {
        boolean notFound = true;
        for (DecryptionKeyHolder decryptionKey : decryptionKeys) {
            if ((decryptionKey.getKeyId() != null && decryptionKey.getKeyId().equals(keyId)) || 
                decryptionKey.getPublicKey().equals(publicKey)) {
                notFound = false;
                if (decryptionKey.getKeyEncryptionAlgorithm().equals(keyEncryptionAlgorithm)) {
                    return getDecryptedData(decryptionKey.getPrivateKey());
                }
            }
        }
        throw new IOException(notFound ? "No matching key found" : "No matching key+algorithm found");
    }
}
