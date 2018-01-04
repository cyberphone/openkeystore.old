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
import java.util.LinkedHashSet;
import java.util.Vector;

import org.webpki.crypto.AlgorithmPreferences;

////////////////////////////////////////////////////////////////////////////////
// JEF is effectively a "remake" of a subset of JWE.  Why a remake?           //
// Because the encryption system (naturally) borrows heavily from JCS         //
// including using the same normalization scheme.                             //
//                                                                            //
// The supported algorithms are though JOSE compatible including their names. //
////////////////////////////////////////////////////////////////////////////////

/**
 * Holds parsed JEF (JSON Encryption Format) data.
 */
public class JSONDecryptionDecoder {

    public static final String ENCRYPTED_KEY_JSON    = "encrypted_key";
    public static final String EPK_JSON              = "epk";
    public static final String ENC_JSON              = "enc";
    public static final String AAD_JSON              = "aad";
    public static final String IV_JSON               = "iv";
    public static final String TAG_JSON              = "tag";
    public static final String CIPHER_TEXT_JSON      = "ciphertext";
    public static final String RECIPIENTS_JSON       = "recipients";

    static final LinkedHashSet<String> reservedWords = new LinkedHashSet<String>();
    
    static {
        reservedWords.add(JSONSignatureDecoder.ALG_JSON);
        reservedWords.add(ENC_JSON);
        reservedWords.add(IV_JSON);
        reservedWords.add(TAG_JSON);
        reservedWords.add(AAD_JSON);
        reservedWords.add(ENCRYPTED_KEY_JSON);
        reservedWords.add(EPK_JSON);
        reservedWords.add(CIPHER_TEXT_JSON);
        reservedWords.add(RECIPIENTS_JSON);
        reservedWords.add(JSONSignatureDecoder.CRIT_JSON);
        reservedWords.add(JSONSignatureDecoder.KID_JSON);
        reservedWords.add(JSONSignatureDecoder.JWK_JSON);
        reservedWords.add(JSONSignatureDecoder.JKU_JSON);
        reservedWords.add(JSONSignatureDecoder.X5C_JSON);
        reservedWords.add(JSONSignatureDecoder.X5T_JSON);
        reservedWords.add(JSONSignatureDecoder.X5T_S256_JSON);
        reservedWords.add(JSONSignatureDecoder.X5U_JSON);
    }

    public static class Options {
        
    }

    private PublicKey publicKey;

    private ECPublicKey ephemeralPublicKey;  // For ECHD only

    private DataEncryptionAlgorithms dataEncryptionAlgorithm;

    private byte[] iv;

    private byte[] tag;

    private String keyId;

    private KeyEncryptionAlgorithms keyEncryptionAlgorithm;

    private byte[] encryptedKeyData;  // For RSA and ECDH+ only

    private byte[] encryptedData;
    
    private boolean sharedSecretMode;

    private byte[] authenticatedData;  // This implementation uses "encryptedKey" which is similar to JWE's protected header

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
        return dataEncryptionAlgorithm;
    }

    public KeyEncryptionAlgorithms getKeyEncryptionAlgorithm() {
        return keyEncryptionAlgorithm;
    }

    private static KeyEncryptionAlgorithms getOptionalAlgorithm(JSONObjectReader reader) throws IOException {
        return reader.hasProperty(JSONSignatureDecoder.ALG_JSON) ? 
            KeyEncryptionAlgorithms.getAlgorithmFromId(reader.getString(JSONSignatureDecoder.ALG_JSON)) : null;
    }

    JSONDecryptionDecoder(JSONObjectReader encryptionObject) throws IOException {
        encryptionObject.clearReadFlags();
        ///////////////////////////////////////////////////////////////////////////////////////
        // Begin JEF normalization                                                           //
        //                                                                                   //
        // 1. Make a shallow copy of the encryption object property list                     //
        LinkedHashMap<String, JSONValue> savedProperties =                                   //
                new LinkedHashMap<String, JSONValue>(encryptionObject.root.properties);      //
        //                                                                                   //
        // 2. Hide these properties from the serializer..                                    //
        encryptionObject.root.properties.remove(TAG_JSON);                                   //
        encryptionObject.root.properties.remove(CIPHER_TEXT_JSON);                           //
        //                                                                                   //
        // 3. Serialize ("JSON.stringify()")                                                 //
        authenticatedData = encryptionObject.serializeToBytes(JSONOutputFormats.NORMALIZED); //
        //                                                                                   //
        // 4. Restore encryption object property list                                        //
        encryptionObject.root.properties = savedProperties;                                  //
        //                                                                                   //
        // End JEF normalization                                                             //
        ///////////////////////////////////////////////////////////////////////////////////////
        dataEncryptionAlgorithm = DataEncryptionAlgorithms
                .getAlgorithmFromId(encryptionObject.getString(ENC_JSON));
        iv = encryptionObject.getBinary(IV_JSON);
        tag = encryptionObject.getBinary(TAG_JSON);
        keyId = encryptionObject.getStringConditional(JSONSignatureDecoder.KID_JSON);
        keyEncryptionAlgorithm = getOptionalAlgorithm(encryptionObject);
        if (encryptionObject.hasProperty(JSONDecryptionDecoder.RECIPIENTS_JSON)) {
            JSONArrayReader recepients = encryptionObject.getArray(RECIPIENTS_JSON);
            do {
                
            } while (recepients.hasMore());
        }
        else if (keyEncryptionAlgorithm != null) {
            if (encryptionObject.hasProperty(JSONSignatureDecoder.JWK_JSON)) {
                publicKey = encryptionObject.getPublicKey(AlgorithmPreferences.JOSE);
            }
            if (keyEncryptionAlgorithm.isKeyWrap()) {
                encryptedKeyData = encryptionObject.getBinary(ENCRYPTED_KEY_JSON);
            }
            if (!keyEncryptionAlgorithm.isRsa()) {
                ephemeralPublicKey =
                        (ECPublicKey) encryptionObject.getObject(EPK_JSON).getCorePublicKey(AlgorithmPreferences.JOSE);
            }
        } else {
            sharedSecretMode = true;
        }
        encryptedData = encryptionObject.getBinary(CIPHER_TEXT_JSON);
        encryptionObject.checkForUnread();
    }

    private byte[] localDecrypt(byte[] dataDecryptionKey) throws IOException, GeneralSecurityException {
        return EncryptionCore.contentDecryption(dataEncryptionAlgorithm,
                                                dataDecryptionKey,
                                                encryptedData,
                                                iv,
                                                authenticatedData,
                                                tag);
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
                                                    dataEncryptionAlgorithm,
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

    static void checkExtensions(String[] properties) throws IOException {
        if (properties.length == 0) {
            throw new IOException("Empty \"" + JSONSignatureDecoder.CRIT_JSON + "\" array not allowed");
        }
        for (String property : properties) {
            if (reservedWords.contains(property)) {
                throw new IOException("Forbidden \"" + JSONSignatureDecoder.CRIT_JSON + "\" property: " + property);
            }
        }
    }
}
