/*
 *  Copyright 2006-2016 WebPKI.org (http://webpki.org).
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
package org.webpki.json;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.Vector;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.json.encryption.DataEncryptionAlgorithms;
import org.webpki.json.encryption.DecryptionKeyHolder;
import org.webpki.json.encryption.EncryptionCore;
import org.webpki.json.encryption.KeyEncryptionAlgorithms;


////////////////////////////////////////////////////////////////////////////////
// JEF is effectively a "remake" of a subset of JWE.  Why a remake?           //
// Because the encryption system (naturally) borrows heavily from JCS         //
// including public key structures and property naming conventions.           //
//                                                                            //
// The supported algorithms are though JOSE compatible including their names. //
////////////////////////////////////////////////////////////////////////////////

/**
 * Holds parsed JEF (JSON Encryption Format) data.
 */
public class JSONDecryptionDecoder {

    public static final String ENCRYPTION_VERSION_ID      = "http://xmlns.webpki.org/jef/v1";

    public static final String ENCRYPTED_KEY_JSON         = "encryptedKey";
    public static final String EPHEMERAL_KEY_JSON         = "ephemeralKey";
    public static final String IV_JSON                    = "iv";
    public static final String TAG_JSON                   = "tag";
    public static final String CIPHER_TEXT_JSON           = "cipherText";

    private PublicKey publicKey;

    private ECPublicKey ephemeralPublicKey;  // For ECHD only

    private DataEncryptionAlgorithms dataEncryptionAlgorithm;

    private byte[] iv;

    private byte[] tag;
    
    private String keyId;

    private KeyEncryptionAlgorithms keyEncryptionAlgorithm;

    private byte[] encryptedKeyData;  // For RSA only

    private byte[] encryptedData;
    
    private byte[] authenticatedData;  // This implementation uses "encryptedKey" which is similar to JWE's protected header
    
    private JSONObjectReader checkVersion(JSONObjectReader rd) throws IOException {
       rd.clearReadFlags();
       String version = rd.getStringConditional(JSONSignatureDecoder.VERSION_JSON, ENCRYPTION_VERSION_ID);
        if (!version.equals(ENCRYPTION_VERSION_ID)) {
            throw new IOException("Unknown encryption version: " + version);
        }
        return rd;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public boolean isSharedSecret() {
        return publicKey == null;
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

    JSONDecryptionDecoder(JSONObjectReader encryptionObject) throws IOException {
        JSONObjectReader rd = checkVersion(encryptionObject);
        dataEncryptionAlgorithm = DataEncryptionAlgorithms
            .getAlgorithmFromString(rd.getString(JSONSignatureDecoder.ALGORITHM_JSON));
        iv = rd.getBinary(IV_JSON);
        tag = rd.getBinary(TAG_JSON);
        if (rd.hasProperty(ENCRYPTED_KEY_JSON)) {
            JSONObjectReader encryptedKey = checkVersion(rd.getObject(ENCRYPTED_KEY_JSON));
            authenticatedData = encryptedKey.serializeJSONObject(JSONOutputFormats.NORMALIZED);
            keyEncryptionAlgorithm = KeyEncryptionAlgorithms
                    .getAlgorithmFromString(encryptedKey.getString(JSONSignatureDecoder.ALGORITHM_JSON));
            publicKey = encryptedKey.getPublicKey(AlgorithmPreferences.JOSE);
            if (keyEncryptionAlgorithm.isRsa()) {
                encryptedKeyData = encryptedKey.getBinary(CIPHER_TEXT_JSON);
            } else {
                ephemeralPublicKey = 
                    (ECPublicKey) encryptedKey.getObject(EPHEMERAL_KEY_JSON).getCorePublicKey(AlgorithmPreferences.JOSE);
            }
        } else {
            keyId = rd.getStringConditional(JSONSignatureDecoder.KEY_ID_JSON);
            authenticatedData = dataEncryptionAlgorithm.toString().getBytes("UTF-8");
        }
        encryptedData = rd.getBinary(CIPHER_TEXT_JSON);
        rd.checkForUnread();
    }

    public byte[] getDecryptedData(byte[] dataDecryptionKey) throws IOException, GeneralSecurityException {
        return EncryptionCore.contentDecryption(dataEncryptionAlgorithm,
                                                dataDecryptionKey,
                                                encryptedData,
                                                iv,
                                                authenticatedData,
                                                tag);
    }

    public byte[] getDecryptedData(Vector<DecryptionKeyHolder> decryptionKeys)
    throws IOException, GeneralSecurityException {
        boolean notFound = true;
        for (DecryptionKeyHolder decryptionKey : decryptionKeys) {
            if (decryptionKey.getPublicKey().equals(publicKey)) {
                notFound = false;
                if (decryptionKey.getKeyEncryptionAlgorithm().equals(keyEncryptionAlgorithm)) {
                    return getDecryptedData(keyEncryptionAlgorithm.isRsa() ?
                         EncryptionCore.rsaDecryptKey(keyEncryptionAlgorithm,
                                                      encryptedKeyData,
                                                      decryptionKey.getPrivateKey())
                                             :
                         EncryptionCore.receiverKeyAgreement(keyEncryptionAlgorithm,
                                                             dataEncryptionAlgorithm,
                                                             ephemeralPublicKey,
                                                             decryptionKey.getPrivateKey()));
                }
            }
        }
        throw new IOException(notFound ? "No matching key found" : "No matching key+algorithm found");
    }
}
