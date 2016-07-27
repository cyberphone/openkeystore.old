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
package org.webpki.json.encryption;

import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import java.security.interfaces.ECPublicKey;

import java.security.spec.ECGenParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.webpki.crypto.KeyAlgorithms;

import org.webpki.util.ArrayUtil;

// Core encryption class

public final class EncryptionCore {
    
    private EncryptionCore() {} // Static and final class

    private static byte[] getTag(byte[] key,
                                 byte[] cipherText,
                                 byte[] iv,
                                 byte[] authenticatedData) throws GeneralSecurityException {
        byte[] al = new byte[8];
        int value = authenticatedData.length * 8;
        for (int q = 24, i = 4; q >= 0; q -= 8, i++) {
            al[i] = (byte)(value >>> q);
        }
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init (new SecretKeySpec (key, 0, 16, "RAW"));
        mac.update(authenticatedData);
        mac.update(iv);
        mac.update(cipherText);
        mac.update(al);
        byte[] tag = new byte[16];
        System.arraycopy(mac.doFinal(), 0, tag, 0, 16);
        return tag;
    }

    private static byte[] aesCore(int mode, byte[] key, byte[] iv, byte[] data, DataEncryptionAlgorithms dataEncryptionAlgorithm)
    throws GeneralSecurityException {
        if (!permittedDataEncryptionAlgorithm(dataEncryptionAlgorithm)) {
            throw new GeneralSecurityException("Unsupported AES algorithm: " + dataEncryptionAlgorithm);
        }
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(mode, new SecretKeySpec(key, 16, 16, "AES"), new IvParameterSpec(iv));
        return cipher.doFinal(data);
    }

    private static byte[] rsaCore(int mode, Key key, byte[] data, KeyEncryptionAlgorithms keyEncryptionAlgorithm)
    throws GeneralSecurityException {
        if (keyEncryptionAlgorithm != KeyEncryptionAlgorithms.JOSE_RSA_OAEP_256_ALG_ID) {
            throw new GeneralSecurityException("Unsupported RSA algorithm: " + keyEncryptionAlgorithm);
        }
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA256AndMGF1Padding");
        cipher.init(mode, key);
        return cipher.doFinal(data);
    }

    public static class AuthEncResult {
        private byte[] iv;
        byte[] tag;
        byte[] cipherText;
        
        private AuthEncResult(byte[] iv, byte[] tag, byte[] cipherText) {
            this.iv = iv;
            this.tag = tag;
            this.cipherText = cipherText;
        }
        
        public byte[] getTag() {
            return tag;
        }

        public byte[] getIv() {
            return iv;
        }

        public byte[] getCipherText() {
            return cipherText;
        }
    }

    public static class EcdhSenderResult {
        private byte[] sharedSecret;
        private ECPublicKey ephemeralKey;
        
        private EcdhSenderResult(byte[] sharedSecret, ECPublicKey ephemeralKey) {
            this.sharedSecret = sharedSecret;
            this.ephemeralKey = ephemeralKey;
        }

        public byte[] getSharedSecret() {
            return sharedSecret;
        }

        public ECPublicKey getEphemeralKey() {
            return ephemeralKey;
        }
    }
    
    public static AuthEncResult contentEncryption(DataEncryptionAlgorithms dataEncryptionAlgorithm,
                                                  byte[] key,
                                                  byte[] plainText,
                                                  byte[] authenticatedData) throws GeneralSecurityException {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes (iv);
        byte[] cipherText = aesCore(Cipher.ENCRYPT_MODE, key, iv, plainText, dataEncryptionAlgorithm);
        return new AuthEncResult(iv, getTag(key, cipherText, iv, authenticatedData), cipherText);
    }

    public static byte[] generateDataEncryptionKey(DataEncryptionAlgorithms dataEncryptionAlgorithm) {
        byte[] dataEncryptionKey = new byte[dataEncryptionAlgorithm.getKeyLength()];
        new SecureRandom().nextBytes (dataEncryptionKey);
        return dataEncryptionKey;
    }

    public static byte[] contentDecryption(DataEncryptionAlgorithms dataEncryptionAlgorithm,
                                           byte[] key,
                                           byte[] cipherText,
                                           byte[] iv,
                                           byte[] authenticatedData,
                                           byte[] tag) throws GeneralSecurityException {
        if (!ArrayUtil.compare(tag, getTag(key, cipherText, iv, authenticatedData))) {
            throw new GeneralSecurityException("Authentication error on algorithm: " + dataEncryptionAlgorithm);
        }
        return aesCore(Cipher.DECRYPT_MODE, key, iv, cipherText, dataEncryptionAlgorithm);
     }

    public static byte[] rsaEncryptKey(KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                                       byte[] rawKey,
                                       PublicKey publicKey) throws GeneralSecurityException {
        return rsaCore(Cipher.ENCRYPT_MODE, publicKey, rawKey, keyEncryptionAlgorithm);
    }

    public static byte[] rsaDecryptKey(KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                                       byte[] encryptedKey,
                                       PrivateKey privateKey) throws GeneralSecurityException {
        return rsaCore(Cipher.DECRYPT_MODE, privateKey, encryptedKey, keyEncryptionAlgorithm);
    }

    private static void addInt4(MessageDigest messageDigest, int value) {
        for (int i = 24; i >= 0; i -= 8) {
            messageDigest.update((byte)(value >>> i));
        }
    }

    public static byte[] receiverKeyAgreement(KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                                              DataEncryptionAlgorithms dataEncryptionAlgorithm,
                                              ECPublicKey receivedPublicKey,
                                              PrivateKey privateKey) throws GeneralSecurityException, IOException {
        if (keyEncryptionAlgorithm != KeyEncryptionAlgorithms.JOSE_ECDH_ES_ALG_ID) {
            throw new GeneralSecurityException("Unsupported ECDH algorithm: " + keyEncryptionAlgorithm);
        }
        if (dataEncryptionAlgorithm != DataEncryptionAlgorithms.JOSE_A128CBC_HS256_ALG_ID) {
            throw new GeneralSecurityException("Unsupported data encryption algorithm: " + dataEncryptionAlgorithm);
        }
        byte[] algorithmId = dataEncryptionAlgorithm.toString().getBytes("UTF-8");
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(receivedPublicKey, true);
        // NIST Concat KDF
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        // Round 1 indicator
        addInt4(messageDigest, 1);
        // Z
        messageDigest.update(keyAgreement.generateSecret());
        // AlgorithmID = Content encryption algorithm
        addInt4(messageDigest, algorithmId.length);
        messageDigest.update(algorithmId);
        // PartyUInfo = Empty
        addInt4(messageDigest, 0);
        // PartyVInfo = Empty
        addInt4(messageDigest, 0);
        // SuppPubInfo = Key length in bits
        addInt4(messageDigest, 256);
        return messageDigest.digest();
    }

    public static EcdhSenderResult senderKeyAgreement(KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                                                      DataEncryptionAlgorithms dataEncryptionAlgorithm,
                                                      PublicKey staticKey) throws GeneralSecurityException, IOException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec eccgen = new ECGenParameterSpec(KeyAlgorithms.getKeyAlgorithm(staticKey).getJCEName());
        generator.initialize (eccgen, new SecureRandom());
        KeyPair keyPair = generator.generateKeyPair();
        return new EcdhSenderResult(receiverKeyAgreement(keyEncryptionAlgorithm,
                                                         dataEncryptionAlgorithm,
                                                         (ECPublicKey)staticKey,
                                                         keyPair.getPrivate()),
                                    (ECPublicKey) keyPair.getPublic());
    }

    public static boolean permittedKeyEncryptionAlgorithm(KeyEncryptionAlgorithms algorithm) {
        return algorithm == KeyEncryptionAlgorithms.JOSE_ECDH_ES_ALG_ID ||
               algorithm == KeyEncryptionAlgorithms.JOSE_RSA_OAEP_256_ALG_ID;
    }

    public static boolean permittedDataEncryptionAlgorithm(DataEncryptionAlgorithms algorithm) {
        return algorithm == DataEncryptionAlgorithms.JOSE_A128CBC_HS256_ALG_ID;
    }
}
