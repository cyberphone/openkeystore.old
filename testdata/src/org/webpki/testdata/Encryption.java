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
package org.webpki.testdata;

import java.io.File;
import java.io.IOException;

import java.security.KeyPair;

import java.security.cert.X509Certificate;

import java.security.interfaces.ECPublicKey;

import java.util.Vector;

import org.webpki.crypto.CustomCryptoProvider;

//Std
import org.webpki.json.JSONArrayReader;
import org.webpki.json.JSONAsymKeyEncrypter;
import org.webpki.json.JSONRemoteKeys;
import org.webpki.json.JSONX509Encrypter;
import org.webpki.json.JSONCryptoHelper;
import org.webpki.json.JSONDecryptionDecoder;
import org.webpki.json.JSONEncrypter;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;
import org.webpki.json.ContentEncryptionAlgorithms;
import org.webpki.json.JSONSymKeyEncrypter;
import org.webpki.json.KeyEncryptionAlgorithms;
// Test
import org.webpki.json.WebKey;
import org.webpki.json.SymmetricKeys;
import org.webpki.json.Extension1;
import org.webpki.json.Extension2;

import org.webpki.util.ArrayUtil;

/*
 * Create Cleartext JWE/JEF test vectors
 */
public class Encryption {
    static String baseKey;
    static String baseEncryption;
    static String baseData;
    static SymmetricKeys symmetricKeys;
    static String keyId;
    static byte[] dataToBeEncrypted;
    static boolean joseMode;
    
    public interface LocalDecrypt {
        public byte[] decrypt(JSONObjectReader reader) throws Exception;
    }

    static void cleanInner(JSONObjectReader inner) throws Exception {
        if (inner.hasProperty(JSONCryptoHelper.ENCRYPTED_KEY_JSON)) {
            inner.removeProperty(JSONCryptoHelper.ENCRYPTED_KEY_JSON);
        }
        if (inner.hasProperty(JSONCryptoHelper.EPK_JSON)) {
            inner.removeProperty(JSONCryptoHelper.EPK_JSON);
        }
     }

    static String cleanEncryption(JSONObjectReader encryptedData) throws Exception {
        encryptedData.removeProperty(JSONCryptoHelper.IV_JSON);
        encryptedData.removeProperty(JSONCryptoHelper.TAG_JSON);
        encryptedData.removeProperty(JSONCryptoHelper.CIPHER_TEXT_JSON);
        if (encryptedData.hasProperty(JSONCryptoHelper.RECIPIENTS_JSON)) {
            JSONArrayReader recipients = encryptedData.getArray(JSONCryptoHelper.RECIPIENTS_JSON);
            do {
                cleanInner(recipients.getObject());
            } while (recipients.hasMore());
        } else {
            cleanInner(encryptedData);
        }
        return encryptedData.toString();
    }

    static void optionalUpdate(String baseName, byte[] encryptedData, LocalDecrypt decrypter) throws Exception {
        String fileName = baseEncryption + baseName;
        JSONObjectReader newEncryptedData = JSONParser.parse(encryptedData);
        if (!ArrayUtil.compare(decrypter.decrypt(newEncryptedData), dataToBeEncrypted)) {
            throw new IOException("Decrypt err:" + baseName);
        }
        boolean changed = true;
        try {
            JSONObjectReader oldEncryptedData = JSONParser.parse(ArrayUtil.readFile(fileName));
            try {
                if (ArrayUtil.compare(decrypter.decrypt(oldEncryptedData), dataToBeEncrypted)) {
                    // All good but are the new and old effectively the same?
                    if (cleanEncryption(newEncryptedData).equals(cleanEncryption(oldEncryptedData))) {
                        return;  // Yes, don't rewrite.
                    }
                }
            } catch (Exception e) {}
        } catch (Exception  e) {
            changed = false;  // New I guess
        }
        if (changed) {
            System.out.println("UPDATED: " + baseName);
        }
        ArrayUtil.writeFile(fileName, encryptedData);
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 4) {
            throw new Exception("Wrong number of arguments");
        }
        CustomCryptoProvider.forcedLoad(true);
        baseKey = args[0] + File.separator;
        baseData = args[1] + File.separator;
        baseEncryption = args[2] + File.separator;
        joseMode = Boolean.valueOf(args[3]);
        symmetricKeys = new SymmetricKeys(baseKey);
        dataToBeEncrypted = ArrayUtil.readFile(baseData + "datatobeencrypted.txt");
        
        boolean next = false;
        StringBuilder numerics = new StringBuilder(new String(dataToBeEncrypted, "utf-8"));
        numerics.append('\n');
        int byteCount = 0;
        for (byte b : dataToBeEncrypted) {
            if (next) {
                numerics.append(", ");
            }
            next = true;
            while (++byteCount % 10 == 0) {
                numerics.append('\n');
            }
            numerics.append(b & 0xff);
        }
        System.out.println(numerics);


        asymEnc("p256", ContentEncryptionAlgorithms.JOSE_A128CBC_HS256_ALG_ID, false);
        asymEnc("p256", ContentEncryptionAlgorithms.JOSE_A256CBC_HS512_ALG_ID, false);
        asymEnc("p384", ContentEncryptionAlgorithms.JOSE_A256CBC_HS512_ALG_ID, false);
        asymEnc("p384", ContentEncryptionAlgorithms.JOSE_A128CBC_HS256_ALG_ID, false);
        asymEnc("p521", ContentEncryptionAlgorithms.JOSE_A128GCM_ALG_ID, false);
        asymEnc("p521", ContentEncryptionAlgorithms.JOSE_A128CBC_HS256_ALG_ID, false);
        asymEnc("r2048", ContentEncryptionAlgorithms.JOSE_A256GCM_ALG_ID, false);
        asymEnc("p256", ContentEncryptionAlgorithms.JOSE_A128CBC_HS256_ALG_ID, true);
        asymEnc("r2048", ContentEncryptionAlgorithms.JOSE_A256GCM_ALG_ID, true);

        asymEncNoPublicKeyInfo("p256", ContentEncryptionAlgorithms.JOSE_A128CBC_HS256_ALG_ID, true);
        asymEncNoPublicKeyInfo("p256", ContentEncryptionAlgorithms.JOSE_A128GCM_ALG_ID, true);
        asymEncNoPublicKeyInfo("r2048", ContentEncryptionAlgorithms.JOSE_A256GCM_ALG_ID, true);
        asymEncNoPublicKeyInfo("r2048", ContentEncryptionAlgorithms.JOSE_A128GCM_ALG_ID, true);
        asymEncNoPublicKeyInfo("p256", ContentEncryptionAlgorithms.JOSE_A128GCM_ALG_ID, false);
        asymEncNoPublicKeyInfo("r2048", ContentEncryptionAlgorithms.JOSE_A256GCM_ALG_ID, false);
        
        certEnc("p256", ContentEncryptionAlgorithms.JOSE_A128CBC_HS256_ALG_ID, false);
        certEnc("r2048", ContentEncryptionAlgorithms.JOSE_A256GCM_ALG_ID, false);
        certEnc("p256", ContentEncryptionAlgorithms.JOSE_A128CBC_HS256_ALG_ID, true);
        certEnc("r2048", ContentEncryptionAlgorithms.JOSE_A128CBC_HS256_ALG_ID, true);
        
        multipleAsymEnc(new String[]{"p256", "p384"}, 
                         ContentEncryptionAlgorithms.JOSE_A128CBC_HS256_ALG_ID, 
                        true);
      
        multipleAsymEnc(new String[]{"p256", "p384"}, 
                        ContentEncryptionAlgorithms.JOSE_A128CBC_HS256_ALG_ID, 
                        false);

        multipleAsymEnc(new String[]{"p256", "p384"}, 
                        ContentEncryptionAlgorithms.JOSE_A256CBC_HS512_ALG_ID, 
                        false);

        multipleAsymEnc(new String[]{"p256", "r2048"}, 
                        ContentEncryptionAlgorithms.JOSE_A128CBC_HS256_ALG_ID, 
                        true);

        multipleAsymEnc(new String[]{"p256", "p256"}, 
                        ContentEncryptionAlgorithms.JOSE_A128CBC_HS256_ALG_ID, 
                        true);

        symmEnc(256, ContentEncryptionAlgorithms.JOSE_A128CBC_HS256_ALG_ID);
        symmEnc(512, ContentEncryptionAlgorithms.JOSE_A256CBC_HS512_ALG_ID);
        symmEnc(128, ContentEncryptionAlgorithms.JOSE_A128GCM_ALG_ID);
        symmEnc(256, ContentEncryptionAlgorithms.JOSE_A256GCM_ALG_ID);

        coreSymmEnc(256, "imp.json", ContentEncryptionAlgorithms.JOSE_A256GCM_ALG_ID, false);
        
        coreAsymEnc("p256", 
                    "crit-jwk.json",
                    ContentEncryptionAlgorithms.JOSE_A256GCM_ALG_ID,
                    false,
                    true,
                    new JSONCryptoHelper.ExtensionHolder()
                        .addExtension(Extension1.class, true)
                        .addExtension(Extension2.class, true),
                    new JSONObjectWriter()
                        .setString(new Extension1().getExtensionUri(), "something")
                        .setObject(new Extension2().getExtensionUri(), 
                            new JSONObjectWriter().setBoolean("life-is-great", true)),
                    false);
    }

    static X509Certificate[] getCertificatePath(String keyType) throws IOException {
        return JSONParser.parse(ArrayUtil.readFile(baseKey + keyType + "certificate.x5c"))
                    .getJSONArrayReader().getCertificatePath();
    }

    static void certEnc(String keyType, 
                        ContentEncryptionAlgorithms contentEncryptionAlgorithm,
                        boolean remote) throws Exception {
        KeyPair keyPair = readJwk(keyType);
        KeyEncryptionAlgorithms keyEncryptionAlgorithm = KeyEncryptionAlgorithms.JOSE_RSA_OAEP_256_ALG_ID;
        if (keyPair.getPublic() instanceof ECPublicKey) {
            switch (contentEncryptionAlgorithm.getKeyLength()) {
            case 16: 
                keyEncryptionAlgorithm = KeyEncryptionAlgorithms.JOSE_ECDH_ES_A128KW_ALG_ID;
                break;
            case 32: 
                keyEncryptionAlgorithm = KeyEncryptionAlgorithms.JOSE_ECDH_ES_A256KW_ALG_ID;
                break;
            default: 
                keyEncryptionAlgorithm = KeyEncryptionAlgorithms.JOSE_ECDH_ES_ALG_ID;
                break;
            }
        }
        if (keyEncryptionAlgorithm == KeyEncryptionAlgorithms.JOSE_RSA_OAEP_256_ALG_ID &&
            contentEncryptionAlgorithm == ContentEncryptionAlgorithms.JOSE_A128GCM_ALG_ID) {
            keyEncryptionAlgorithm = KeyEncryptionAlgorithms.JOSE_RSA_OAEP_ALG_ID;
        }
        JSONX509Encrypter encrypter = new JSONX509Encrypter(getCertificatePath(keyType),
                                                            keyEncryptionAlgorithm);
        JSONCryptoHelper.Options options = new JSONCryptoHelper.Options();
        String fileSuffix = "x5c.json";
        if (remote) {
            fileSuffix = "x5u.json";
            encrypter.setRemoteKey(Signatures.REMOTE_PATH + keyType + "certpath.pem");
            options.setRemoteKeyReader(new WebKey(), JSONRemoteKeys.PEM_CERT_PATH);
        }
        byte[] encryptedData =
               JSONObjectWriter.createEncryptionObject(dataToBeEncrypted, 
                                                       contentEncryptionAlgorithm,
                                                       encrypter).serializeToBytes(JSONOutputFormats.PRETTY_PRINT);
        optionalUpdate(keyType + "#" + keyEncryptionAlgorithm.toString().toLowerCase() + 
                           "@" + contentEncryptionAlgorithm.toString().toLowerCase() + "@" + fileSuffix,
                       encryptedData,
                       new LocalDecrypt() {
        
                           @Override
                           public byte[] decrypt(JSONObjectReader reader) throws Exception {
                               return reader.getEncryptionObject(options).getDecryptedData(keyPair.getPrivate());
                           }
            
                       });
    }

    static void coreSymmEnc(int keyBits, String fileSuffix, ContentEncryptionAlgorithms contentEncryptionAlgorithm, boolean wantKeyId) throws Exception {
        byte[] key = symmetricKeys.getValue(keyBits);
        String keyName = symmetricKeys.getName(keyBits);
        JSONSymKeyEncrypter encrypter = new JSONSymKeyEncrypter(key);
        JSONCryptoHelper.Options options = new JSONCryptoHelper.Options();
        if (wantKeyId) {
            encrypter.setKeyId(keyName);
            options.setKeyIdOption(JSONCryptoHelper.KEY_ID_OPTIONS.REQUIRED);
        }
        byte[] encryptedData = 
                JSONObjectWriter.createEncryptionObject(dataToBeEncrypted, 
                                                        contentEncryptionAlgorithm,
                                                        encrypter).serializeToBytes(JSONOutputFormats.PRETTY_PRINT);
        optionalUpdate("a" + keyBits + "@" + contentEncryptionAlgorithm.toString().toLowerCase() + "@" + fileSuffix,
                       encryptedData,
                       new LocalDecrypt() {
         
                           @Override
                           public byte[] decrypt(JSONObjectReader reader) throws Exception {
                               return reader.getEncryptionObject(options).getDecryptedData(key);
                           }
             
                       });
    }

    static void symmEnc(int keyBits, ContentEncryptionAlgorithms contentEncryptionAlgorithm) throws Exception {
        coreSymmEnc(keyBits, "kid.json", contentEncryptionAlgorithm, true);
    }
    
    static KeyPair readJwk(String keyType) throws Exception {
        JSONObjectReader jwkPlus = JSONParser.parse(ArrayUtil.readFile(baseKey + keyType + "privatekey.jwk"));
        // Note: The built-in JWK decoder does not accept "kid" since it doesn't have a meaning in JCS or JEF. 
        if ((keyId = jwkPlus.getStringConditional("kid")) != null) {
            jwkPlus.removeProperty("kid");
        }
        return jwkPlus.getKeyPair();
    }

    static void coreAsymEnc(String keyType, 
                            String fileSuffix,
                            ContentEncryptionAlgorithms contentEncryptionAlgorithm,
                            boolean wantKeyId,
                            boolean wantPublicKey,
                            JSONCryptoHelper.ExtensionHolder extensionHolder,
                            JSONObjectWriter extensions,
                            boolean remote) throws Exception {
        KeyPair keyPair = readJwk(keyType);
        KeyEncryptionAlgorithms keyEncryptionAlgorithm = KeyEncryptionAlgorithms.JOSE_RSA_OAEP_256_ALG_ID;
        if (keyPair.getPublic() instanceof ECPublicKey) {
            switch (contentEncryptionAlgorithm.getKeyLength()) {
            case 16: 
                keyEncryptionAlgorithm = KeyEncryptionAlgorithms.JOSE_ECDH_ES_A128KW_ALG_ID;
                break;
            case 32: 
                keyEncryptionAlgorithm = KeyEncryptionAlgorithms.JOSE_ECDH_ES_A256KW_ALG_ID;
                break;
            default: 
                keyEncryptionAlgorithm = KeyEncryptionAlgorithms.JOSE_ECDH_ES_ALG_ID;
                break;
            }
        }
        if (keyEncryptionAlgorithm == KeyEncryptionAlgorithms.JOSE_RSA_OAEP_256_ALG_ID &&
            contentEncryptionAlgorithm == ContentEncryptionAlgorithms.JOSE_A128GCM_ALG_ID) {
            keyEncryptionAlgorithm = KeyEncryptionAlgorithms.JOSE_RSA_OAEP_ALG_ID;
        }
        JSONAsymKeyEncrypter encrypter = new JSONAsymKeyEncrypter(keyPair.getPublic(),
                                                                  keyEncryptionAlgorithm);
        JSONCryptoHelper.Options options = new JSONCryptoHelper.Options();
        if (extensionHolder != null) {
            options.setPermittedExtensions(extensionHolder);
            encrypter.setExtensions(extensions);
        }
        if (remote) {
            options.setRemoteKeyReader(new WebKey(), JSONRemoteKeys.JWK_KEY_SET);
            encrypter.setRemoteKey(Signatures.REMOTE_PATH + keyType + ".jwks");
        }
        encrypter.setOutputPublicKeyInfo(wantPublicKey);
        options.setRequirePublicKeyInfo(wantPublicKey);
        if (wantKeyId) {
            encrypter.setKeyId(keyId);
            options.setKeyIdOption(JSONCryptoHelper.KEY_ID_OPTIONS.REQUIRED);
        }
        byte[] encryptedData =
               JSONObjectWriter.createEncryptionObject(dataToBeEncrypted, 
                                                       contentEncryptionAlgorithm,
                                                       encrypter).serializeToBytes(JSONOutputFormats.PRETTY_PRINT);
        optionalUpdate(keyType + "#" +  keyEncryptionAlgorithm.toString().toLowerCase() + 
                           "@" + contentEncryptionAlgorithm.toString().toLowerCase() + "@" + fileSuffix,
                       encryptedData,
                       new LocalDecrypt() {
          
                           @Override
                           public byte[] decrypt(JSONObjectReader reader) throws Exception {
                               return reader.getEncryptionObject(options).getDecryptedData(keyPair.getPrivate());
                           }
              
                       });
     }

    static void asymEnc(String keyType, 
                        ContentEncryptionAlgorithms contentEncryptionAlgorithm,
                        boolean remote) throws Exception {
        coreAsymEnc(keyType,
                    remote ? "jku.json" : "jwk.json",
                    contentEncryptionAlgorithm,
                    false,
                    true,
                    null,
                    null,
                    remote);
    }

    static void asymEncNoPublicKeyInfo(String keyType,
                                       ContentEncryptionAlgorithms contentEncryptionAlgorithm,
                                       boolean wantKeyId) throws Exception {
        coreAsymEnc(keyType, 
                    wantKeyId ? "kid.json" : "imp.json",
                    contentEncryptionAlgorithm,
                    wantKeyId,
                    false,
                    null,
                    null,
                    false);
    }

    static void multipleAsymEnc(String[] keyTypes, 
                                ContentEncryptionAlgorithms contentEncryptionAlgorithm, 
                                boolean wantKeyId) throws Exception {
        Vector<JSONDecryptionDecoder.DecryptionKeyHolder> decryptionKeys =
                new Vector<JSONDecryptionDecoder.DecryptionKeyHolder>();
        Vector<JSONEncrypter> encrypters = new Vector<JSONEncrypter>();
        String algList = "";
        KeyEncryptionAlgorithms algCheck = null;
        boolean first = true;
        for (String keyType : keyTypes) {
            KeyPair keyPair = readJwk(keyType);
            KeyEncryptionAlgorithms keyEncryptionAlgorithm = KeyEncryptionAlgorithms.JOSE_RSA_OAEP_256_ALG_ID;
            if (keyPair.getPublic() instanceof ECPublicKey) {
                switch (contentEncryptionAlgorithm.getKeyLength()) {
                case 16: 
                    keyEncryptionAlgorithm = KeyEncryptionAlgorithms.JOSE_ECDH_ES_A128KW_ALG_ID;
                    break;
                default: 
                case 32: 
                    keyEncryptionAlgorithm = KeyEncryptionAlgorithms.JOSE_ECDH_ES_A256KW_ALG_ID;
                    break;
                }
            }
            if (keyEncryptionAlgorithm == KeyEncryptionAlgorithms.JOSE_RSA_OAEP_256_ALG_ID &&
                contentEncryptionAlgorithm == ContentEncryptionAlgorithms.JOSE_A128GCM_ALG_ID) {
                keyEncryptionAlgorithm = KeyEncryptionAlgorithms.JOSE_RSA_OAEP_ALG_ID;
            }
            if (first) {
                algCheck = keyEncryptionAlgorithm;
            } else {
                if (algCheck != keyEncryptionAlgorithm) {
                    algCheck = null;
                }
            }
            first = false;
            decryptionKeys.add(new JSONDecryptionDecoder.DecryptionKeyHolder(keyPair.getPublic(),
                                                                             keyPair.getPrivate(),
                                                                             keyEncryptionAlgorithm,
                                                                             keyId));
            JSONAsymKeyEncrypter encrypter = new JSONAsymKeyEncrypter(keyPair.getPublic(),
                                                                      keyEncryptionAlgorithm);
            if (wantKeyId) {
                encrypter.setKeyId(keyId).setOutputPublicKeyInfo(false);
            }
            if (algList.length() > 0) {
                algList += ",";
            }
            algList += keyType + "#" + keyEncryptionAlgorithm.toString().toLowerCase();
            encrypters.add(encrypter);
        }
        JSONCryptoHelper.Options options = new JSONCryptoHelper.Options();
        String fileSuffix = algCheck == null ? "mult-jwk.json" : "mult-glob+alg-jwk.json"; 
        if (wantKeyId) {
            fileSuffix = "mult-kid.json"; 
            if (algCheck != null) {
                fileSuffix = "mult-glob+alg-kid.json";
            }
            options.setKeyIdOption(JSONCryptoHelper.KEY_ID_OPTIONS.REQUIRED);
            options.setRequirePublicKeyInfo(false);
        }
        byte[] encryptedData =
               JSONObjectWriter.createEncryptionObjects(dataToBeEncrypted, 
                                                        contentEncryptionAlgorithm,
                                                        encrypters).serializeToBytes(JSONOutputFormats.PRETTY_PRINT);
        String baseName = algList + "@" + contentEncryptionAlgorithm.toString().toLowerCase() + "@" + fileSuffix;
        String fileName = baseEncryption + baseName;
        int q = 0;
        JSONObjectReader newEncryptedData = JSONParser.parse(encryptedData);
        for (JSONDecryptionDecoder decoder : newEncryptedData.getEncryptionObjects(options)) {
            q++;
            if (!ArrayUtil.compare(decoder.getDecryptedData(decryptionKeys), dataToBeEncrypted)) {
                throw new Exception("Dec err");
            }
        }
        if (q != keyTypes.length) {
            throw new IOException("Wrong number of recipients");
        }
        boolean changed = true;
        options = new JSONCryptoHelper.Options();
        if (wantKeyId) {
            options.setKeyIdOption(JSONCryptoHelper.KEY_ID_OPTIONS.REQUIRED);
            options.setRequirePublicKeyInfo(false);
        }
        try {
            JSONObjectReader oldEncryptedData = JSONParser.parse(ArrayUtil.readFile(fileName));
            boolean allOk = true;
            for (JSONDecryptionDecoder decoder : oldEncryptedData.getEncryptionObjects(options)) {
                if (!ArrayUtil.compare(decoder.getDecryptedData(decryptionKeys), dataToBeEncrypted)) {
                    allOk = false;
                    break;
                }
            }
            if (allOk) {
                // All good but are the new and old effectively the same?
                if (cleanEncryption(newEncryptedData).equals(cleanEncryption(oldEncryptedData))) {
                    return;  // Yes, don't rewrite.
                }
            }
        } catch (Exception  e) {
            changed = false;  // New I guess
        }
        if (changed) {
            System.out.println("UPDATED: " + baseName);
        }
        ArrayUtil.writeFile(fileName, encryptedData);
    }
}