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
import java.security.KeyStore;

import java.security.cert.X509Certificate;

import java.util.Vector;

import org.webpki.crypto.CustomCryptoProvider;
import org.webpki.crypto.KeyStoreVerifier;
import org.webpki.crypto.MACAlgorithms;

import org.webpki.json.JSONArrayWriter;
import org.webpki.json.JSONAsymKeySigner;
import org.webpki.json.JSONAsymKeyVerifier;
import org.webpki.json.JSONCryptoDecoder;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;
import org.webpki.json.JSONRemoteKeys;
import org.webpki.json.JSONSignatureDecoder;
import org.webpki.json.JSONSigner;
import org.webpki.json.JSONSymKeySigner;
import org.webpki.json.JSONSymKeyVerifier;
import org.webpki.json.JSONX509Signer;
import org.webpki.json.JSONX509Verifier;

import org.webpki.json.WebKey;

import org.webpki.util.ArrayUtil;

/*
 * Create JCS test vectors
 */
public class Signatures {
    static String baseKey;
    static String baseSignatures;
    static SymmetricKeys symmetricKeys;
    static JSONX509Verifier x509Verifier;
    static String keyId;
   
    static final String P256CERTPATH = "https://cyberphone.github.io/doc/openkeystore/p256certpath.pem";
    static final String R2048KEY     = "https://cyberphone.github.io/doc/openkeystore/r2048.jwks";

    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            throw new Exception("Wrong number of arguments");
        }
        CustomCryptoProvider.forcedLoad(true);
        baseKey = args[0] + File.separator;
        baseSignatures = args[1] + File.separator;
        symmetricKeys = new SymmetricKeys(baseKey);
        
        X509Certificate rootca = JSONParser.parse(ArrayUtil.readFile(baseKey + "rootca.x5c"))
                .getJSONArrayReader().getCertificatePath()[0];
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load (null, null);
        keyStore.setCertificateEntry ("mykey", rootca);        
        x509Verifier = new JSONX509Verifier(new KeyStoreVerifier(keyStore));

       
        asymSign("p256");
        asymSign("p384");
        asymSign("p521");
        asymSign("r2048");

        asymSignOptionalPublicKeyInfo("p256", true, false);
        asymSignOptionalPublicKeyInfo("p256", true, true);
        asymSignOptionalPublicKeyInfo("p521", false, false);

        certSign("p256");
        certSign("p384");
        certSign("p521");
        certSign("r2048");
        
        symmSign(256, MACAlgorithms.HMAC_SHA256);
        symmSign(384, MACAlgorithms.HMAC_SHA384);
        symmSign(512, MACAlgorithms.HMAC_SHA512);
        
        multipleSign("p256", "r2048");
        
        KeyPair localKey = readJwk("r2048");
        JSONAsymKeySigner remoteKeySigner =
                new JSONAsymKeySigner(localKey.getPrivate(),
                                      localKey.getPublic(),
                                      null)
                    .setRemoteKey(R2048KEY);
        byte[] remoteSig = createSignature(remoteKeySigner);
        ArrayUtil.writeFile(baseSignatures + "r2048remotekeysigned.json", remoteSig);
        JSONParser.parse(remoteSig).getSignature(new JSONCryptoDecoder.Options()
            .setRemoteKeyReader(new WebKey(), JSONRemoteKeys.JWK_KEY_SET));

        localKey = readJwk("p256");
        X509Certificate[] localPath = readCertificatePath("p256");
        JSONX509Signer remoteCertSigner =
                new JSONX509Signer(localKey.getPrivate(),
                                   localPath,
                                   null)
                    .setRemoteKey(P256CERTPATH);
        remoteSig = createSignature(remoteCertSigner);
        ArrayUtil.writeFile(baseSignatures + "p256remotecertsigned.json", remoteSig);
        JSONParser.parse(remoteSig).getSignature(new JSONCryptoDecoder.Options()
            .setRemoteKeyReader(new WebKey(), JSONRemoteKeys.PEM_CERT_PATH));
        
        byte[] signedData = createSignature(new JSONAsymKeySigner(localKey.getPrivate(), localKey.getPublic(), null)
                   .setExtensions(new JSONObjectWriter()
                        .setString(new Extension1().getExtensionUri(), "something")
                        .setObject(new Extension2().getExtensionUri(), 
                                   new JSONObjectWriter().setBoolean("life-is-great", true))));
        ArrayUtil.writeFile(baseSignatures + "p256keyextsigned.json", signedData);
        JSONCryptoDecoder.ExtensionHolder eh = new JSONCryptoDecoder.ExtensionHolder();
        eh.addExtension(Extension1.class, true);
        eh.addExtension(Extension2.class, true);
        JSONParser.parse(signedData).getSignature(new JSONCryptoDecoder.Options()
                        .setPermittedExtensions(eh)).verify(new JSONAsymKeyVerifier(localKey.getPublic()));

        JSONObjectWriter mixedData = new JSONObjectWriter()
            .setString("mySignedData", "something")
            .setString("myUnsignedData", "something else")
            .setSignature(new JSONAsymKeySigner(localKey.getPrivate(), localKey.getPublic(), null)
                .setExcluded(new String[]{"myUnsignedData"}));
        signedData = mixedData.serializeToBytes(JSONOutputFormats.PRETTY_PRINT);
        ArrayUtil.writeFile(baseSignatures + "p256keyexclsigned.json", signedData);
        JSONParser.parse(signedData).getSignature(new JSONCryptoDecoder.Options()
                         .setPermittedExclusions(new String[]{"myUnsignedData"}))
                         .verify(new JSONAsymKeyVerifier(localKey.getPublic()));

        JSONObjectWriter javaScriptSignature = new JSONObjectWriter()
            .setString("statement", "Hello Signed World!")
            .setArray("otherProperties", 
                      new JSONArrayWriter()
                .setInt(2000)
                .setBoolean(true));
        javaScriptSignature.setSignature(new JSONAsymKeySigner(localKey.getPrivate(), localKey.getPublic(), null));
        ArrayUtil.writeFile(baseSignatures + "p256keysigned.js",
                            javaScriptSignature.serializeToBytes(JSONOutputFormats.PRETTY_JS_NATIVE));
    }
    
    static void symmSign(int keyBits, MACAlgorithms algorithm) throws Exception {
        byte[] key = symmetricKeys.getValue(keyBits);
        String keyName = symmetricKeys.getName(keyBits);
        byte[] signedData = createSignature(new JSONSymKeySigner(key, algorithm).setKeyId(keyName));
        ArrayUtil.writeFile(baseSignatures + "hs" + (key.length * 8) + "signed.json", signedData);
        JSONParser.parse(signedData).getSignature(new JSONCryptoDecoder.Options()
                .setRequirePublicKeyInfo(false)
                .setKeyIdOption(JSONCryptoDecoder.KEY_ID_OPTIONS.REQUIRED)).verify(new JSONSymKeyVerifier(key));
    }

    static String getDataToSign() throws Exception {
        return new String(ArrayUtil.readFile(baseSignatures + "datatobesigned.json"), 
                          "UTF-8").replace("\r", "");
    }
    
    static JSONObjectWriter parseDataToSign() throws Exception {
        return new JSONObjectWriter(JSONParser.parse(getDataToSign()));
    }

    static byte[] createSignature(JSONSigner signer) throws Exception {
        String signed = parseDataToSign().setSignature(signer).toString();
        int i = signed.indexOf(",\n  \"signature\":");
        String unsigned = getDataToSign();
        int j = unsigned.lastIndexOf("\n}");
        return (unsigned.substring(0,j) + signed.substring(i)).getBytes("UTF-8");
    }
    
    static byte[] createSignatures(Vector<JSONSigner> signers) throws Exception {
        String signed = parseDataToSign().setSignatures(signers).toString();
        int i = signed.indexOf(",\n  \"signatures\":");
        String unsigned = getDataToSign();
        int j = unsigned.lastIndexOf("\n}");
        return (unsigned.substring(0,j) + signed.substring(i)).getBytes("UTF-8");
    }

    static KeyPair readJwk(String keyType) throws Exception {
        JSONObjectReader jwkPlus = JSONParser.parse(ArrayUtil.readFile(baseKey + keyType + "privatekey.jwk"));
        // Note: The built-in JWK decoder does not accept "kid" since it doesn't have a meaning in JCS or JEF. 
        if ((keyId = jwkPlus.getStringConditional("kid")) != null) {
            jwkPlus.removeProperty("kid");
        }
        return jwkPlus.getKeyPair();
    }

    static void asymSign(String keyType) throws Exception {
        KeyPair keyPair = readJwk(keyType);
        byte[] signedData = createSignature(new JSONAsymKeySigner(keyPair.getPrivate(), keyPair.getPublic(), null));
        ArrayUtil.writeFile(baseSignatures + keyType + "keysigned.json", signedData);
        JSONParser.parse(signedData).getSignature(new JSONCryptoDecoder.Options()).verify(new JSONAsymKeyVerifier(keyPair.getPublic()));
     }

    static void multipleSign(String keyType1, String KeyType2) throws Exception {
        KeyPair keyPair1 = readJwk(keyType1);
        KeyPair keyPair2 = readJwk(KeyType2);
        Vector<JSONSigner> signers = new Vector<JSONSigner>();
        signers.add(new JSONAsymKeySigner(keyPair1.getPrivate(), keyPair1.getPublic(), null));
        signers.add(new JSONAsymKeySigner(keyPair2.getPrivate(), keyPair2.getPublic(), null));
        byte[] signedData = createSignatures(signers);
        ArrayUtil.writeFile(baseSignatures + keyType1 + "+" + KeyType2 + "keysigned.json", signedData);
        Vector<JSONSignatureDecoder> signatures = 
                JSONParser.parse(signedData).getSignatures(new JSONCryptoDecoder.Options());
        signatures.get(0).verify(new JSONAsymKeyVerifier(keyPair1.getPublic()));
        signatures.get(1).verify(new JSONAsymKeyVerifier(keyPair2.getPublic()));
        if (signatures.size() != 2) {
            throw new Exception("Wrong multi");
        }
     }

    static void asymSignOptionalPublicKeyInfo(String keyType, boolean wantKeyId, boolean wantPublicKey) throws Exception {
        KeyPair keyPair = readJwk(keyType);
        JSONSigner signer = 
                new JSONAsymKeySigner(keyPair.getPrivate(), keyPair.getPublic(), null);
        if (wantKeyId) {
            signer.setKeyId(keyId);
        }
        signer.setOutputPublicKeyInfo(wantPublicKey);
        byte[] signedData = createSignature(signer);
        ArrayUtil.writeFile(baseSignatures + keyType + (wantPublicKey && wantKeyId ? "mixed" : "implicit") + "keysigned.json", signedData);
        JSONParser.parse(signedData).getSignature(
            new JSONCryptoDecoder.Options()
                .setRequirePublicKeyInfo(wantPublicKey)
                .setKeyIdOption(wantKeyId ? 
                        JSONCryptoDecoder.KEY_ID_OPTIONS.REQUIRED : JSONCryptoDecoder.KEY_ID_OPTIONS.FORBIDDEN))
                    .verify(new JSONAsymKeyVerifier(keyPair.getPublic()));
     }

    static X509Certificate[] readCertificatePath(String keyType) throws IOException {
        return JSONParser.parse(ArrayUtil.readFile(baseKey + keyType + "certificate.x5c"))
                .getJSONArrayReader().getCertificatePath();
    }

    static void certSign(String keyType) throws Exception {
        KeyPair keyPair = readJwk(keyType);
        byte[] signedData = createSignature(new JSONX509Signer(keyPair.getPrivate(), 
                                                               readCertificatePath(keyType),
                                                               null));
        ArrayUtil.writeFile(baseSignatures + keyType + "certsigned.json", signedData);
        JSONParser.parse(signedData).getSignature(new JSONCryptoDecoder.Options()).verify(x509Verifier);
    }
}