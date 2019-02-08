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

import java.math.BigInteger;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;

import java.security.cert.X509Certificate;

import java.security.interfaces.RSAPublicKey;

import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.MACAlgorithms;
import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.SignatureWrapper;

/**
 * Decoder for JSF signatures.
 */
public class JSONSignatureDecoder implements Serializable {

    private static final long serialVersionUID = 1L;

    SignatureAlgorithms algorithm;

    String algorithmString;

    byte[] normalizedData;

    byte[] signatureValue;

    X509Certificate[] certificatePath;

    PublicKey publicKey;

    String keyId;
    
    JSONCryptoHelper.Options options;
    
    LinkedHashMap<String,JSONCryptoHelper.Extension> extensions = new LinkedHashMap<String,JSONCryptoHelper.Extension>();

    JSONSignatureDecoder(JSONObjectReader signedData,
                         JSONObjectReader innerSignatureObject,
                         JSONObjectReader outerSignatureObject,
                         JSONCryptoHelper.Options options) throws IOException {
        this.options = options;
        algorithmString = innerSignatureObject.getString(JSONCryptoHelper.ALGORITHM_JSON);
        keyId = options.getKeyId(innerSignatureObject);
        if (options.requirePublicKeyInfo) {
            getPublicKeyInfo(innerSignatureObject);
        } else {
            for (AsymSignatureAlgorithms alg : AsymSignatureAlgorithms.values()) {
                if (algorithmString.equals(alg.getAlgorithmId(AlgorithmPreferences.JOSE_ACCEPT_PREFER)) ||
                        algorithmString.equals(alg.getAlgorithmId(AlgorithmPreferences.SKS))) {
                    algorithm = AsymSignatureAlgorithms.getAlgorithmFromId(algorithmString, 
                                                                           options.algorithmPreferences);
                    break;
                }
            }
            if (algorithm == null) {
                algorithm = MACAlgorithms.getAlgorithmFromId(algorithmString, options.algorithmPreferences);
            }
        }

        options.getExtensions(innerSignatureObject, outerSignatureObject, extensions);

        LinkedHashMap<String, JSONValue> saveExcluded = null;
        JSONValue saveExcludeArray = null;

        // Note: the following section will not execute for array signatures
        if (options.exclusions == null) {
            if (outerSignatureObject.hasProperty(JSONCryptoHelper.EXCLUDE_JSON)) {
                throw new IOException("Use of \"" + JSONCryptoHelper.EXCLUDE_JSON +
                                      "\" must be set in options");
            }
        } else {
            saveExcluded = new LinkedHashMap<String, JSONValue>(signedData.root.properties);
            LinkedHashSet<String> parsedExcludes = 
                    checkExcluded(outerSignatureObject.getStringArray(JSONCryptoHelper.EXCLUDE_JSON));
            for (String excluded : parsedExcludes.toArray(new String[0])) {
                if (!options.exclusions.contains(excluded)) {
                    throw new IOException("Unexpected \"" + JSONCryptoHelper.EXCLUDE_JSON + 
                                          "\" property: " + excluded);
                }
                signedData.root.properties.remove(excluded);
            }
            for (String excluded : options.exclusions.toArray(new String[0])) {
                if (!parsedExcludes.contains(excluded)) {
                    throw new IOException("Missing \"" + JSONCryptoHelper.EXCLUDE_JSON +
                                          "\" property: " + excluded);
                }
            }
            // Hide the exclude property from the serializer...
            saveExcludeArray = outerSignatureObject.root.properties.get(JSONCryptoHelper.EXCLUDE_JSON);
            outerSignatureObject.root.properties.put(JSONCryptoHelper.EXCLUDE_JSON, null);
        }

        signatureValue = innerSignatureObject.getBinary(JSONCryptoHelper.VALUE_JSON);

        //////////////////////////////////////////////////////////////////////////////////////
        // Begin JSF core normalization                                                     //
        //                                                                                  //
        // 1. Make a shallow copy of the signature object                                   //
        LinkedHashMap<String, JSONValue> savedProperties =                                  //
                new LinkedHashMap<String, JSONValue>(innerSignatureObject.root.properties); //
        //                                                                                  //
        // 2. Hide the signature value property for the serializer...                       //
        innerSignatureObject.root.properties.remove(JSONCryptoHelper.VALUE_JSON);           //
        //                                                                                  //
        // 3. Serialize ("JSON.stringify()")                                                //
        normalizedData = signedData.serializeToBytes(JSONOutputFormats.CANONICALIZED);      //
        //                                                                                  //
        // 4. Restore the signature object                                                  //
        innerSignatureObject.root.properties = savedProperties;                             //
        //                                                                                  //
        // End JCS core normalization                                                       //
        //////////////////////////////////////////////////////////////////////////////////////

        if (options.exclusions != null) {
            signedData.root.properties = saveExcluded;
            outerSignatureObject.root.properties.put(JSONCryptoHelper.EXCLUDE_JSON, saveExcludeArray);
        }

        // Check for unread (=forbidden) data                                            //
        innerSignatureObject.checkForUnread();                                              //

        if (options.requirePublicKeyInfo) switch (getSignatureType()) {
            case X509_CERTIFICATE:
                asymmetricSignatureVerification(certificatePath[0].getPublicKey());
                break;

            case ASYMMETRIC_KEY:
                asymmetricSignatureVerification(publicKey);
                break;

            default:
                // Should be a symmetric key then...
                break;
        }
    }

    void getPublicKeyInfo(JSONObjectReader rd) throws IOException {
        algorithm = AsymSignatureAlgorithms.getAlgorithmFromId(algorithmString, 
                                                               options.algorithmPreferences);
        if (rd.hasProperty(JSONCryptoHelper.CERTIFICATE_PATH)) {
            certificatePath = rd.getCertificatePath();
        } else if (rd.hasProperty(JSONCryptoHelper.PUBLIC_KEY_JSON)) {
            publicKey = rd.getPublicKey(options.algorithmPreferences);
        } else {
            throw new IOException("Missing key information");
        }
    }

    static BigInteger getCurvePoint(JSONObjectReader rd, String property, KeyAlgorithms ec) throws IOException {
        byte[] fixedBinary = rd.getBinary(property);
        if (fixedBinary.length != (ec.getPublicKeySizeInBits() + 7) / 8) {
            throw new IOException("Public EC key parameter \"" + property + "\" is not normalized");
        }
        return new BigInteger(1, fixedBinary);
    }

    static BigInteger getCryptoBinary(JSONObjectReader rd, String property) throws IOException {
        byte[] cryptoBinary = rd.getBinary(property);
        if (cryptoBinary[0] == 0x00) {
            throw new IOException("RSA key parameter \"" + property + "\" contains leading zeroes");
        }
        return new BigInteger(1, cryptoBinary);
    }

    static PublicKey decodePublicKey(JSONObjectReader rd,
                                     AlgorithmPreferences algorithmPreferences) throws IOException {
        PublicKey publicKey = null;
        try {
            String type = rd.getString(JSONCryptoHelper.KTY_JSON);
            if (type.equals(JSONCryptoHelper.RSA_PUBLIC_KEY)) {
                publicKey = KeyFactory.getInstance("RSA").generatePublic(
                        new RSAPublicKeySpec(getCryptoBinary(rd, JSONCryptoHelper.N_JSON),
                                             getCryptoBinary(rd, JSONCryptoHelper.E_JSON)));
            } else if (type.equals(JSONCryptoHelper.EC_PUBLIC_KEY)) {
                KeyAlgorithms ec = 
                        KeyAlgorithms.getKeyAlgorithmFromId(rd.getString(JSONCryptoHelper.CRV_JSON),
                                                            algorithmPreferences);
                if (!ec.isECKey()) {
                    throw new IOException("\"" + JSONCryptoHelper.CRV_JSON + "\" is not an EC type");
                }
                ECPoint w = new ECPoint(getCurvePoint(rd, JSONCryptoHelper.X_JSON, ec), getCurvePoint(rd, JSONCryptoHelper.Y_JSON, ec));
                publicKey = KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(w, ec.getECParameterSpec()));
            } else {
                throw new IOException("Unrecognized \"" + JSONCryptoHelper.KTY_JSON + "\": " + type);
            }
            return publicKey;
        } catch (GeneralSecurityException e) {
            throw new IOException(e);
        }
    }

    void asymmetricSignatureVerification(PublicKey publicKey) throws IOException {
        if (((AsymSignatureAlgorithms) algorithm).isRsa() != publicKey instanceof RSAPublicKey) {
            throw new IOException("\"" + algorithmString + "\" doesn't match key type: " + publicKey.getAlgorithm());
        }
        try {
            if (!new SignatureWrapper((AsymSignatureAlgorithms) algorithm, publicKey)
                         .update(normalizedData)
                         .verify(signatureValue)) {
                throw new IOException("Bad signature for key: " + publicKey.toString());
            }
        } catch (GeneralSecurityException e) {
            throw new IOException(e);
        }
    }

    public byte[] getSignatureValue() {
        return signatureValue;
    }

    public SignatureAlgorithms getAlgorithm() {
        return algorithm;
    }

    public JSONCryptoHelper.Extension getExtension(String name) {
        return extensions.get(name);
    }

    void checkRequest(JSONSignatureTypes signatureType) throws IOException {
        if (signatureType != getSignatureType()) {
            throw new IOException("Request doesn't match received signature: " + getSignatureType().toString());
        }
    }

    public X509Certificate[] getCertificatePath() throws IOException {
        checkRequest(JSONSignatureTypes.X509_CERTIFICATE);
        return certificatePath;
    }

    public PublicKey getPublicKey() throws IOException {
        checkRequest(JSONSignatureTypes.ASYMMETRIC_KEY);
        return publicKey;
    }

    public String getKeyId() {
        return keyId;
    }

    public byte[] getNormalizedData() {
        return normalizedData;
    }

    public JSONSignatureTypes getSignatureType() {
        if (certificatePath != null) {
            return JSONSignatureTypes.X509_CERTIFICATE;
        }
        return algorithm instanceof AsymSignatureAlgorithms ? JSONSignatureTypes.ASYMMETRIC_KEY : JSONSignatureTypes.SYMMETRIC_KEY;
    }

    /**
     * Simplified verify that only checks that there are no "kid" or "crit", and that the signature type matches.
     * Note that asymmetric key signatures are always checked for technical correctness unless
     * you have specified false for requirePublicKeyInfo.
     *
     * @param signatureType Type of signature :-)
     * @throws IOException &nbsp;
     */
    public void verify(JSONSignatureTypes signatureType) throws IOException {
        verify(new JSONVerifier(signatureType) {
            private static final long serialVersionUID = 1L;

                @Override
                void verify(JSONSignatureDecoder signatureDecoder) throws IOException {
            }
        });
    }

    public void verify(JSONVerifier verifier) throws IOException {
        checkRequest(verifier.signatureType);
        verifier.verify(this);
    }

    static PrivateKey decodePrivateKey(JSONObjectReader rd, PublicKey publicKey) throws IOException {
        try {
            KeyAlgorithms keyAlgorithm = KeyAlgorithms.getKeyAlgorithm(publicKey);
            if (keyAlgorithm.isECKey()) {
                return KeyFactory.getInstance("EC")
                        .generatePrivate(new ECPrivateKeySpec(getCurvePoint(rd, "d", keyAlgorithm),
                                                              keyAlgorithm.getECParameterSpec()));
            }
            return KeyFactory.getInstance("RSA")
                    .generatePrivate(new RSAPrivateCrtKeySpec(((RSAPublicKey) publicKey).getModulus(),
                                                              ((RSAPublicKey) publicKey).getPublicExponent(),
                                                              getCryptoBinary(rd, "d"),
                                                              getCryptoBinary(rd, "p"),
                                                              getCryptoBinary(rd, "q"),
                                                              getCryptoBinary(rd, "dp"),
                                                              getCryptoBinary(rd, "dq"),
                                                              getCryptoBinary(rd, "qi")));
        } catch (GeneralSecurityException e) {
            throw new IOException(e);
        }
    }

    static LinkedHashSet<String> checkExcluded(String[] excluded) throws IOException {
        if (excluded.length == 0) {
            throw new IOException("Empty \"" + JSONCryptoHelper.EXCLUDE_JSON + "\" array not allowed");
        }
        LinkedHashSet<String> ex = new LinkedHashSet<String>();
        for (String property : excluded) {
            if (!ex.add(property)) {
                throw new IOException("Duplicate \"" + JSONCryptoHelper.EXCLUDE_JSON + "\" property: " + property);
            }
        }
        return ex;
    }
}
