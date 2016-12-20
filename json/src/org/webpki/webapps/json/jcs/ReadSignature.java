/*
 *  Copyright 2006-2016 WebPKI.org (http://webpki.org).
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
package org.webpki.webapps.json.jcs;

import java.io.IOException;

import java.math.BigInteger;

import java.security.PublicKey;

import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import java.security.spec.ECPoint;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.CertificateInfo;
import org.webpki.crypto.KeyAlgorithms;

import org.webpki.json.JSONArrayReader;
import org.webpki.json.JSONSignatureDecoder;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONSymKeyVerifier;
import org.webpki.json.JSONTypes;

import org.webpki.util.DebugFormatter;

/**
 * Simple signature verify program
 */
public class ReadSignature {
    private StringBuffer result = new StringBuffer();

    private String cryptoBinary(BigInteger value, KeyAlgorithms key_alg)
            throws IOException {
        byte[] crypto_binary = value.toByteArray();
        boolean modify = true;
        if (key_alg.isECKey()) {
            if (crypto_binary.length > (key_alg.getPublicKeySizeInBits() + 7) / 8) {
                if (crypto_binary[0] != 0) {
                    throw new IOException("Unexpected EC value");
                }
            } else {
                modify = false;
            }
        }
        if (modify && crypto_binary[0] == 0x00) {
            byte[] wo_zero = new byte[crypto_binary.length - 1];
            System.arraycopy(crypto_binary, 1, wo_zero, 0, wo_zero.length);
            crypto_binary = wo_zero;
        }
        String pre = "";
        StringBuffer result = new StringBuffer();
        int i = 0;
        for (char c : DebugFormatter.getHexString(crypto_binary).toCharArray()) {
            if (++i % 80 == 0) {
                result.append('\n');
                pre = "\n";
            }
            result.append(c);
        }
        return pre + result.toString();
    }

    void recurseObject(JSONObjectReader rd) throws IOException {
        for (String property : rd.getProperties()) {
            switch (rd.getPropertyType(property)) {
            case OBJECT:
                if (property.equals(JSONSignatureDecoder.SIGNATURE_JSON)) {
                    JSONSignatureDecoder signature = rd
                            .getSignature(AlgorithmPreferences.JOSE_ACCEPT_PREFER);
                    switch (signature.getSignatureType()) {
                    case ASYMMETRIC_KEY:
                        PublicKey publicKey = signature.getPublicKey();
                        KeyAlgorithms key_alg = KeyAlgorithms
                                .getKeyAlgorithm(publicKey);
                        StringBuffer asym_text = new StringBuffer(
                                "Asymmetric key signature validated for:\n")
                                .append(key_alg.isECKey() ? "EC" : "RSA")
                                .append(" Public Key (")
                                .append(key_alg.getPublicKeySizeInBits())
                                .append(" bits)");
                        if (key_alg.isECKey()) {
                            asym_text.append(", Curve=").append(
                                    key_alg.getJCEName());
                            ECPoint ec_point = ((ECPublicKey) publicKey)
                                    .getW();
                            asym_text
                                    .append("\nX: ")
                                    .append(cryptoBinary(ec_point.getAffineX(),
                                            key_alg))
                                    .append("\nY: ")
                                    .append(cryptoBinary(ec_point.getAffineY(),
                                            key_alg));
                        } else {
                            asym_text
                                    .append("\nModulus: ")
                                    .append(cryptoBinary(
                                            ((RSAPublicKey) publicKey)
                                                    .getModulus(), key_alg))
                                    .append("\nExponent: ")
                                    .append(cryptoBinary(
                                            ((RSAPublicKey) publicKey)
                                                    .getPublicExponent(),
                                            key_alg));
                        }
                        debugOutput(asym_text.toString());
                        break;

                    case SYMMETRIC_KEY:
                        signature.verify(new JSONSymKeyVerifier(
                                new GenerateSignature.SymmetricOperations())
                                .permitKeyId(true));
                        debugOutput("Symmetric key signature validated for Key ID: "
                                + signature.getKeyId()
                                + "\nValue="
                                + DebugFormatter
                                        .getHexString(GenerateSignature.SYMMETRIC_KEY));
                        break;

                    default:
                        debugOutput("X509 signature validated for:\n"
                                + new CertificateInfo(
                                        signature.getCertificatePath()[0])
                                        .toString());
                        break;
                    }
                } else {
                    recurseObject(rd.getObject(property));
                }
                break;

            case ARRAY:
                recurseArray(rd.getArray(property));
                break;

            default:
                rd.scanAway(property);
            }
        }
    }

    void recurseArray(JSONArrayReader array) throws IOException {
        while (array.hasMore()) {
            if (array.getElementType() == JSONTypes.OBJECT) {
                recurseObject(array.getObject());
            } else if (array.getElementType() == JSONTypes.ARRAY) {
                recurseArray(array.getArray());
            } else {
                array.scanAway();
            }
        }
    }

    void debugOutput(String string) {
        result.append('\n').append(string).append('\n');
    }

    String getResult() throws IOException {
        if (result.length() == 0) {
            throw new IOException("No Signatures found!");
        }
        return result.toString();
    }
}
