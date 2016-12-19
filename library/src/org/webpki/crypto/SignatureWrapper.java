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
package org.webpki.crypto;

import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;

import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;

import java.security.spec.ECParameterSpec;

/**
 * Wrapper over java.security.Signature
 */
public class SignatureWrapper {

    static final int ASN1_SEQUENCE = 0x30;
    static final int ASN1_INTEGER  = 0x02;

    static final int LEADING_ZERO  = 0x00;

    boolean ecdsa_der_encoded;

    private static int getExtendTo(ECParameterSpec ec_parameters) throws IOException {
        return (KeyAlgorithms.getECKeyAlgorithm(ec_parameters).getPublicKeySizeInBits() + 7) / 8;
    }

    public static byte[] decodeDEREncodedECDSASignature(byte[] der_coded_signature,
                                                        ECParameterSpec ec_parameters) throws IOException {
        int extend_to = getExtendTo(ec_parameters);
        int index = 2;
        int length;
        byte[] concatendated_signature = new byte[extend_to << 1];
        if (der_coded_signature[0] != ASN1_SEQUENCE) {
            throw new IOException("Not SEQUENCE");
        }
        length = der_coded_signature[1];
        if (length < 4) {
            if (length != -127) {
                throw new IOException("ASN.1 Length error");
            }
            length = der_coded_signature[index++] & 0xFF;
        }
        if (index != der_coded_signature.length - length) {
            throw new IOException("ASN.1 Length error");
        }
        for (int offset = 0; offset <= extend_to; offset += extend_to) {
            if (der_coded_signature[index++] != ASN1_INTEGER) {
                throw new IOException("Not INTEGER");
            }
            int l = der_coded_signature[index++];
            while (l > extend_to) {
                if (der_coded_signature[index++] != LEADING_ZERO) {
                    throw new IOException("Bad INTEGER");
                }
                l--;
            }
            System.arraycopy(der_coded_signature, index, concatendated_signature, offset + extend_to - l, l);
            index += l;
        }
        if (index != der_coded_signature.length) {
            throw new IOException("ASN.1 Length error");
        }
        return concatendated_signature;
    }

    public static byte[] encodeDEREncodedECDSASignature(byte[] concatendated_signature,
                                                        ECParameterSpec ec_parameters) throws IOException {
        int extend_to = getExtendTo(ec_parameters);
        if (extend_to != concatendated_signature.length / 2) {
            throw new IOException("Signature length error");
        }

        int i = extend_to;
        while (i > 0 && concatendated_signature[extend_to - i] == LEADING_ZERO) {
            i--;
        }
        int j = i;
        if (concatendated_signature[extend_to - i] < 0) {
            j++;
        }

        int k = extend_to;
        while (k > 0 && concatendated_signature[2 * extend_to - k] == LEADING_ZERO) {
            k--;
        }
        int l = k;
        if (concatendated_signature[2 * extend_to - k] < 0) {
            l++;
        }

        int len = 2 + j + 2 + l;
        int offset = 1;
        byte der_coded_signature[];
        if (len < 128) {
            der_coded_signature = new byte[len + 2];
        } else {
            der_coded_signature = new byte[len + 3];
            der_coded_signature[1] = (byte) 0x81;
            offset = 2;
        }
        der_coded_signature[0] = ASN1_SEQUENCE;
        der_coded_signature[offset++] = (byte) len;
        der_coded_signature[offset++] = ASN1_INTEGER;
        der_coded_signature[offset++] = (byte) j;
        System.arraycopy(concatendated_signature, extend_to - i, der_coded_signature, offset + j - i, i);
        offset += j;
        der_coded_signature[offset++] = ASN1_INTEGER;
        der_coded_signature[offset++] = (byte) l;
        System.arraycopy(concatendated_signature, 2 * extend_to - k, der_coded_signature, offset + l - k, k);
        return der_coded_signature;
    }

    Signature instance;
    boolean rsa_flag;
    ECParameterSpec ec_parameters;

    private SignatureWrapper(AsymSignatureAlgorithms algorithm, String provider, Key key) throws GeneralSecurityException, IOException {
        instance = provider == null ? Signature.getInstance(algorithm.getJCEName())
                                                    : 
                                      Signature.getInstance(algorithm.getJCEName(), provider);
        rsa_flag = key instanceof RSAKey;
        if (!rsa_flag) {
            ec_parameters = ((ECKey) key).getParams();
        }
    }

    public SignatureWrapper(AsymSignatureAlgorithms algorithm, 
                            PublicKey public_key,
                            String provider) throws GeneralSecurityException, IOException {
        this(algorithm, provider, public_key);
        instance.initVerify(public_key);
    }

    public SignatureWrapper(AsymSignatureAlgorithms algorithm,
                            PublicKey public_key) throws GeneralSecurityException, IOException {
        this(algorithm, public_key, null);
    }

    public SignatureWrapper(AsymSignatureAlgorithms algorithm,
                            PrivateKey private_key,
                            String provider) throws GeneralSecurityException, IOException {
        this(algorithm, provider, private_key);
        instance.initSign(private_key);
    }

    public SignatureWrapper(AsymSignatureAlgorithms algorithm,
                            PrivateKey private_key) throws GeneralSecurityException, IOException {
        this(algorithm, private_key, null);
    }

    public SignatureWrapper setECDSASignatureEncoding(boolean der_encoded) {
        ecdsa_der_encoded = der_encoded;
        return this;
    }

    public SignatureWrapper update(byte[] data) throws GeneralSecurityException {
        instance.update(data);
        return this;
    }

    public SignatureWrapper update(byte data) throws GeneralSecurityException {
        instance.update(data);
        return this;
    }

    public Provider getProvider() {
        return instance.getProvider();
    }

    public boolean verify(byte[] signature) throws GeneralSecurityException, IOException {
        return instance.verify(ecdsa_der_encoded || rsa_flag ?
                signature : SignatureWrapper.encodeDEREncodedECDSASignature(signature, ec_parameters));
    }

    public byte[] sign() throws GeneralSecurityException, IOException {
        return ecdsa_der_encoded || rsa_flag ?
                instance.sign() : SignatureWrapper.decodeDEREncodedECDSASignature(instance.sign(), ec_parameters);
    }
}
