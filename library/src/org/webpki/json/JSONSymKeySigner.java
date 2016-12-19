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
package org.webpki.json;

import java.io.IOException;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.MACAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.crypto.SymKeySignerInterface;

/**
 * Initiatiator object for symmetric key signatures.
 */
public class JSONSymKeySigner extends JSONSigner {

    private static final long serialVersionUID = 1L;

    MACAlgorithms algorithm;

    SymKeySignerInterface signer;

    public JSONSymKeySigner(SymKeySignerInterface signer) throws IOException {
        this.signer = signer;
        algorithm = signer.getMacAlgorithm();
    }

    public JSONSymKeySigner setAlgorithmPreferences(AlgorithmPreferences algorithmPreferences) {
        this.algorithmPreferences = algorithmPreferences;
        return this;
    }

    @Override
    SignatureAlgorithms getAlgorithm() {
        return algorithm;
    }

    @Override
    byte[] signData(byte[] data) throws IOException {
        return signer.signData(data);
    }

    @Override
    void writeKeyData(JSONObjectWriter wr) throws IOException {
    }
}
