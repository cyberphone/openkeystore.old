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

import java.security.cert.X509Certificate;

/**
 * Initiatiator object for certificate based encryptions.
 */
public class JSONX509Encrypter extends JSONEncrypter {

    private static final long serialVersionUID = 1L;
    
    X509Certificate[] certificatePath;

    /**
     * Constructor for JCE based solutions.
     * @param certificatePath Certificate path used for encrypting the key
     * @param keyEncryptionAlgorithm The algorithm used for encrypting the key
     * @param provider Optional JCE provider or null
     * @throws IOException &nbsp;
     */
    public JSONX509Encrypter(X509Certificate[] certificatePath,
                             KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                             String provider) throws IOException {
        this.certificatePath = certificatePath;
        this.keyEncryptionAlgorithm = keyEncryptionAlgorithm;
        this.publicKey = certificatePath[0].getPublicKey();
        this.provider = provider;
    }

    /**
     * Set remote key (&quot;x5u&quot;) indicator.
     * This method <i>suppresses</i> the in-line certificate data.
     * Note that the certificate path must anyway be provided during <i>encryption</i>. 
     * @param url Where the (PEM) certificate path resides
     * @return this
     * @throws IOException &nbsp;
     * @see org.webpki.json.JSONRemoteKeys
     */
    public JSONX509Encrypter setRemoteKey(String url) throws IOException {
        setRemoteKey(url, JSONRemoteKeys.PEM_CERT_PATH);
        return this;
    }

    @Override
    void writeKeyData(JSONObjectWriter wr) throws IOException {
        wr.setCertificatePath(certificatePath);
    }
}
