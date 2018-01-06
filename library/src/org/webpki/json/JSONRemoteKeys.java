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

import java.security.PublicKey;

import java.security.cert.X509Certificate;

/**
 * Enum and interface to "jku" and "x5u";.
 */
public enum JSONRemoteKeys {

    PEM_CERT_PATH (JSONCryptoDecoder.X5U_JSON, true),
    JWK_KEY_SET   (JSONCryptoDecoder.JKU_JSON, false);

    String jsonName;
    boolean certificateFlag;

    JSONRemoteKeys(String jsonName, boolean certificateFlag) {
        this.jsonName = jsonName;
        this.certificateFlag = certificateFlag;
    }
    
    /**
     * For reading "jku" and "x5u" data
     */
    public interface Reader {
        
        public PublicKey readPublicKey(String uri) throws IOException;
        
        public X509Certificate[] readCertificatePath(String uri) throws IOException;
    }
}
