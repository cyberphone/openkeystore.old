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

import java.security.PublicKey;

import java.security.cert.X509Certificate;

/**
 * Enum and interface to &quot;remoteKey&quot;.
 */
public enum JSONRemoteKeys {

    PEM_CERT_PATH ("PEM-CERT-PATH", true),
    DER_CERT      ("DER-CERT",      true),
    PEM_PUB_KEY   ("PEM-PUB-KEY",   false),
    JWK_PUB_KEY   ("JWK-PUB-KEY",   false);

    String jsonName;
    boolean certificatePath;

    JSONRemoteKeys(String jsonName, boolean certificatePath) {
        this.jsonName = jsonName;
        this.certificatePath = certificatePath;
    }
    
    public interface Reader {
        
        public PublicKey readPublicKey(String uri, JSONRemoteKeys format) throws IOException;
        
        public X509Certificate[] readCertificatePath(String uri, JSONRemoteKeys format) throws IOException;
    }

    public boolean isCertificatePath() {
        return certificatePath;
    }

    @Override
    public String toString() {
        return jsonName;
    }

    public static JSONRemoteKeys getFormatFromId(String formatId) throws IOException {
        for (JSONRemoteKeys format : JSONRemoteKeys.values()) {
            if (formatId.equals(format.jsonName)) {
                return format;
            }
        }
        throw new IOException("No such format: " + formatId);
    }
}
