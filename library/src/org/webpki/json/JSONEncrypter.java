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

import org.webpki.crypto.AlgorithmPreferences;

/**
 * Support class for encryption generators.
 */
public abstract class JSONEncrypter implements Serializable {

    private static final long serialVersionUID = 1L;

    JSONObjectReader extensions;
    
    String keyId;

    boolean outputPublicKeyInfo = true;

    String remoteUrl;

    JSONRemoteKeys remoteKeyFormat;
    
    AlgorithmPreferences algorithmPreferences = AlgorithmPreferences.JOSE_ACCEPT_PREFER;

    JSONEncrypter() {
    }

    abstract void writeKeyData(JSONObjectWriter wr) throws IOException;

    /**
     * Set &quot;crit&quot; for this encryption object.
     * @param extensions JSON object holding the extension properties and associated values
     * @return this
     * @throws IOException &nbsp;
     */
    public JSONEncrypter setExtensions(JSONObjectWriter extensions) throws IOException {
        this.extensions = new JSONObjectReader(extensions);
        JSONSignatureDecoder.checkExtensions(this.extensions.getProperties());
        return this;
    }

    void setRemoteKey(String url, JSONRemoteKeys format) throws IOException {
        this.remoteUrl = JSONSignatureDecoder.checkHttpsUrl(url);
        this.remoteKeyFormat = format;
    }

    /**
     * Set optional &quot;kid&quot; for this encryption object.
     * @param keyId The identifier
     * @return this
     */
    public JSONEncrypter setKeyId(String keyId) {
        this.keyId = keyId;
        return this;
    }

    /**
     * Set if public key information should be provided in the encryption object.
     * Note: default <code>true</code>.
     * @param flag <code>true</code> if such information is to be provided
     * @return this
     */
    public JSONEncrypter setOutputPublicKeyInfo(boolean flag) {
        this.outputPublicKeyInfo = flag;
        return this;
    }
}
