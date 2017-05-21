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
import java.io.Serializable;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.SignatureAlgorithms;

/**
 * Support class for signature generators.
 */
public abstract class JSONSigner implements Serializable {

    private static final long serialVersionUID = 1L;

    JSONObjectWriter extensions;

    String keyId;

    byte[] normalizedData;

    AlgorithmPreferences algorithmPreferences = AlgorithmPreferences.JOSE_ACCEPT_PREFER;

    JSONSigner() {
    }

    abstract SignatureAlgorithms getAlgorithm();

    abstract byte[] signData(byte[] data) throws IOException;

    abstract void writeKeyData(JSONObjectWriter wr) throws IOException;

    /**
     * Set &quot;extensions&quot; for this signature.
     * @param extensions A JSON object holding the extension properties and associated values
     * @return this
     * @throws IOException &nbsp;
     */
    public JSONSigner setExtensions(JSONObjectWriter extensions) throws IOException {
        if (extensions.root.properties.isEmpty()) {
            throw new IOException("Empty \"" + JSONSignatureDecoder.EXTENSIONS_JSON + "\" object not allowed");
        }
        this.extensions = extensions;
        return this;
    }

    /**
     * Set &quot;keyId&quot; for this signature.
     * Notes:<ul>
     * <li>keyId and in-line public key/certificate data are <i>mutually exclusive</i>.</li>
     * <li>And keyId with length zero (&quot;&quot;) is considered as a keyId
     *  but no output is produced.  That is, this solution is to be used when
     *  the signature key is <i>implicitly known</i> by the relying party.</li>
     * </ul>
     * @param keyId The identifier
     * @return this
     */
    public JSONSigner setKeyId(String keyId) {
        this.keyId = keyId;
        return this;
    }

    public byte[] getNormalizedData() {
        return normalizedData;
    }
}
