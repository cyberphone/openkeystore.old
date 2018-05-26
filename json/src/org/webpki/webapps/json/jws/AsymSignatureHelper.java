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
package org.webpki.webapps.json.jws;

import java.io.IOException;

import java.security.KeyStore;
import java.security.PublicKey;

import org.webpki.crypto.AsymKeySignerInterface;
import org.webpki.crypto.KeyStoreSigner;

/**
 * Signature helper
 */
public class AsymSignatureHelper extends KeyStoreSigner implements  AsymKeySignerInterface {
    AsymSignatureHelper(KeyStore signer_keystore) throws IOException {
        super(signer_keystore, null);
        setKey(null, JWSService.key_password);
    }

    @Override
    public PublicKey getPublicKey() throws IOException {
        return getCertificatePath()[0].getPublicKey();
    }
}
