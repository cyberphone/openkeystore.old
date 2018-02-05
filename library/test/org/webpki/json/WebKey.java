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

import java.util.Vector;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.CertificateUtil;

import org.webpki.net.HTTPSWrapper;

import org.webpki.util.Base64;

public class WebKey implements JSONRemoteKeys.Reader {
        
    Vector<byte[]> getBinaryContentFromPem(byte[] pemBinary, String label, boolean multiple) throws IOException {
        String pem = new String(pemBinary, "UTF-8");
        Vector<byte[]> result = new Vector<byte[]>();
        while (true) {
            int start = pem.indexOf("-----BEGIN " + label + "-----");
            int end = pem.indexOf("-----END " + label + "-----");
            if (start >= 0 && end > 0 && end > start) {
                byte[] blob = new Base64().getBinaryFromBase64String(pem.substring(start + label.length() + 16, end));
                result.add(blob);
                pem = pem.substring(end + label.length() + 14);
            } else {
                if (result.isEmpty()) {
                    throw new IOException("No \"" + label + "\" found");
                }
                if (!multiple && result.size() > 1) {
                    throw new IOException("Multiple \"" + label + "\" found");
                }
                return result;
            }
        }
    }
 
    byte[] shoot(String uri) throws IOException {
        HTTPSWrapper wrapper = new HTTPSWrapper();
        wrapper.makeGetRequest(uri);
        return wrapper.getData();
    }

    @Override
    public PublicKey readPublicKey(String uri) throws IOException {
        byte[] data = shoot(uri);
        JSONArrayReader ar = JSONParser.parse(data).getArray(JSONCryptoHelper.KEYS_JSON);
        PublicKey publicKey = ar.getObject().getCorePublicKey(AlgorithmPreferences.JOSE_ACCEPT_PREFER);
        if (ar.hasMore()) {
            throw new IOException("JWK key sets must in this implementation only hold a single JWK");
        }
        return publicKey;
    }

    @Override
    public X509Certificate[] readCertificatePath(String uri) throws IOException {
        byte[] data = shoot(uri);
        return CertificateUtil.getSortedPathFromBlobs(getBinaryContentFromPem(data, "CERTIFICATE", true));
    }
}
