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
package org.webpki.util;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Vector;

import org.webpki.asn1.BaseASN1Object;
import org.webpki.asn1.DerDecoder;
import org.webpki.asn1.ParseUtil;
import org.webpki.crypto.CertificateUtil;

/**
 * Functions for decoding PEM files
 */
public class PEMDecoder {
    private PEMDecoder() {
    }  // No instantiation please

 
    public static KeyPair getKeyPair(byte[] pemBlob) throws IOException, GeneralSecurityException {
        return new KeyPair(getPublicKey(pemBlob), getPrivateKey(pemBlob));
    }

    private static KeyFactory getKeyFactory(BaseASN1Object object) throws IOException, GeneralSecurityException {
        return KeyFactory.getInstance(ParseUtil.oid(ParseUtil.sequence(object).get(0))
                .oid().equals("1.2.840.113549.1.1.1") ? "RSA" : "EC");
    }

    public static PrivateKey getPrivateKey(byte[] pemBlob) throws IOException, GeneralSecurityException {
        byte[] privateKeyBlob = decodePemObject(pemBlob, "PRIVATE KEY");
        return getKeyFactory(ParseUtil.sequence(DerDecoder.decode(privateKeyBlob)).get(1))
                .generatePrivate(new PKCS8EncodedKeySpec(privateKeyBlob)); 
    }
    
    public static PublicKey getPublicKey(byte[] pemBlob) throws GeneralSecurityException, IOException {
        byte[] publicKeyBlob = decodePemObject(pemBlob, "PUBLIC KEY");
        return getKeyFactory(ParseUtil.sequence(DerDecoder.decode(publicKeyBlob)).get(0))
                .generatePublic(new X509EncodedKeySpec(publicKeyBlob)); 
    }

    public static X509Certificate[] getCertificatePath(byte[] pemBlob) throws IOException {
        return CertificateUtil.getSortedPathFromBlobs(decodePemObjects(pemBlob, "CERTIFICATE"));
    }

    public static KeyStore getKeyStore(byte[] pemBlob, String alias, String password)
    throws GeneralSecurityException, IOException {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, password.toCharArray());
        keyStore.setKeyEntry(alias,
                             getPrivateKey(pemBlob),
                             password.toCharArray(),
                             getCertificatePath(pemBlob));
        return keyStore;
    }

    public static X509Certificate getRootCertificate(byte[] pemBlob) 
    throws IOException {
        X509Certificate[] certPath = getCertificatePath(pemBlob);
        return certPath[certPath.length - 1];
    }

    private static Vector<byte[]> decodePemObjects(byte[]pemBlob, String itemType) throws IOException {
        String pemString = new String(pemBlob, "utf-8");
        String header = "-----BEGIN " + itemType + "-----";
        String footer = "-----END "   + itemType + "-----";
        Vector<byte[]> objects = new Vector<byte[]>();
        int start = 0;
        while (true) {
            start = pemString.indexOf(header, start);
            if (start < 0) {
                if (objects.isEmpty()) {
                    throw new IOException("Didn't find any: " + header);
                }
                break;
            }
            int end = pemString.indexOf(footer, start);
            if (end < 0) throw new IOException("Expected to find: " + footer);
            objects.add(new Base64()
                .getBinaryFromBase64String(pemString.substring(start + header.length(), end)));
            start = end + footer.length();
        }
        return objects;
    }
    
    private static byte[] decodePemObject(byte[]pemBlob, String itemType) throws IOException {
        Vector<byte[]> objects = decodePemObjects(pemBlob, itemType);
        if (objects.size() != 1) {
            throw new IOException("Only expected one: " + itemType);
        }
        return objects.firstElement();
    }
}
