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

import java.util.Enumeration;

import java.security.cert.X509Certificate;
import java.security.cert.Certificate;

import java.security.KeyStore;
import java.security.PrivateKey;

import java.security.GeneralSecurityException;

/**
 * Sign data using the KeyStore interface.
 */
public class KeyStoreSigner implements SignerInterface, CertificateSelectorSpi {

    private PrivateKey private_key;

    private KeyStore signer_cert_keystore;

    private AuthorityInfoAccessCAIssuersSpi aia_caissuer_handler;

    private String key_alias;

    private boolean extended_certpath;

    private boolean ecdsa_der_encoded;


    private KeyStoreSigner testKey(String key_alias) throws IOException, GeneralSecurityException {
        if (!signer_cert_keystore.isKeyEntry(key_alias)) {
            throw new IOException("Specified certficate does not have a private key: " + key_alias);
        }
        return this;
    }


    private X509Certificate[] getCertPath(String key_alias, boolean path_expansion) throws IOException, GeneralSecurityException {
        testKey(key_alias);
        Certificate[] cp = signer_cert_keystore.getCertificateChain(key_alias);
        X509Certificate[] certificate_path = new X509Certificate[cp.length];
        for (int q = 0; q < cp.length; q++) {
            certificate_path[q] = (X509Certificate) cp[q];
        }
        if (path_expansion && aia_caissuer_handler != null) {
            return aia_caissuer_handler.getUpdatedPath(certificate_path);
        }
        return certificate_path;
    }


    public CertificateSelection getCertificateSelection(CertificateFilter[] cfs) throws IOException {
        boolean path_expansion = false;
        for (CertificateFilter cf : cfs) {
            if (cf.needsPathExpansion()) {
                path_expansion = true;
                break;
            }
        }
        CertificateSelection cs = new CertificateSelection(this);
        try {
            Enumeration<String> aliases = signer_cert_keystore.aliases();
            while (aliases.hasMoreElements()) {
                String new_key = aliases.nextElement();
                if (signer_cert_keystore.isKeyEntry(new_key)) {
                    X509Certificate[] curr_path = getCertPath(new_key, path_expansion);
                    if (cfs.length == 0) {
                        cs.addEntry(new_key, curr_path[0]);
                        continue;
                    }
                    for (CertificateFilter cf : cfs) {
                        if (cf.matches(curr_path)) {
                            cs.addEntry(new_key, curr_path[0]);
                            break;  // No need to test other filters for this key; it is already selected
                        }
                    }
                }
            }
        } catch (GeneralSecurityException e) {
            throw new IOException(e.getMessage());
        }
        return cs;
    }


    @Override
    public X509Certificate[] getCertificatePath() throws IOException {
        try {
            X509Certificate[] path = getCertPath(key_alias, true);
            return extended_certpath ? path : new X509Certificate[]{path[0]};
        } catch (GeneralSecurityException e) {
            throw new IOException(e.getMessage());
        }
    }


    public KeyStoreSigner setECDSASignatureEncoding(boolean der_encoded) {
        ecdsa_der_encoded = der_encoded;
        return this;
    }


    public KeyStoreSigner setAuthorityInfoAccessCAIssuersHandler(AuthorityInfoAccessCAIssuersSpi aia_caissuer_handler) {
        this.aia_caissuer_handler = aia_caissuer_handler;
        return this;
    }


    @Override
    public byte[] signData(byte[] data, AsymSignatureAlgorithms algorithm) throws IOException {
        try {
            return new SignatureWrapper(algorithm,
                    private_key).setECDSASignatureEncoding(ecdsa_der_encoded)
                    .update(data)
                    .sign();
        } catch (GeneralSecurityException e) {
            throw new IOException(e);
        }
    }


    public KeyStoreSigner(KeyStore signer_cert_keystore, KeyContainerTypes container_type) {
        this.signer_cert_keystore = signer_cert_keystore;
    }


    public KeyStoreSigner setKey(String in_key_alias, String password) throws IOException {
        key_alias = in_key_alias;
        try {
            if (key_alias == null) {
                // Search for signer certificate/key:
                Enumeration<String> aliases = signer_cert_keystore.aliases();

                while (aliases.hasMoreElements()) {
                    String new_key = aliases.nextElement();
                    if (signer_cert_keystore.isKeyEntry(new_key)) {
                        if (key_alias != null) {
                            throw new IOException("Missing certificate alias and multiple matches");
                        }
                        key_alias = new_key;
                    }
                }
                if (key_alias == null) {
                    throw new IOException("No matching certificate");
                }
            } else {
                testKey(key_alias);
            }
            private_key = (PrivateKey) signer_cert_keystore.getKey(key_alias,
                    password == null ? null : password.toCharArray());
            return this;
        } catch (GeneralSecurityException e) {
            throw new IOException(e);
        }
    }


    public KeyStoreSigner setExtendedCertPath(boolean flag) {
        extended_certpath = flag;
        return this;
    }
}
