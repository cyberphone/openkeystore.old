/*
 *  Copyright 2006-2013 WebPKI.org (http://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
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

import java.security.cert.X509Certificate;


/**
 * PKI signature interface.
 * Note that the actual key, certificate path, and signature creation mechanism are supposed to
 * be hosted by the implementing class.
 */
public interface SignerInterface
  {

    /**
     * Returns the certificate path associated with the key.
     */
    public X509Certificate[] prepareSigning (boolean fullpath) throws IOException;

    /**
     * Signs data using the key.
     */
    public byte[] signData (byte[] data, SignatureAlgorithms algorithm) throws IOException;

    /**
     * Returns a descriptor of the signer certificate.
     */
    public CertificateInfo getSignerCertificateInfo () throws IOException;
    
    /**
     * Tests if a signature operation failed due to authorization errors.
     * 
     * @return true if the key wasn't authorized (wrong PIN)
     * @throws IOException
     */
    public boolean authorizationFailed () throws IOException;

  }
