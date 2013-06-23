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
package org.webpki.android.wasp;

import java.io.IOException;

import java.util.Vector;

import org.webpki.android.crypto.VerifierInterface;
import org.webpki.android.crypto.CertificateFilter;


public interface SignatureProfileResponseDecoder
  {

    void verifySignature (VerifierInterface verifier) throws IOException;

    boolean match (SignatureProfileEncoder spreenc,
                   DocumentData doc_data,
                   DocumentReferences doc_refs,
                   Vector<CertificateFilter> cert_filters,
                   String id,
                   byte[] expected_fingerprint) throws IOException;

  }
