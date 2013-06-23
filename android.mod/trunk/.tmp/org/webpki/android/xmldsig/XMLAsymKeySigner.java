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
package org.webpki.android.xmldsig;

import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.PublicKey;

import org.webpki.android.crypto.SignatureAlgorithms;
import org.webpki.android.crypto.AsymKeySignerInterface;


public class XMLAsymKeySigner extends XMLSignerCore
  {

    AsymKeySignerInterface signer_impl;

    PublicKey populateKeys (XMLSignatureWrapper r) throws GeneralSecurityException, IOException
      {
        return r.public_key = signer_impl.getPublicKey ();
      }

    byte[] getSignatureBlob (byte[] data, SignatureAlgorithms sig_alg) throws GeneralSecurityException, IOException
      {
        return signer_impl.signData (data, sig_alg);
      }


    /**
     * Creates an XMLAsymKeySigner.
     */
    public XMLAsymKeySigner (AsymKeySignerInterface signer_impl)
      {
        this.signer_impl = signer_impl;
      }

  }
