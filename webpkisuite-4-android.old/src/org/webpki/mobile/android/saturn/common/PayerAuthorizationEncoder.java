/*
 *  Copyright 2006-2016 WebPKI.org (http://webpki.org).
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
package org.webpki.mobile.android.saturn.common;

import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.PublicKey;

import org.webpki.json.JSONEncoder;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;

import org.webpki.json.encryption.DataEncryptionAlgorithms;
import org.webpki.json.encryption.KeyEncryptionAlgorithms;

public class PayerAuthorizationEncoder extends JSONEncoder implements BaseProperties {
    
    private static final long serialVersionUID = 1L;

    String providerAuthorityUrl;

    String accountType;

    PaymentRequest paymentRequest;
    
    JSONObjectWriter encryptedData;

    public PayerAuthorizationEncoder(PaymentRequest paymentRequest,
                                     JSONObjectWriter unencryptedAuthorizationData,
                                     String providerAuthorityUrl,
                                     String accountType,
                                     DataEncryptionAlgorithms dataEncryptionAlgorithm,
                                     PublicKey keyEncryptionKey,
                                     KeyEncryptionAlgorithms keyEncryptionAlgorithm) throws GeneralSecurityException, IOException {
        this.providerAuthorityUrl = providerAuthorityUrl;
        this.accountType = accountType;
        this.paymentRequest = paymentRequest;
        this.encryptedData = new JSONObjectWriter()
            .setEncryptionObject(unencryptedAuthorizationData.serializeJSONObject(JSONOutputFormats.NORMALIZED),
                                 dataEncryptionAlgorithm,
                                 keyEncryptionKey,
                                 keyEncryptionAlgorithm);
    }

    @Override
    protected void writeJSONData(JSONObjectWriter wr) throws IOException {
        wr.setString(PROVIDER_AUTHORITY_URL_JSON, providerAuthorityUrl)
          .setString(ACCOUNT_TYPE_JSON, accountType)
          .setObject(PAYMENT_REQUEST_JSON, paymentRequest.root)
          .setObject(ENCRYPTED_AUTHORIZATION_JSON, encryptedData);
    }

    @Override
    public String getContext() {
        return SATURN_WEB_PAY_CONTEXT_URI;
    }

    @Override
    public String getQualifier() {
        return Messages.PAYER_AUTHORIZATION.toString();
    }
}
