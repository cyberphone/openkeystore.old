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

import org.webpki.json.JSONDecoder;
import org.webpki.json.JSONObjectReader;

public class WalletRequestDecoder extends JSONDecoder implements BaseProperties {

    private static final long serialVersionUID = 1L;
    
    PaymentRequest paymentRequest;
    public PaymentRequest getPaymentRequest() {
        return paymentRequest;
    }

    String[] accountTypes;
    public String[] getAccountTypes() {
        return accountTypes;
    }

    String androidCancelUrl;
    public String getAndroidCancelUrl() {
        return androidCancelUrl;
    }

    String androidSuccessUrl;
    public String getAndroidSuccessUrl() {
        return androidSuccessUrl;
    }

    String androidTransactionUrl;
    public String getAndroidTransactionUrl() {
        return androidTransactionUrl;
    }

    @Override
    protected void readJSONData(JSONObjectReader rd) throws IOException {
        accountTypes = rd.getStringArray(ACCEPTED_ACCOUNT_TYPES_JSON);
        paymentRequest = new PaymentRequest(rd.getObject(PAYMENT_REQUEST_JSON));
        androidCancelUrl = rd.getString(ANDROID_CANCEL_URL_JSON);
        androidSuccessUrl = rd.getString(ANDROID_SUCCESS_URL_JSON);
        androidTransactionUrl = rd.getString(ANDROID_TRANSACTION_URL_JSON);
    }

    @Override
    public String getContext() {
        return SATURN_WEB_PAY_CONTEXT_URI;
    }

    @Override
    public String getQualifier() {
        return Messages.WALLET_REQUEST.toString ();
    }
}
