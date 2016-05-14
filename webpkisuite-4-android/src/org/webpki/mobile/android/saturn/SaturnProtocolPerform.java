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
package org.webpki.mobile.android.saturn;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

import android.os.AsyncTask;
import android.webkit.JavascriptInterface;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;
import android.view.View;
import android.util.Log;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.json.JSONDecoder;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONParser;
import org.webpki.keygen2.KeyGen2URIs;
import org.webpki.mobile.android.R;
import org.webpki.mobile.android.saturn.SaturnActivity.Account;
import org.webpki.mobile.android.saturn.common.AccountDescriptor;
import org.webpki.mobile.android.saturn.common.BaseProperties;
import org.webpki.mobile.android.saturn.common.Encryption;
import org.webpki.mobile.android.saturn.common.PayerAuthorizationEncoder;
import org.webpki.mobile.android.saturn.common.PaymentRequest;
import org.webpki.mobile.android.saturn.common.WalletRequestDecoder;
import org.webpki.sks.EnumeratedKey;
import org.webpki.sks.Extension;
import org.webpki.sks.SKSException;
import org.webpki.sks.SecureKeyStore;


public class SaturnProtocolPerform extends AsyncTask<Void, String, Boolean> {
    private SaturnActivity saturnActivity;

    public SaturnProtocolPerform (SaturnActivity saturnActivity) {
        this.saturnActivity = saturnActivity;
    }

    @Override
    protected Boolean doInBackground (Void... params) {
        try {
            // Since user authorizations are pushed through the Payees they must be encrypted in order
            // to not leak user information to Payees.  Only the proper Payment Provider can decrypt
            // and process user authorizations.
            saturnActivity.postJSONData(
                saturnActivity.walletRequest.getAndroidTransactionUrl(),
                new PayerAuthorizationEncoder(saturnActivity.walletRequest.getPaymentRequest(),
                                              saturnActivity.authorizationData,
                                              saturnActivity.selectedCard.authorityUrl,
                                              saturnActivity.selectedCard.accountDescriptor.getAccountType(),
                                              saturnActivity.selectedCard.dataEncryptionAlgorithm,
                                              saturnActivity.selectedCard.keyEncryptionKey,
                                              saturnActivity.selectedCard.keyEncryptionAlgorithm),
                false);
    //        JSONDecoder jsonDecoder = saturnActivity.parseJSONResponse();

            return true;
        } catch (Exception e) {
            saturnActivity.logException(e);
        }
        return false;
    }

    @Override
    protected void onPostExecute(Boolean success) {
        if (saturnActivity.userHasAborted() || saturnActivity.initWasRejected()) {
            return;
        }
        saturnActivity.noMoreWorkToDo();
        if (success) {
            String url = saturnActivity.walletRequest.getAndroidSuccessUrl();
            if (url.equals("local")) {
                saturnActivity.done = true;
                saturnActivity.loadHtml("<tr><td>The operation was successful!</td></tr>");
            } else {    
                saturnActivity.launchBrowser(url);
            }
        } else {
            saturnActivity.showFailLog();
        }
    }
}
