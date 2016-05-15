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

import android.os.AsyncTask;

import android.util.Log;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.AsymSignatureAlgorithms;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONParser;

import org.webpki.keygen2.KeyGen2URIs;

import org.webpki.mobile.android.saturn.SaturnActivity.Account;

import org.webpki.mobile.android.saturn.common.AccountDescriptor;
import org.webpki.mobile.android.saturn.common.BaseProperties;
import org.webpki.mobile.android.saturn.common.Encryption;
import org.webpki.mobile.android.saturn.common.PaymentRequest;
import org.webpki.mobile.android.saturn.common.ProviderUserResponseDecoder;
import org.webpki.mobile.android.saturn.common.WalletAlertDecoder;
import org.webpki.mobile.android.saturn.common.WalletRequestDecoder;
import org.webpki.mobile.android.saturn.common.WalletSuccessDecoder;

import org.webpki.sks.EnumeratedKey;
import org.webpki.sks.Extension;
import org.webpki.sks.SKSException;
import org.webpki.sks.SecureKeyStore;


public class SaturnProtocolInit extends AsyncTask<Void, String, Boolean> {
    private SaturnActivity saturnActivity;

    public SaturnProtocolInit (SaturnActivity saturnActivity) {
        this.saturnActivity = saturnActivity;
    }

    @Override
    protected Boolean doInBackground (Void... params) {
        try {
            saturnActivity.getProtocolInvocationData();
            saturnActivity.addDecoder(WalletRequestDecoder.class);
            saturnActivity.addDecoder(WalletSuccessDecoder.class);
            saturnActivity.addDecoder(WalletAlertDecoder.class);
            saturnActivity.addDecoder(ProviderUserResponseDecoder.class);
            saturnActivity.walletRequest = (WalletRequestDecoder) saturnActivity.getInitialReguest();
            saturnActivity.setAbortURL(saturnActivity.walletRequest.getAndroidCancelUrl());

            // Primary information to the user...
            PaymentRequest paymentRequest = saturnActivity.walletRequest.getPaymentRequest();
            saturnActivity.amountString = paymentRequest.getCurrency()
                .amountToDisplayString(paymentRequest.getAmount());
            saturnActivity.payeeCommonName = paymentRequest.getPayee().getCommonName();

            // Enumerate keys but only go for those who are intended for
            // Web Payments (according to our fictitious payment schemes...)
            EnumeratedKey ek = new EnumeratedKey();
            while ((ek = saturnActivity.sks.enumerateKeys(ek.getKeyHandle())) != null) {
                Extension ext = null;
                try {
                    ext = saturnActivity.sks.getExtension(ek.getKeyHandle(),
                                                          BaseProperties.SATURN_WEB_PAY_CONTEXT_URI);
                } catch (SKSException e) {
                    if (e.getError() == SKSException.ERROR_OPTION) {
                        continue;
                    }
                    throw new Exception(e);
                }

                // This key had the attribute signifying that it is a payment credential
                // for the fictitious payment schemes this system is supporting but it
                // might still not match the Payee's list of supported account types.
                collectPotentialCard(ek.getKeyHandle(),
                                     JSONParser.parse(ext.getExtensionData(SecureKeyStore.SUB_TYPE_EXTENSION)),
                                     saturnActivity.walletRequest.getAccountTypes());

                // The key we use for decrypting private information from our bank
                saturnActivity.dataEncryptionKey = 
                    Encryption.generateDataEncryptionKey(Encryption.JOSE_A128CBC_HS256_ALG_ID);

            }
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
            if (saturnActivity.cardCollection.isEmpty()) {
                saturnActivity.loadHtml("<tr><td style=\"padding:20pt\"><p>You do not seem to have any payment cards.</p>" +
                                         "For a selection of test cards, you can enroll such at the Saturn proof-of-concept site.</td></tr>");
            } else if (saturnActivity.cardCollection.size () == 1) {
                saturnActivity.showPaymentRequest("0");
            } else {
                saturnActivity.showCardCollection();
            }
        } else {
            saturnActivity.showFailLog();
        }
    }

    void collectPotentialCard(int keyHandle, JSONObjectReader cardProperties, String[] accountTypes) throws IOException {
        AccountDescriptor cardAccount = new AccountDescriptor(cardProperties.getObject(BaseProperties.ACCOUNT_JSON));
        for (String accountType : accountTypes) {
            if (cardAccount.getAccountType().equals(accountType)) {
                Account card =
                    new Account(cardAccount,
                                cardProperties.getBoolean(BaseProperties.CARD_FORMAT_ACCOUNT_ID_JSON),
                                new String(saturnActivity.sks.getExtension(keyHandle, KeyGen2URIs.LOGOTYPES.CARD)
                                    .getExtensionData(SecureKeyStore.SUB_TYPE_LOGOTYPE), "UTF-8"),
                                keyHandle,
                                AsymSignatureAlgorithms
                                    .getAlgorithmFromID(cardProperties.getString(BaseProperties.SIGNATURE_ALGORITHM_JSON),
                                                        AlgorithmPreferences.JOSE),
                                cardProperties.getString(BaseProperties.PROVIDER_AUTHORITY_URL_JSON));
                JSONObjectReader encryptionParameters = cardProperties.getObject(BaseProperties.ENCRYPTION_PARAMETERS_JSON);
                card.keyEncryptionAlgorithm = encryptionParameters.getString(BaseProperties.KEY_ENCRYPTION_ALGORITHM_JSON);
                if (!Encryption.permittedKeyEncryptionAlgorithm(card.keyEncryptionAlgorithm)) {
                    Log.w(SaturnActivity.SATURN,
                          "Account " + cardAccount.getAccountId() + " contained an unknown \"" +
                              BaseProperties.KEY_ENCRYPTION_ALGORITHM_JSON + "\": " + card.keyEncryptionAlgorithm);
                    break;
                }
                card.dataEncryptionAlgorithm = encryptionParameters.getString (BaseProperties.DATA_ENCRYPTION_ALGORITHM_JSON);
                if (!Encryption.permittedDataEncryptionAlgorithm (card.dataEncryptionAlgorithm)) {
                    Log.w(SaturnActivity.SATURN,
                          "Account " + cardAccount.getAccountId () + " contained an unknown \"" +
                              BaseProperties.DATA_ENCRYPTION_ALGORITHM_JSON + "\": " + card.dataEncryptionAlgorithm);
                    break;
                }
                card.keyEncryptionKey = encryptionParameters.getPublicKey(AlgorithmPreferences.JOSE);

                // We found a useful card!
                saturnActivity.cardCollection.add(card);
                break;
            }
        }
    }
}
