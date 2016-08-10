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

import android.os.AsyncTask;

import org.webpki.json.JSONDecoder;

import org.webpki.json.encryption.DataEncryptionAlgorithms;

import org.webpki.mobile.android.saturn.common.ChallengeField;
import org.webpki.mobile.android.saturn.common.PayerAuthorizationEncoder;
import org.webpki.mobile.android.saturn.common.ProviderUserResponseDecoder;
import org.webpki.mobile.android.saturn.common.WalletAlertDecoder;

import org.webpki.util.HTMLEncoder;

public class SaturnProtocolPerform extends AsyncTask<Void, String, Boolean> {
    private SaturnActivity saturnActivity;

    public SaturnProtocolPerform (SaturnActivity saturnActivity) {
        this.saturnActivity = saturnActivity;
    }
    
    ProviderUserResponseDecoder.PrivateMessage privateMessage;
    
    String merchantHtmlAlert;

    @Override
    protected Boolean doInBackground (Void... params) {
        try {
            // Since user authorizations are pushed through the Payees they must be encrypted in order
            // to not leak user information to Payees.  Only the proper Payment Provider can decrypt
            // and process user authorizations.
            saturnActivity.postJSONData(
                saturnActivity.walletRequest.getAndroidTransactionUrl(),
                new PayerAuthorizationEncoder(saturnActivity.selectedCard.paymentRequest,
                                              saturnActivity.authorizationData,
                                              saturnActivity.selectedCard.authorityUrl,
                                              saturnActivity.selectedCard.accountDescriptor.getAccountType(),
                                              saturnActivity.selectedCard.dataEncryptionAlgorithm,
                                              saturnActivity.selectedCard.keyEncryptionKey,
                                              saturnActivity.selectedCard.keyEncryptionAlgorithm),
                false);
            JSONDecoder returnMessage = saturnActivity.parseJSONResponse();
            if (returnMessage instanceof ProviderUserResponseDecoder) {
                privateMessage =
                    ((ProviderUserResponseDecoder)returnMessage)
                        .getPrivateMessage(saturnActivity.dataEncryptionKey, 
                                           DataEncryptionAlgorithms.JOSE_A128CBC_HS256_ALG_ID);
                return true;
            } else if (returnMessage instanceof WalletAlertDecoder) {
                merchantHtmlAlert = ((WalletAlertDecoder)returnMessage).getText();
                return true;
            }
        } catch (Exception e) {
            saturnActivity.logException(e);
            return null;
        }
        return false;
    }

    StringBuffer header(String party, String message) {
        return new StringBuffer("<tr><td style=\"text-align:center\">Message from <b><i>")
            .append(HTMLEncoder.encode(party))
            .append("</i></b></td></tr><tr><td style=\"padding-top:20pt\">")
            .append(message.replace("${width}", "100%").replace("${submit}", "Validate"))
            .append("</td></tr>");
    }

    @Override
    protected void onPostExecute(Boolean alertUser) {
        if (saturnActivity.userHasAborted() || saturnActivity.initWasRejected()) {
            return;
        }
        saturnActivity.noMoreWorkToDo();
        if (alertUser == null) {
            saturnActivity.showFailLog();
        } else if (alertUser) {
            saturnActivity.saturnView.numbericPin = false;
            StringBuffer text = new StringBuffer();
            if (merchantHtmlAlert == null) {
                text.append(header(privateMessage.getCommonName(), privateMessage.getText()));
                if (privateMessage.getOptionalChallengeFields() != null) {
                    text.append("<script type=\"text/javascript\">\n" +
                                "function getChallengeData() {\n" +
                                "  var data = [];\n");
                    for (ChallengeField challengeField : privateMessage.getOptionalChallengeFields()) {
                        text.append("  data.push({'")
                            .append(challengeField.getId())
                            .append("': document.getElementById('")
                            .append(challengeField.getId())
                            .append("').value});\n");
                    }
                    text.append("  return JSON.stringify(data);\n" +
                                "}\n" +
                                "</script>");
                    for (ChallengeField challengeField : privateMessage.getOptionalChallengeFields()) {
                        text.append("<tr><td style=\"padding-top:10pt\">");
                        if (challengeField.getOptionalLabel() != null) {
                            text.append(challengeField.getOptionalLabel())
                                .append(":<br>");
                        }
                        text.append("<input type=\"password\" id=\"")
                            .append(challengeField.getId())
                            .append("\" size=\"")
                            .append(challengeField.getLength())
                            .append("\"></td></tr>");
                    }
                    text.append("<tr><td style=\"text-align:center;padding-top:20pt\">" +
                                "<input type=\"button\" value=\"Validate\" onClick=\"Saturn.getChallengeJSON(getChallengeData())\"></td></tr>");
                }
             } else {
                 text.append(header(saturnActivity.selectedCard == null ?
                         "Unknown" : saturnActivity.selectedCard.paymentRequest.getPayee().getCommonName(),
                                    merchantHtmlAlert));
            }
            saturnActivity.loadHtml(text.toString());
       } else {
            String url = saturnActivity.walletRequest.getAndroidSuccessUrl();
            if (url.equals("local")) {
                saturnActivity.done = true;
                saturnActivity.loadHtml("<tr><td>The operation was successful!</td></tr>");
            } else {    
                saturnActivity.launchBrowser(url);
            }
        }
    }
}
