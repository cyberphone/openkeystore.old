/*
 *  Copyright 2006-2015 WebPKI.org (http://webpki.org).
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

import java.security.PublicKey;

import java.util.Vector;

import android.annotation.SuppressLint;

import android.os.Bundle;

import android.util.Base64;
import android.util.DisplayMetrics;
import android.util.Log;

import android.webkit.JavascriptInterface;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.widget.Toast;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.AsymKeySignerInterface;
import org.webpki.crypto.AsymSignatureAlgorithms;

import org.webpki.json.JSONArrayReader;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONParser;

import org.webpki.mobile.android.R;

import org.webpki.mobile.android.proxy.BaseProxyActivity;

import org.webpki.mobile.android.saturn.common.AccountDescriptor;
import org.webpki.mobile.android.saturn.common.AuthorizationData;
import org.webpki.mobile.android.saturn.common.ChallengeResult;
import org.webpki.mobile.android.saturn.common.Encryption;
import org.webpki.mobile.android.saturn.common.WalletRequestDecoder;

import org.webpki.sks.KeyProtectionInfo;
import org.webpki.sks.SKSException;

import org.webpki.util.ArrayUtil;
import org.webpki.util.HTMLEncoder;

public class SaturnActivity extends BaseProxyActivity {

    public static final String SATURN = "Saturn";
    
    static final String LABEL_STYLE = "text-align:right;padding-right:3pt";
    
    static final String FIELD_STYLE = "padding:1pt 4pt 1pt 4pt;border-width:1px;border-style:solid;" +
                                      "border-color:#adadad;background-color:#f4fdf7";

    WalletRequestDecoder walletRequest;

    String payeeCommonName;
    
    String amountString;
    
    Account selectedCard;
    
    String pin = "";
    
    ChallengeResult[] challengeResults;
    
    byte[] dataEncryptionKey;
    
    JSONObjectWriter authorizationData;
    
    boolean done;
    
    SaturnView saturnView;
    int factor;
    StringBuffer standardHtml;
    DisplayMetrics displayMetrics;

    static class Account {
        AccountDescriptor accountDescriptor;
        boolean cardFormatAccountId;
        String cardSvgIcon;
        AsymSignatureAlgorithms signatureAlgorithm;
        String authorityUrl;
        int keyHandle;
        String dataEncryptionAlgorithm;
        String keyEncryptionAlgorithm;
        PublicKey keyEncryptionKey;

        Account(AccountDescriptor accountDescriptor,
                boolean cardFormatAccountId,
                String cardSvgIcon,
                int keyHandle,
                AsymSignatureAlgorithms signatureAlgorithm,
                String authorityUrl) {
            this.accountDescriptor = accountDescriptor;
            this.cardFormatAccountId = cardFormatAccountId;
            this.cardSvgIcon = cardSvgIcon;
            this.keyHandle = keyHandle;
            this.signatureAlgorithm = signatureAlgorithm;
            this.authorityUrl = authorityUrl;
        }
    }

    Vector<Account> cardCollection = new Vector<Account>();

    void loadHtml(String html) {
        saturnView.loadData(new StringBuffer(standardHtml).append(html).append("</table></td></tr></table></body></html>").toString(),
                            "text/html; charset=utf-8",
                            null);
    }
    
    @Override
    public void launchBrowser(String url) {
        if (url.startsWith("get:")) {
            new QRCancel(this, url.substring(4)).execute();
        } else {
            super.launchBrowser(url);
        }
    }

    @SuppressLint("SetJavaScriptEnabled")
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_saturn);
        saturnView = (SaturnView) findViewById(R.id.saturnMain);
        WebSettings webSettings = saturnView.getSettings();
        webSettings.setJavaScriptEnabled(true);
        saturnView.addJavascriptInterface (this, "Saturn");
        displayMetrics = new DisplayMetrics();
        getWindowManager().getDefaultDisplay().getMetrics(displayMetrics);
        factor = displayMetrics.densityDpi / 96;
        try {
            byte[] saturnLogo = ArrayUtil.getByteArrayFromInputStream(getResources().openRawResource(R.drawable.saturnlogo));
            standardHtml = new StringBuffer("<html><body><img src=\"data:image/png;base64,")
                .append(Base64.encodeToString(saturnLogo, Base64.NO_WRAP))
                .append("\" style=\"z-index:5;position:absolute\">" +
                        "<table cellpadding=\"0\" cellspacing=\"0\" width=\"100%\" height=\"100%\">" +
                        "<tr><td width=\"100%\" align=\"center\" valign=\"middle\"><table cellpadding=\"0\" cellspacing=\"0\">");
            loadHtml("<tr><td>Initializing...</td></tr>");
        } catch (Exception e) {
            unconditionalAbort("Saturn didn't initialize!");
            return;
        }

        showHeavyWork(PROGRESS_INITIALIZING);

        // Start of Saturn
        new SaturnProtocolInit(this).execute();
    }

    static String formatAccountId(Account card) {
        return card.cardFormatAccountId ?
            AuthorizationData.formatCardNumber(card.accountDescriptor.getAccountId()) 
                                        :
            card.accountDescriptor.getAccountId();
    }

    String htmlOneCard(Account account, String topStyle, String clickOption) {
        return new StringBuffer("<tr><td")
            .append(topStyle)
            .append("><div style=\"width:")
            .append(displayMetrics.widthPixels / factor)
            .append("px;height:")
            .append((displayMetrics.widthPixels * 6) / (10 * factor))
            .append("px\"")
            .append(clickOption)
            .append(">")
            .append(account.cardSvgIcon)
            .append("</div></td></tr><tr><td style=\"text-align:center;font-size:8pt;font-family:courier\">")
            .append(formatAccountId(account))
            .append("</td></tr>").toString();
    }

    void ShowPaymentRequest() {
        saturnView.numbericPin = true;
        StringBuffer payHtml = 
                new StringBuffer(htmlOneCard(selectedCard, "", ""));
            payHtml.append("<tr><td align=\"center\"><table style=\"margin-right:20pt\"><tr><td colspan=\"2\" style=\"height:25pt\"></td></tr>" +
                           "<tr><td style=\"" + LABEL_STYLE + "\">Payee</td><td style=\"" + FIELD_STYLE + "\">")
                   .append(HTMLEncoder.encode(payeeCommonName))
                   .append("</td><tr><td colspan=\"2\" style=\"height:5pt\"></td></tr>" +
                           "</tr><tr><td style=\"" + LABEL_STYLE + "\">Amount</td><td style=\"" + FIELD_STYLE + "\">")
                   .append(amountString)
                   .append("</td></tr><tr><td colspan=\"2\" style=\"height:5pt\"></td></tr>" +
                           "<tr><td style=\"" + LABEL_STYLE + "\">PIN</td><td style=\"padding:0\">" +
                           "<input id=\"pin\" type=\"password\" size=\"10\" style=\"padding:0;margin:0\" autofocus value=\"")
                   .append(HTMLEncoder.encode(pin))
                   .append("\"></td></tr>" +
                           "<tr><td colspan=\"2\" style=\"text-align:center;padding-top:20pt\">" +
                           "<input type=\"button\" value=\"Validate\" onClick=\"Saturn.performPayment(document.getElementById('pin').value)\"></td></tr>" +
                           "</table></td></tr>");
            loadHtml(payHtml.toString());
    }

    @JavascriptInterface
    public void selectCard(String index) {
        selectedCard = cardCollection.elementAt(Integer.parseInt(index));
        ShowPaymentRequest();
    }

    @JavascriptInterface
    public void getChallengeJSON(String json) {
        try {
            Vector<ChallengeResult> temp = new Vector<ChallengeResult>();
            JSONArrayReader challengeArray = JSONParser.parse(json).getJSONArrayReader();
             do {
                 JSONObjectReader challengeObject = challengeArray.getObject();
                 String id = challengeObject.getProperties()[0];
                 temp.add(new ChallengeResult(id, challengeObject.getString(id)));
            } while (challengeArray.hasMore());
            challengeResults = temp.toArray(new ChallengeResult[0]);
            ShowPaymentRequest();
            paymentEvent();
        } catch (Exception e) {
            unconditionalAbort("Challenge data read failure");
        }
    }

    boolean pinBlockCheck() throws SKSException {
        if (sks.getKeyProtectionInfo(selectedCard.keyHandle).isPinBlocked()) {
            unconditionalAbort("Card blocked due to previous PIN errors!");
            return true;
        }
        return false;
    }

    boolean userAuthorizationSucceeded() {
        try {
            if (pinBlockCheck()) {
                return false;
            }
            try {
                // User authorizations are always signed by a key that only needs to be
                // understood by the issuing Payment Provider (bank).
                ChallengeResult[] tempChallenge = challengeResults;
                challengeResults = null;
                authorizationData = AuthorizationData.encode(
                    walletRequest.getPaymentRequest(),
                    getRequestingHost(),
                    selectedCard.accountDescriptor,
                    dataEncryptionKey,
                    Encryption.JOSE_A128CBC_HS256_ALG_ID,
                    tempChallenge,
                    selectedCard.signatureAlgorithm,
                    new AsymKeySignerInterface () {
                        @Override
                        public PublicKey getPublicKey() throws IOException {
                            return sks.getKeyAttributes(selectedCard.keyHandle).getCertificatePath()[0].getPublicKey();
                        }
                        @Override
                        public byte[] signData(byte[] data, AsymSignatureAlgorithms algorithm) throws IOException {
                            return sks.signHashedData(selectedCard.keyHandle,
                                                      algorithm.getAlgorithmId (AlgorithmPreferences.SKS),
                                                      null,
                                                      new String(pin).getBytes("UTF-8"),
                                                      algorithm.getDigestAlgorithm().digest(data));
                        }
                    });
                Log.i(SATURN, "Authorization before encryption:\n" + authorizationData);
                return true;
            } catch (SKSException e) {
                if (e.getError() != SKSException.ERROR_AUTHORIZATION) {
                    throw new Exception(e);
                }
            }
            if (!pinBlockCheck()) {
                Log.w(SATURN, "Incorrect PIN");
                KeyProtectionInfo pi = sks.getKeyProtectionInfo(selectedCard.keyHandle);
                showAlert("Incorrect PIN. There are " +
                          (pi.getPinRetryLimit() - pi.getPinErrorCount()) +
                          " tries left.");
            }
            return false;
        } catch (Exception e) {
            unconditionalAbort(e.getMessage());
            return false;  
        }
    }

    void paymentEvent() {
        if (userAuthorizationSucceeded()) {

            showHeavyWork(PROGRESS_PAYMENT);

            // Threaded payment process
            new SaturnProtocolPerform(this).execute();
        }
    }

    @JavascriptInterface
    public void performPayment(String pin) {
        this.pin = pin;
        if (pin.isEmpty()) {
            Toast.makeText (getApplicationContext(), "Empty PIN, ignored", Toast.LENGTH_SHORT).show ();
        } else {
            paymentEvent();
        }
    }

    void showCardCollection() {
        StringBuffer html = new StringBuffer("<tr><td align=\"center\">Select Payment Card</td></tr>");
        int index = 0;
        for (SaturnActivity.Account account : cardCollection) {
            html.append(htmlOneCard(account,
                        " style=\"padding-top:10pt\"",
                        " onClick=\"Saturn.selectCard('" + (index++) + "')\""));
  
        }
        loadHtml(html.toString());
    }

    @Override
    protected String getProtocolName() {
        return SATURN;
    }

    @Override
    protected void abortTearDown() {
    }

    @Override
    public void onBackPressed() {
        if (done) {
            closeProxy();
        } else {
            if (selectedCard == null || cardCollection.size() == 1) {
                conditionalAbort(null);
            }
            selectedCard = null;
            showCardCollection();
        }
    }

    @Override
    protected String getAbortString() {
        return "Do you want to abort the payment process?";
    }
}
