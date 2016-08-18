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

import android.annotation.SuppressLint;

import android.content.res.Configuration;

import android.os.Bundle;

import android.util.Base64;
import android.util.DisplayMetrics;
import android.util.Log;

import android.webkit.JavascriptInterface;
import android.webkit.WebSettings;
import android.widget.Toast;

import org.webpki.mobile.android.R;

import java.io.IOException;

import java.security.PublicKey;

import java.util.Vector;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.AsymKeySignerInterface;
import org.webpki.crypto.AsymSignatureAlgorithms;

import org.webpki.json.JSONArrayReader;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONParser;

import org.webpki.json.encryption.DataEncryptionAlgorithms;
import org.webpki.json.encryption.KeyEncryptionAlgorithms;

import org.webpki.mobile.android.proxy.BaseProxyActivity;

import org.webpki.mobile.android.saturn.common.AccountDescriptor;
import org.webpki.mobile.android.saturn.common.AuthorizationData;
import org.webpki.mobile.android.saturn.common.ChallengeResult;
import org.webpki.mobile.android.saturn.common.PaymentRequest;
import org.webpki.mobile.android.saturn.common.WalletRequestDecoder;

import org.webpki.sks.KeyProtectionInfo;
import org.webpki.sks.SKSException;

import org.webpki.util.ArrayUtil;
import org.webpki.util.HTMLEncoder;

public class SaturnActivity extends BaseProxyActivity {

    public static final String SATURN = "Saturn";
    
    static final String HTML_HEADER = "<html><head><style type='text/css'>\n" +
                                      "body {margin:0;font-size:12pt;color:#000000;font-family:Roboto;background-color:white}\n" +
                                      "td.label {text-align:right;padding:2pt 3pt 3pt 0pt}\n" +
                                      "td.field {padding:2pt 6pt 3pt 6pt;border-width:1px;" +
                                      "border-style:solid;border-color:#808080;background-color:#fafafa;min-width:10em}\n" +
                                      "td.pan {text-align:center;padding:5pt 0 0 0;font-size:9pt;font-family:monospace}\n" +
                                      "div.cardimage {border-style:groove;border-width:2px;border-color:#c0c0c0;border-radius:15px;" +
                                      "box-shadow:5px 5px 5px #d0d0d0;background-size:cover;background-repeat:no-repeat}\n" +
                                      "</style>\n" +
                                      "<script type='text/javascript'>\n" +
                                      "function positionElements() {\n";

    String htmlBodyPrefix;
 
    boolean landscapeMode;
    
    WalletRequestDecoder walletRequest;
    
    enum FORM {INITIALIZE, COLLECTION, PAYMENTREQUEST};
    
    FORM currentForm = FORM.INITIALIZE;

    Account selectedCard;
    
    String pin = "";
    
    ChallengeResult[] challengeResults;
    
    byte[] dataEncryptionKey;
    
    String keyboardSvg;
    
    JSONObjectWriter authorizationData;
    
    boolean done;
    
    SaturnView saturnView;
    int factor;
    DisplayMetrics displayMetrics;

    static class Account {
        PaymentRequest paymentRequest;
        AccountDescriptor accountDescriptor;
        boolean cardFormatAccountId;
        byte[] cardSvgIcon;
        AsymSignatureAlgorithms signatureAlgorithm;
        String authorityUrl;
        int keyHandle;
        DataEncryptionAlgorithms dataEncryptionAlgorithm;
        KeyEncryptionAlgorithms keyEncryptionAlgorithm;
        PublicKey keyEncryptionKey;

        Account(PaymentRequest paymentRequest,
                AccountDescriptor accountDescriptor,
                boolean cardFormatAccountId,
                byte[] cardSvgIcon,
                int keyHandle,
                AsymSignatureAlgorithms signatureAlgorithm,
                String authorityUrl) {
            this.paymentRequest = paymentRequest;
            this.accountDescriptor = accountDescriptor;
            this.cardFormatAccountId = cardFormatAccountId;
            this.cardSvgIcon = cardSvgIcon;
            this.keyHandle = keyHandle;
            this.signatureAlgorithm = signatureAlgorithm;
            this.authorityUrl = authorityUrl;
        }
    }

    Vector<Account> cardCollection = new Vector<Account>();

    void loadHtml(String positionScript, String body) {
        final String positionScriptArgument = positionScript;
        final String bodyArgument = body;
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                 String html = new StringBuffer(HTML_HEADER)
                    .append(positionScriptArgument)
                    .append(htmlBodyPrefix)
                    .append(bodyArgument)
                    .append("</body></html>").toString();
               Log.i(SATURN,html);
               saturnView.loadData(html, "text/html; charset=utf-8", null);
               saturnView.reload();
            }
        });
    } 
    
    @Override
    public void launchBrowser(String url) {
        if (url.startsWith("get:")) {
            new QRCancel(this, url.substring(4)).execute();
        } else {
            super.launchBrowser(url);
        }
    }

    @Override
    public void onConfigurationChanged(Configuration newConfig) {
        super.onConfigurationChanged(newConfig);
        // Checks the orientation of the screen
        if (newConfig.orientation == Configuration.ORIENTATION_LANDSCAPE) {
            landscapeMode = true;
        } else if (newConfig.orientation == Configuration.ORIENTATION_PORTRAIT) {
            landscapeMode = false;
        } else {
            return;
        }
        displayMetrics = new DisplayMetrics();
        getWindowManager().getDefaultDisplay().getMetrics(displayMetrics);
        switch (currentForm) {
            case COLLECTION:
                showCardCollection();
                break;

            case PAYMENTREQUEST:
                try {
                    ShowPaymentRequest();
                } catch (IOException e) {
                }
                break;

            case INITIALIZE:
            default:
                break;
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
        factor = (int)(displayMetrics.density * 100);
        landscapeMode = getResources().getConfiguration().orientation == Configuration.ORIENTATION_LANDSCAPE;
        Log.i(SATURN,"LS" + landscapeMode);
        try {
            keyboardSvg = new String(ArrayUtil.getByteArrayFromInputStream(getResources()
                    .openRawResource(R.raw.pinkeyboard)), "utf-8");
            htmlBodyPrefix = new StringBuffer("}\n" +
                                              "</script>" +
                                              "</head><body onload=\"positionElements()\">" +
                                              "<img src='data:image/png;base64,")
                .append(Base64.encodeToString(ArrayUtil.getByteArrayFromInputStream(getResources()
                                                  .openRawResource(R.drawable.saturnlogo)),
                                              Base64.NO_WRAP))
                .append("'>").toString();
             loadHtml("var init = document.getElementById('init');\n" +
                      "init.style.top = ((window.innerHeight - init.offsetHeight) / 2) + 'px';\n" +
                      "init.style.visibility='visible';\n",
                      "<div id='init' style='visibility:hidden;position:absolute;width:100%;text-align:center'>Initializing...</div>");
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

    String htmlOneCard(Account account, int width, String card, String clickOption) {
        return new StringBuffer("<table id='")
            .append(card)
            .append("' style='visibility:hidden;position:absolute'><tr><td><div class='cardimage' style='width:")
            .append((width * 100) / factor)
            .append("px;height:")
            .append((width * 60) / factor)
            .append("px;background-image:url(data:image/svg+xml;base64,")
            .append(Base64.encodeToString(account.cardSvgIcon, Base64.NO_WRAP))
            .append(")'")
            .append(clickOption)
            .append("></div></td></tr><tr><td class='pan'>")
            .append(formatAccountId(account))
            .append("</td></tr></table>").toString();
    }

    void ShowPaymentRequest() throws IOException {
        currentForm = FORM.PAYMENTREQUEST;
        int width = displayMetrics.widthPixels;
        StringBuffer js = new StringBuffer(
            "var card = document.getElementById('card');\n" +
            "var paydata = document.getElementById('paydata');\n" +
            "var payfield = document.getElementById('payfield');\n" +
            "var kbd = document.getElementById('kbd');\n" +
            "card.style.left = ((window.innerWidth - card.offsetWidth) / 2) + 'px';\n" +
            "paydata.style.left = ((window.innerWidth - paydata.offsetWidth - payfield.offsetWidth) / 2) + 'px';\n" +
            "var kbdTop = window.innerHeight - Math.floor(kbd.offsetHeight * 1.26);\n" +
            "kbd.style.top = kbdTop + 'px';\n" +
            "kbd.style.left = ((window.innerWidth - kbd.offsetWidth) / 2) + 'px';\n" +
            "var gutter = (kbdTop - card.offsetHeight - paydata.offsetHeight) / 7;\n" +
            "card.style.top = gutter * 3 + 'px';\n" +
            "paydata.style.top = (5 * gutter + card.offsetHeight) + 'px';\n" +
            "card.style.visibility='visible';\n" +
            "paydata.style.visibility='visible';\n" +
            "kbd.style.visibility='visible';\n");
        StringBuffer html = new StringBuffer(
            "<table id='paydata' style='visibility:hidden;position:absolute'>" +
            "<tr><td id='payfield' class='label'>Payee</td><td class='field'>Demo Merchant</td></tr>" +
            "<tr><td colspan='2' style='height:5pt'></td></tr>" +
            "<tr><td class='label'>Amount</td><td class='field'>$1,999.25</td></tr>" + 
            "<tr><td colspan='2' style='height:5pt'></td></tr>" +
            "<tr><td class='label'>PIN</td><td class='field' style='background-color:white;border-color:#0000ff'>****</td></tr>" +
            "</table>" + 
            "<div id='kbd' style='visibility:hidden;position:absolute;width:")
          .append((width * 86) / factor)
          .append("px;height:")
          .append((width * ((86 * 150) / 404)) / factor)
          .append("'>")
          .append(keyboardSvg)
          .append("</div>");
         saturnView.numbericPin = true;
        html.append(htmlOneCard(selectedCard, (width * 3) / 5, "card", ""));
/*
        payHtml.append("<tr><td align=\"center\"><table style=\"margin-right:20pt\"><tr><td colspan=\"2\" style=\"height:25pt\"></td></tr>" +
                           "<tr><td style=\"" + LABEL_STYLE + "\">Payee</td><td style=\"" + FIELD_STYLE + "\">")
                   .append(HTMLEncoder.encode(selectedCard.paymentRequest.getPayee().getCommonName()))
                   .append("</td><tr><td colspan=\"2\" style=\"height:5pt\"></td></tr>" +
                           "</tr><tr><td style=\"" + LABEL_STYLE + "\">Amount</td><td style=\"" + FIELD_STYLE + "\">")
                   .append(selectedCard.paymentRequest.getCurrency().amountToDisplayString(selectedCard.paymentRequest.getAmount()))
                   .append("</td></tr><tr><td colspan=\"2\" style=\"height:5pt\"></td></tr>" +
                           "<tr><td style=\"" + LABEL_STYLE + "\">PIN</td><td style=\"padding:0\">" +
                           "<input id=\"pin\" type=\"password\" size=\"10\" style=\"padding:0;margin:0\" autofocus value=\"")
                   .append(HTMLEncoder.encode(pin))
                   .append("\"></td></tr>" +
                           "<tr><td colspan=\"2\" style=\"text-align:center;padding-top:20pt\">" +
                           "<input type=\"button\" value=\"Validate\" onClick=\"Saturn.performPayment(document.getElementById('pin').value)\"></td></tr>" +
                           "</table></td></tr>");
*/
        loadHtml(js.toString(), html.toString());
    }

    void showCardCollection() {
        currentForm = FORM.COLLECTION;
        StringBuffer js = new StringBuffer("var header = document.getElementById('header');\n");
        StringBuffer html = 
            new StringBuffer("<div id='header' style='visibility:hidden;position:absolute;width:100%;text-align:center'>Select Payment Card</div>");
        int width = displayMetrics.widthPixels;
        int index = 0;
        for (SaturnActivity.Account account : cardCollection) {
            String card = "card" + String.valueOf(index);
            js.append("var " + card + " = document.getElementById('" + card + "');\n");
            if (index == 0) {
                js.append("var next = ")
                  .append(landscapeMode ? 
                          "(window.innerHeight - " + card + ".offsetHeight) / 2;\n" 
                                        :
                          "(window.innerHeight - Math.floor(" + card + ".offsetHeight * 2.3)) / 2;\n");
                js.append("header.style.top = (next - header.offsetHeight) / 2 + 'px';\n");
            }
            js.append(card + ".style.top = next;\n");
            if (landscapeMode) {
                double left = 1.0 / 11;
                if (index % 2 == 1) {
                    js.append("next += Math.floor(" + card + ".offsetHeight * 1.3);\n");
                    left = 6.0 / 11;
                }
                js.append(card + ".style.left = Math.floor(window.innerWidth * " + String.valueOf(left) + ") + 'px';\n");
            } else {
                js.append(card + ".style.left = ((window.innerWidth - " + card + ".offsetWidth) / 2) + 'px';\n" +
                          "next += Math.floor(" + card + ".offsetHeight * 1.3);\n");
            }
            js.append(card + ".style.visibility = 'visible';\n");
            html.append(htmlOneCard(account,
                                    landscapeMode ? (width * 4) / 11 : (width * 3) / 5,
                                    card,
                                    " onClick=\"Saturn.selectCard('" + (index++) + "')\""));
        }
        js.append("header.style.visibility='visible';\n");
        loadHtml(js.toString(), html.toString());
    }

    @JavascriptInterface
    public void selectCard(String index) throws IOException {
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
                    selectedCard.paymentRequest,
                    getRequestingHost(),
                    selectedCard.accountDescriptor,
                    dataEncryptionKey,
                    DataEncryptionAlgorithms.JOSE_A128CBC_HS256_ALG_ID,
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
