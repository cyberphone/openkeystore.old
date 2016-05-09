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

import java.security.PublicKey;
import java.util.LinkedHashMap;

import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.webkit.WebView;

import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.mobile.android.R;
import org.webpki.mobile.android.proxy.BaseProxyActivity;
import org.webpki.mobile.android.saturn.common.AccountDescriptor;
import org.webpki.mobile.android.saturn.common.WalletRequestDecoder;

public class SaturnActivity extends BaseProxyActivity {

    public static final String SATURN = "Saturn";

    WalletRequestDecoder walletRequest;

    String payeeCommonName;

    String amountString;
    
    WebView saturnView;

    static class Account {
        AccountDescriptor accountDescriptor;
        boolean cardFormatAccountId;
        byte[] cardIcon;
        AsymSignatureAlgorithms signatureAlgorithm;
        String authorityUrl;
        String dataEncryptionAlgorithm;
        String keyEncryptionAlgorithm;
        PublicKey keyEncryptionKey;

        Account(AccountDescriptor accountDescriptor,
                boolean cardFormatAccountId,
                byte[] cardIcon,
                AsymSignatureAlgorithms signatureAlgorithm,
                String authorityUrl) {
            this.accountDescriptor = accountDescriptor;
            this.cardFormatAccountId = cardFormatAccountId;
            this.cardIcon = cardIcon;
            this.signatureAlgorithm = signatureAlgorithm;
            this.authorityUrl = authorityUrl;
        }
    }

    LinkedHashMap<Integer,Account> cardCollection = new LinkedHashMap<Integer,Account>();

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_saturn);
        saturnView = (WebView) findViewById(R.id.saturnMain);
        StringBuffer log_message = new StringBuffer("<html><body>Hi There!");
        saturnView.loadData(log_message.append ("</body></html>").toString (), "text/html", null);

        showHeavyWork (PROGRESS_INITIALIZING);

        // Start of Saturn
        new SaturnProtocolInit(this).execute();
    }

    @Override
    protected String getProtocolName() {
        return SATURN;
    }

    @Override
    protected void abortTearDown() {
/*
        if (provisioning_handle != 0)
          {
            try
              {
                sks.abortProvisioningSession (provisioning_handle);
              }
            catch (Exception e)
              {
                Log.e (SATURN, "Failed to abort SKS session");
              }
          }
*/
    }

    @Override
    public void onBackPressed() {
        conditionalAbort(null);
    }

    @Override
    protected String getAbortString() {
        return "Do you want to abort the payment process?";
    }
}
