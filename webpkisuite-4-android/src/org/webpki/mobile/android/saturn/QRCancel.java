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

import org.webpki.net.HTTPSWrapper;

public class QRCancel extends AsyncTask<Void, String, Boolean> {
    private SaturnActivity saturnActivity;
    private String cancelUrl;

    public QRCancel (SaturnActivity saturnActivity, String cancelUrl) {
        this.saturnActivity = saturnActivity;
        this.cancelUrl = cancelUrl;
    }

    @Override
    protected Boolean doInBackground (Void... params) {
        try {
            new HTTPSWrapper().makeGetRequest(cancelUrl);
        } catch (Exception e) {
        }
        return true;
    }

    @Override
    protected void onPostExecute(Boolean success) {
        saturnActivity.done = true;
//        saturnActivity.loadHtml("<tr><td>The operation was cancelled</td></tr>");
    }
}
