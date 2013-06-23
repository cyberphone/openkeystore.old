/*
 *  Copyright 2006-2012 WebPKI.org (http://webpki.org).
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
package org.webpki.mobile.android.proxy;

import org.webpki.mobile.android.R;

import android.os.Bundle;

import android.webkit.WebView;

import android.app.Activity;

import android.content.Intent;

public class FailLoggerActivity extends Activity
  {

    public static final String LOG_MESSAGE = "log";

    @Override
    public void onCreate (Bundle savedInstanceState)
      {
        super.onCreate (savedInstanceState);
        setContentView (R.layout.activity_fail_logger);
        WebView log_view = (WebView) findViewById (R.id.failedData);
        Intent intent = getIntent ();
        StringBuffer log_message = new StringBuffer ("<html><body><pre>");
        for (char c : intent.getStringExtra (LOG_MESSAGE).toCharArray ())
          {
            if (c == '\n')
              {
                log_message.append ("%0A");
              }
            else
              {
                log_message.append (c);
              }
          }
        log_view.loadData (log_message.append ("</pre></body></html>").toString (), "text/html", null);
      }
  }
