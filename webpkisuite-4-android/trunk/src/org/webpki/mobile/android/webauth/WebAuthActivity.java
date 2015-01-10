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
package org.webpki.mobile.android.webauth;

import java.util.LinkedHashMap;

import android.os.Bundle;

import org.webpki.mobile.android.R;

import org.webpki.mobile.android.proxy.BaseProxyActivity;

import org.webpki.crypto.AsymSignatureAlgorithms;


import org.webpki.webauth.AuthenticationRequestDecoder;

public class WebAuthActivity extends BaseProxyActivity
  {
    public static final String WEBAUTH = "WebAuth";

    AuthenticationRequestDecoder authentication_request;
    
    LinkedHashMap<Integer,AsymSignatureAlgorithms> matching_keys = new LinkedHashMap<Integer,AsymSignatureAlgorithms> ();

    @Override
    public void onCreate (Bundle savedInstanceState)
      {
        super.onCreate (savedInstanceState);
        setContentView (R.layout.activity_webauth);

        showHeavyWork (PROGRESS_INITIALIZING);

        // Start of webauth
        new WebAuthProtocolInit (this).execute ();
      }

    @Override
    protected String getProtocolName ()
      {
        return WEBAUTH;
      }

    @Override
    public void onBackPressed ()
      {
        conditionalAbort (null);
      }

    @Override
    protected String getAbortString ()
      {
        return "Do you want to abort the current authentication process?";
      }

    @Override
    protected void abortTearDown ()
      {
      }
  }
