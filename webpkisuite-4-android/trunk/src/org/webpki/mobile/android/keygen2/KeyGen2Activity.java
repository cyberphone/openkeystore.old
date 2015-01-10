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
package org.webpki.mobile.android.keygen2;

import android.os.Bundle;

import android.util.Log;

import org.webpki.mobile.android.R;

import org.webpki.mobile.android.proxy.BaseProxyActivity;

import org.webpki.keygen2.KeyCreationRequestDecoder;
import org.webpki.keygen2.InvocationRequestDecoder;
import org.webpki.keygen2.ProvisioningInitializationRequestDecoder;

public class KeyGen2Activity extends BaseProxyActivity
  {
    public static final String KEYGEN2 = "KeyGen2";

    InvocationRequestDecoder invocation_request;

    ProvisioningInitializationRequestDecoder prov_init_request;

    KeyCreationRequestDecoder key_creation_request;

    int provisioning_handle;

    @Override
    public void onCreate (Bundle savedInstanceState)
      {
        super.onCreate (savedInstanceState);
        setContentView (R.layout.activity_keygen2);

        showHeavyWork (PROGRESS_INITIALIZING);

        // Start of keygen2
        new KeyGen2ProtocolInit (this).execute ();
      }

    @Override
    protected String getProtocolName ()
      {
        return KEYGEN2;
      }

    @Override
    protected void abortTearDown ()
      {
        if (provisioning_handle != 0)
          {
            try
              {
                sks.abortProvisioningSession (provisioning_handle);
              }
            catch (Exception e)
              {
                Log.e (KEYGEN2, "Failed to abort SKS session");
              }
          }
      }

    @Override
    public void onBackPressed ()
      {
        conditionalAbort (null);
      }

    @Override
    protected String getAbortString ()
      {
        return "Do you want to abort the current enrollment process?";
      }
  }
