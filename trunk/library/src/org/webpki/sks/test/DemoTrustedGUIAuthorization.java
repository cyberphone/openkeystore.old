/*
 *  Copyright 2006-2011 WebPKI.org (http://webpki.org).
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
package org.webpki.sks.test;

import java.io.IOException;

import org.webpki.sks.AppUsage;
import org.webpki.sks.Grouping;
import org.webpki.sks.PassphraseFormat;
import org.webpki.sks.SKSException;

import org.webpki.sks.ws.TrustedGUIAuthorization;

public class DemoTrustedGUIAuthorization implements TrustedGUIAuthorization
  {
    static final String GOOD_TRUSTED_GUI_PIN = "1234";
    
    static final byte[] SHARED_SECRET_32 = {0,1,2,3,4,5,6,7,8,9,1,0,3,2,5,4,7,6,9,8,9,8,7,6,5,4,3,2,1,0,3,2};

    @Override
    public byte[] restoreTrustedAuthorization (byte[] value) throws SKSException
      {
        return value;
      }

    @Override
    public byte[] getTrustedAuthorization (PassphraseFormat format,
                                           Grouping grouping,
                                           AppUsage app_usage,
                                           String friendly_name) throws SKSException
      {
        byte[] authorization = null;
        try
          {
            authorization = GOOD_TRUSTED_GUI_PIN.getBytes ("UTF-8");
          }
        catch (IOException e)
          {
          }
        return authorization;
      }

    @Override
    public String getImplementation ()
      {
        return "Non-functional mockup version";
      }
  }
