/*
 *  Copyright 2006-2013 WebPKI.org (http://webpki.org).
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
package org.webpki.keygen2;

import java.io.IOException;

import org.webpki.json.JSONObjectReader;

import static org.webpki.keygen2.KeyGen2Constants.*;

public class PlatformNegotiationRequestDecoder extends ClientDecoder
  {
    Action action;

    public Action getAction ()
      {
        return action;
      }
    

    boolean privacy_enabled;

    public boolean getPrivacyEnabledFlag ()
      {
        return privacy_enabled;
      }


    BasicCapabilities basic_capabilities = new BasicCapabilities (true);
    
    public BasicCapabilities getBasicCapabilities ()
      {
        return basic_capabilities;
      }


    String server_session_id;

    public String getServerSessionID ()
      {
        return server_session_id;
      }


    String submit_url;

    public String getSubmitURL ()
      {
        return submit_url;
      }


    String abort_url; // Optional

    public String getAbortURL ()
      {
        return abort_url;
      }


    String[] languages;

    public String[] getLanguages ()
      {
        return languages;
      }

    @Override
    void readServerRequest (JSONObjectReader rd) throws IOException
      {
        /////////////////////////////////////////////////////////////////////////////////////////
        // Read the top level properties
        /////////////////////////////////////////////////////////////////////////////////////////
        action = Action.getActionFromString (rd.getString (ACTION_JSON));

        languages = rd.getStringArrayConditional (LANGUAGES_JSON);

        privacy_enabled = rd.getBooleanConditional (PRIVACY_ENABLED_JSON);

        server_session_id = getID (rd, SERVER_SESSION_ID_JSON);

        submit_url = getURL (rd, SUBMIT_URL_JSON);

        if (rd.hasProperty (ABORT_URL_JSON))
          {
            abort_url = getURL (rd, ABORT_URL_JSON);
          }

        BasicCapabilities.read (rd, basic_capabilities, true);
      }

    @Override
    public String getQualifier ()
      {
        return PLATFORM_NEGOTIATION_REQUEST_JSON;
      }
  }
