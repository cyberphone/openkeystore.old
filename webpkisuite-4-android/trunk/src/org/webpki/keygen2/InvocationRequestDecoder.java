/*
 *  Copyright 2006-2014 WebPKI.org (http://webpki.org).
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
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Set;

import org.webpki.crypto.KeyContainerTypes;
import org.webpki.json.JSONObjectReader;

import static org.webpki.keygen2.KeyGen2Constants.*;

public class InvocationRequestDecoder extends ClientDecoder
  {
    private static final long serialVersionUID = 1L;
    
    enum CAPABILITY {UNDEFINED, URI_FEATURE, VALUES, IMAGE_ATTRIBUTES};
    
    LinkedHashMap<String,CAPABILITY> queried_capabilities = new LinkedHashMap<String,CAPABILITY> ();   

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


    public Set<String> getQueriedCapabilities ()
      {
        return queried_capabilities.keySet ();
      }


    String server_session_id;

    public String getServerSessionId ()
      {
        return server_session_id;
      }


    String submit_url;

    public String getSubmitUrl ()
      {
        return submit_url;
      }


    String abort_url; // Optional

    public String getOptionalAbortUrl ()
      {
        return abort_url;
      }


    String[] languages; // Optional

    public String[] getOptionalLanguageList ()
      {
        return languages;
      }


    LinkedHashSet<KeyContainerTypes> key_container_list;  // Optional
    
    public LinkedHashSet<KeyContainerTypes> getOptionalKeyContainerList ()
      {
        return key_container_list;
      }


    @Override
    void readServerRequest (JSONObjectReader rd) throws IOException
      {
        /////////////////////////////////////////////////////////////////////////////////////////
        // Session properties
        /////////////////////////////////////////////////////////////////////////////////////////
        action = Action.getActionFromString (rd.getString (ACTION_JSON));

        languages = rd.getStringArrayConditional (PREFERREDD_LANGUAGES_JSON);

        key_container_list = KeyContainerTypes.getOptionalKeyContainerSet (rd.getStringArrayConditional (KeyContainerTypes.KCT_TARGET_KEY_CONTAINERS));

        privacy_enabled = rd.getBooleanConditional (PRIVACY_ENABLED_JSON);

        server_session_id = getID (rd, SERVER_SESSION_ID_JSON);

        submit_url = getURL (rd, SUBMIT_URL_JSON);

        if (rd.hasProperty (ABORT_URL_JSON))
          {
            abort_url = getURL (rd, ABORT_URL_JSON);
          }

        String[] capability_uris = KeyGen2Validator.getURIListConditional (rd, CLIENT_CAPABILITY_QUERY_JSON);
        if (capability_uris != null)
          {
            for (String uri : capability_uris)
              {
                if (queried_capabilities.put (uri, CAPABILITY.UNDEFINED) != null)
                  {
                    KeyGen2Validator.bad ("Duplicate capability URI: " + uri);
                  }
              }
          }
      }

    @Override
    public String getQualifier ()
      {
        return KeyGen2Messages.INVOCATION_REQUEST.getName ();
      }
  }
