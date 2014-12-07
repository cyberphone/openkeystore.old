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

import org.webpki.json.JSONObjectReader;

import static org.webpki.keygen2.KeyGen2Constants.*;

public class InvocationResponseDecoder extends KeyGen2Validator
  {
    private static final long serialVersionUID = 1L;

    byte[] nonce;  // For VMs
    
    LinkedHashMap<String,ServerState.CapabilityBase> received_capabilities = new LinkedHashMap<String,ServerState.CapabilityBase> ();

    String server_session_id;
    
    @Override
    protected void readJSONData (JSONObjectReader rd) throws IOException
      {
        //////////////////////////////////////////////////////////////////////////
        // Get the top-level properties
        //////////////////////////////////////////////////////////////////////////
        server_session_id = getID (rd, SERVER_SESSION_ID_JSON);
        
        nonce = rd.getBinaryConditional (NONCE_JSON);

        //////////////////////////////////////////////////////////////////////////
        // Get the optional client capabilities
        //////////////////////////////////////////////////////////////////////////
        for (JSONObjectReader cc : getObjectArrayConditional (rd, CLIENT_CAPABILITIES_JSON))
          {
            String type = cc.getString (TYPE_JSON);
            ServerState.CapabilityBase capability = null;
            if (cc.hasProperty (SUPPORTED_JSON))
              {
                capability = new ServerState.Feature (cc.getBoolean (SUPPORTED_JSON));
              }
            else if (cc.hasProperty (VALUES_JSON))
              {
                capability = new ServerState.Values (KeyGen2Validator.getNonEmptyList (cc, VALUES_JSON));
              }
            else
              {
                JSONObjectReader or = cc.getObject (IMAGE_ATTRIBUTES_JSON);
                capability = new ServerState.ImagePreference (or.getString (MIME_TYPE_JSON),
                                                              or.getInt (WIDTH_JSON),
                                                              or.getInt (HEIGHT_JSON));
              }
            capability.type = type;
            if (received_capabilities.put (type, capability) != null)
              {
                KeyGen2Validator.bad ("Duplicated capability URI: " + type);
              }
          }
      }

    @Override
    public String getQualifier ()
      {
        return KeyGen2Messages.INVOCATION_RESPONSE.getName ();
      }
  }
