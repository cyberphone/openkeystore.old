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

import java.util.Vector;

import org.webpki.json.JSONObjectReader;

import static org.webpki.keygen2.KeyGen2Constants.*;

public class PlatformNegotiationResponseDecoder extends KeyGen2Validator
  {
    private static final long serialVersionUID = 1L;

    String server_session_id;
    
    byte[] nonce;  // For VMs

    Vector<ImagePreference> image_preferences = new Vector<ImagePreference> ();

    BasicCapabilities basic_capabilities = new BasicCapabilities ();

    public BasicCapabilities getBasicCapabilities ()
      {
        return basic_capabilities;
      }

    public String getServerSessionID ()
      {
        return server_session_id;
      }


    public ImagePreference[] getImagesPreferences ()
      {
        return image_preferences.toArray (new ImagePreference[0]);
      }

    
    @Override
    protected void unmarshallJSONData (JSONObjectReader rd) throws IOException
      {
        //////////////////////////////////////////////////////////////////////////
        // Get the top-level properties
        //////////////////////////////////////////////////////////////////////////
        server_session_id = getID (rd, SERVER_SESSION_ID_JSON);
        
        nonce = rd.getBinaryConditional (NONCE_JSON);

        BasicCapabilities.read (rd, basic_capabilities, false);
        
        //////////////////////////////////////////////////////////////////////////
        // Get the optional image preferences
        //////////////////////////////////////////////////////////////////////////
        for (JSONObjectReader ip : getObjectArrayConditional (rd, IMAGE_PREFERENCES_JSON))
          {
            ImagePreference im_pref = new ImagePreference ();
            im_pref.type = getURI (ip, TYPE_JSON);
            im_pref.mime_type = ip.getString (MIME_TYPE_JSON);
            im_pref.width = ip.getInt (WIDTH_JSON);
            im_pref.height = ip.getInt (HEIGHT_JSON);
            image_preferences.add (im_pref);
          }
      }

    @Override
    public String getQualifier ()
      {
        return PLATFORM_NEGOTIATION_RESPONSE_JSON;
      }
  }
