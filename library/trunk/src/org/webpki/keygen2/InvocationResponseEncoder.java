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
import java.io.IOException;

import java.util.Vector;

import org.webpki.json.JSONArrayWriter;
import org.webpki.json.JSONEncoder;
import org.webpki.json.JSONObjectWriter;

import static org.webpki.keygen2.KeyGen2Constants.*;

public class InvocationResponseEncoder extends JSONEncoder
  {
    private static final long serialVersionUID = 1L;

    String server_session_id;
    
    byte[] nonce;  // For VMs

    Vector<ImagePreference> image_preferences = new Vector<ImagePreference> ();


    public InvocationResponseEncoder addImagePreference (String type_url,
                                                                  String mime_type,
                                                                  int width,
                                                                  int height)
      {
        ImagePreference im_pref = new ImagePreference ();
        im_pref.type = type_url;
        im_pref.mime_type = mime_type;
        im_pref.width = width;
        im_pref.height = height;
        image_preferences.add (im_pref);
        return this;
      }

    BasicCapabilities basic_capabilities = new BasicCapabilities ();

    public BasicCapabilities getBasicCapabilities ()
      {
        return basic_capabilities;
      }

    public InvocationResponseEncoder (InvocationRequestDecoder decoder)
      {
        this.server_session_id = decoder.server_session_id;
      }
    
    public void setNonce (byte[] nonce)
      {
        this.nonce = nonce;
      }

    @Override
    protected void writeJSONData (JSONObjectWriter wr) throws IOException
      {
        wr.setString (SERVER_SESSION_ID_JSON, server_session_id);
        
        ////////////////////////////////////////////////////////////////////////
        // VM mandatory option
        ////////////////////////////////////////////////////////////////////////
        if (nonce != null)
          {
            wr.setBinary (NONCE_JSON, nonce);
          }

        ////////////////////////////////////////////////////////////////////////
        // Basic capabilities
        ////////////////////////////////////////////////////////////////////////
        BasicCapabilities.write (wr, basic_capabilities, false);

        ////////////////////////////////////////////////////////////////////////
        // Optional image preferences
        ////////////////////////////////////////////////////////////////////////
        if (!image_preferences.isEmpty ())
          {
            JSONArrayWriter array = wr.setArray (IMAGE_PREFERENCES_JSON);
            for (ImagePreference im_pref : image_preferences)
              {
                array.setObject ()
                  .setString (TYPE_JSON, im_pref.type)
                  .setString (MIME_TYPE_JSON, im_pref.mime_type)
                  .setInt (WIDTH_JSON, im_pref.width)
                  .setInt (HEIGHT_JSON, im_pref.height);
              }
          }
      }

    @Override
    public String getQualifier ()
      {
        return INVOCATION_RESPONSE_JSON;
      }

    @Override
    public String getContext ()
      {
        return KEYGEN2_NS;
      }
  }
