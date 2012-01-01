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
package org.webpki.keygen2;
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
import java.io.IOException;

import java.util.Vector;

import org.webpki.xml.DOMWriterHelper;
import org.webpki.xml.ServerCookie;

import static org.webpki.keygen2.KeyGen2Constants.*;

public class PlatformNegotiationResponseEncoder extends PlatformNegotiationResponse
  {
    BasicCapabilities basic_capabilities = new BasicCapabilities ();

    private String prefix;  // Default: no prefix
    
    class ImagePreference
      {
        String type;
        String mime_type;
        int width;
        int height;
      }
    
    Vector<ImagePreference> image_preferences = new Vector<ImagePreference> ();


    public ServerCookie setServerCookie (ServerCookie server_cookie)
      {
        return this.server_cookie = server_cookie;
      }


    public void setPrefix (String prefix) throws IOException
      {
        this.prefix = prefix;
      }


    public String getPrefix ()
      {
        return prefix;
      }


    public BasicCapabilities getBasicCapabilities ()
      {
        return basic_capabilities;
      }


    public PlatformNegotiationResponseEncoder addImagePreference (String type_url,
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


    public PlatformNegotiationResponseEncoder (PlatformNegotiationRequestDecoder decoder)
      {
        this.server_session_id = decoder.server_session_id;
        this.server_cookie = decoder.server_cookie;
      }

    protected void toXML (DOMWriterHelper wr) throws IOException
      {
        wr.initializeRootObject (prefix);

        wr.setStringAttribute (SERVER_SESSION_ID_ATTR, server_session_id);

        ////////////////////////////////////////////////////////////////////////
        // Basic capabilities
        ////////////////////////////////////////////////////////////////////////
        basic_capabilities.write (wr);

        ////////////////////////////////////////////////////////////////////////
        // Optional image preferences
        ////////////////////////////////////////////////////////////////////////
        for (ImagePreference im_pref : image_preferences)
          {
            wr.addChildElement (IMAGE_PREFERENCE_ELEM);
            wr.setStringAttribute (TYPE_ATTR, im_pref.type);
            wr.setStringAttribute (MIME_TYPE_ATTR, im_pref.mime_type);
            wr.setIntAttribute (WIDTH_ATTR, im_pref.width);
            wr.setIntAttribute (HEIGHT_ATTR, im_pref.height);
            wr.getParent ();
          }

        ////////////////////////////////////////////////////////////////////////
        // Optional ServerCookie
        ////////////////////////////////////////////////////////////////////////
        if (server_cookie != null)
          {
            server_cookie.write (wr);
          }
      }

  }
