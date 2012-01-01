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

import java.io.IOException;

import java.util.Vector;

import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMAttributeReaderHelper;
import org.webpki.xml.ServerCookie;

import static org.webpki.keygen2.KeyGen2Constants.*;

public class PlatformNegotiationResponseDecoder extends PlatformNegotiationResponse
  {
    BasicCapabilities basic_capabilities;
    
    public class ImagePreference
      {
        private ImagePreference () {}

        String type;
        String mime_type;
        int width;
        int height;
      }
    
    Vector<ImagePreference> image_preferences = new Vector<ImagePreference> ();

    public String getServerSessionID ()
      {
        return server_session_id;
      }


    public ServerCookie getServerCookie ()
      {
        return server_cookie;
      }


    public BasicCapabilities getBasicCapabilities ()
      {
        return basic_capabilities;
      }
    
    
    public ImagePreference[] getImagesPreferences ()
      {
        return image_preferences.toArray (new ImagePreference[0]);
      }

    
    protected void fromXML (DOMReaderHelper rd) throws IOException
      {
        DOMAttributeReaderHelper ah = rd.getAttributeHelper ();
        //////////////////////////////////////////////////////////////////////////
        // Get the top-level attributes
        //////////////////////////////////////////////////////////////////////////
        server_session_id = ah.getString (SERVER_SESSION_ID_ATTR);

        rd.getChild ();

        //////////////////////////////////////////////////////////////////////////
        // Get the child elements
        //////////////////////////////////////////////////////////////////////////

        basic_capabilities = BasicCapabilities.read (rd);
        
        while (rd.hasNext (IMAGE_PREFERENCE_ELEM))
          {
            ImagePreference im_pref = new ImagePreference ();
            rd.getNext (IMAGE_PREFERENCE_ELEM);
            im_pref.type = ah.getString (TYPE_ATTR);
            im_pref.mime_type = ah.getString (MIME_TYPE_ATTR);
            im_pref.width = ah.getInt (WIDTH_ATTR);
            im_pref.height = ah.getInt (HEIGHT_ATTR);
            image_preferences.add (im_pref);
          }

        if (rd.hasNext (ServerCookie.SERVER_COOKIE_ELEM))
          {
            server_cookie = ServerCookie.read (rd);
          }
      }

   }
