/*
 *  Copyright 2006-2010 WebPKI.org (http://webpki.org).
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

import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMAttributeReaderHelper;
import org.webpki.xml.ServerCookie;

import static org.webpki.keygen2.KeyGen2Constants.*;


public class PlatformNegotiationResponseDecoder extends PlatformNegotiationResponse
  {
    private String server_session_id;

    BasicCapabilities basic_capabilities;

    private ServerCookie server_cookie;                         // Optional


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

/*
    private void bad (String mismatch) throws IOException
      {
        throw new IOException ("Mismatch between request and response: " + mismatch);
      }
*/

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

        if (rd.hasNext (ServerCookie.SERVER_COOKIE_ELEM))
          {
            server_cookie = ServerCookie.read (rd);
          }
      }


   }
