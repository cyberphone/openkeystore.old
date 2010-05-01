package org.webpki.keygen2;

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
import java.io.IOException;

import org.webpki.xml.DOMWriterHelper;
import org.webpki.xml.ServerCookie;

import static org.webpki.keygen2.KeyGen2Constants.*;


public class PlatformNegotiationResponseEncoder extends PlatformNegotiationResponse
  {

    private String server_session_id;

    BasicCapabilities basic_capabilities = new BasicCapabilities ();

    private ServerCookie server_cookie;  // Optional

    private String prefix;  // Default: no prefix


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


    public PlatformNegotiationResponseEncoder (String server_session_id)
      {
        this.server_session_id = server_session_id;
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
        // Optional ServerCookie
        ////////////////////////////////////////////////////////////////////////
        if (server_cookie != null)
          {
            server_cookie.write (wr);
          }
      }

  }
