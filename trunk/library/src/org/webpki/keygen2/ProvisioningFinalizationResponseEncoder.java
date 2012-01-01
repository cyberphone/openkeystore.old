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

import org.webpki.xml.DOMWriterHelper;
import org.webpki.xml.ServerCookie;


import static org.webpki.keygen2.KeyGen2Constants.*;


public class ProvisioningFinalizationResponseEncoder extends ProvisioningFinalizationResponse
  {

    String client_session_id;

    String server_session_id;

    ServerCookie server_cookie;
    
    byte[] attestation;

    String prefix;


    // Constructors

    public ProvisioningFinalizationResponseEncoder (ProvisioningFinalizationRequestDecoder fin_prov_request, byte[] attestation)
      {
        client_session_id = fin_prov_request.getClientSessionID ();
        server_session_id = fin_prov_request.getServerSessionID ();
        this.attestation = attestation;
      }


    public ServerCookie setServerCookie (ServerCookie server_cookie)
      {
        return this.server_cookie = server_cookie;
      }


    public void setPrefix (String prefix)
      {
        this.prefix = prefix;
      }


    protected void toXML (DOMWriterHelper wr) throws IOException
      {
        wr.initializeRootObject (prefix);

        //////////////////////////////////////////////////////////////////////////
        // Set top-level attributes
        //////////////////////////////////////////////////////////////////////////
        wr.setStringAttribute (ID_ATTR, client_session_id);

        wr.setStringAttribute (SERVER_SESSION_ID_ATTR, server_session_id);

        wr.setBinaryAttribute (ATTESTATION_ATTR, attestation);

        ////////////////////////////////////////////////////////////////////////
        // Optional ServerCookie
        ////////////////////////////////////////////////////////////////////////
        if (server_cookie != null)
          {
            server_cookie.write (wr);
          }

      }

  }
