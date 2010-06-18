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

import java.security.GeneralSecurityException;

import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMAttributeReaderHelper;
import org.webpki.xml.ServerCookie;

import static org.webpki.keygen2.KeyGen2Constants.*;

public class CredentialDeploymentResponseDecoder extends CredentialDeploymentResponse
  {
      
    private String client_session_id;

    private String server_session_id;
    
    private byte[] close_session_attestation;

    private ServerCookie server_cookie;     // Optional


    public byte[] getCloseSessionAttestation ()
      {
        return close_session_attestation;
      }

    
    public String getServerSessionID ()
      {
        return server_session_id;
      }


    public String getClientSessionID ()
      {
        return client_session_id;
      }


    public ServerCookie getServerCookie ()
      {
        return server_cookie;
      }
    
    
    public void verifyProvisioningResult (ServerCredentialStore server_credential_store,
                                          ServerSessionKeyInterface sess_key_interface) throws IOException
      {
        server_credential_store.checkSession (client_session_id, server_session_id);
        try
          {
            server_credential_store.checkFinalResult (close_session_attestation, sess_key_interface);
          }
        catch (GeneralSecurityException e)
          {
            throw new IOException (e);
          }
      }


    protected void fromXML (DOMReaderHelper rd) throws IOException
      {
        DOMAttributeReaderHelper ah = rd.getAttributeHelper ();

        /////////////////////////////////////////////////////////////////////////////////////////
        // Read the top level attributes
        /////////////////////////////////////////////////////////////////////////////////////////

        client_session_id = ah.getString (ID_ATTR);

        server_session_id = ah.getString (SERVER_SESSION_ID_ATTR);
        
        close_session_attestation = ah.getBinary (CLOSE_SESSION_ATTESTATION_ATTR);

        rd.getChild ();

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the ServerCookie if there is one
        /////////////////////////////////////////////////////////////////////////////////////////
        if (rd.hasNext ())
          {
            server_cookie = ServerCookie.read (rd);
          }
      }

  }
