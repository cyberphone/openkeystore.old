package org.webpki.keygen2;

import java.io.IOException;

import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMAttributeReaderHelper;
import org.webpki.xml.ServerCookie;

import static org.webpki.keygen2.KeyGen2Constants.*;


public class CredentialDeploymentResponseDecoder extends CredentialDeploymentResponse
  {
      
    private String client_session_id;

    private String server_session_id;

    private ServerCookie server_cookie;     // Optional


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


    protected void fromXML (DOMReaderHelper rd) throws IOException
      {
        DOMAttributeReaderHelper ah = rd.getAttributeHelper ();

        /////////////////////////////////////////////////////////////////////////////////////////
        // Read the top level attributes
        /////////////////////////////////////////////////////////////////////////////////////////

        client_session_id = ah.getString (ID_ATTR);

        server_session_id = ah.getString (SERVER_SESSION_ID_ATTR);

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
