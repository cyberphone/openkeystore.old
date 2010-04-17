package org.webpki.keygen2;

import java.io.IOException;

import org.webpki.xml.DOMWriterHelper;
import org.webpki.xml.ServerCookie;


import static org.webpki.keygen2.KeyGen2Constants.*;


public class CredentialDeploymentResponseEncoder extends CredentialDeploymentResponse
  {

    String client_session_id;

    String server_session_id;

    ServerCookie server_cookie;

    String prefix;


    // Constructors

    public CredentialDeploymentResponseEncoder (String client_session_id, String server_session_id)
      {
        this.client_session_id = client_session_id;
        this.server_session_id = server_session_id;
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

        wr.addComment ("\n" +
                       "    This message is still TBD.\n\n" +
                       "    Here the client will return a success signature\n  ",
                       true);
        ////////////////////////////////////////////////////////////////////////
        // Optional ServerCookie
        ////////////////////////////////////////////////////////////////////////
        if (server_cookie != null)
          {
            server_cookie.write (wr);
          }

      }

  }
