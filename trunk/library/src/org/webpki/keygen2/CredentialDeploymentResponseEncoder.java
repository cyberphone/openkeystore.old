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
    
    byte[] close_session_attestation;

    String prefix;


    // Constructors

    public CredentialDeploymentResponseEncoder (CredentialDeploymentRequestDecoder cre_dep_dec,
                                                byte[] close_session_attestation)
      {
        client_session_id = cre_dep_dec.getClientSessionID ();
        server_session_id = cre_dep_dec.getServerSessionID ();
        this.close_session_attestation = close_session_attestation;
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

        wr.setBinaryAttribute (CLOSE_SESSION_ATTESTATION_ATTR, close_session_attestation);

        ////////////////////////////////////////////////////////////////////////
        // Optional ServerCookie
        ////////////////////////////////////////////////////////////////////////
        if (server_cookie != null)
          {
            server_cookie.write (wr);
          }

      }

  }
