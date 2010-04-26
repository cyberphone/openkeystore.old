package org.webpki.keygen2;

import java.io.IOException;
import java.security.GeneralSecurityException;

import org.webpki.sks.SessionKeyOperations;
import org.webpki.util.ArrayUtil;
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
    
    
    public void verifyProvisioningResult (ServerCredentialStore server_credential_store, SessionKeyOperations mac_interface) throws IOException, GeneralSecurityException
      {
        server_credential_store.checkSession (client_session_id, server_session_id);
        if (!ArrayUtil.compare (mac_interface.getAttest (ArrayUtil.add (SessionKeyOperations.SUCCESS_MODIFIER, 
                                                                        server_credential_store.getMACSequenceCounterAndUpdate ())),
                                close_session_attestation))
          {
            ServerCredentialStore.bad ("Final attestation failed!");
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
