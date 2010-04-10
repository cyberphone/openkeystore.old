package org.webpki.keygen2;

import java.io.IOException;
import java.io.Serializable;

import java.util.Date;

import java.security.GeneralSecurityException;

import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;

import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMAttributeReaderHelper;
import org.webpki.xml.ServerCookie;

import org.webpki.xmldsig.XMLSignatureWrapper;
import org.webpki.xmldsig.XMLSymKeyVerifier;

import org.webpki.crypto.SymKeyVerifierInterface;

import static org.webpki.keygen2.KeyGen2Constants.*;


public class ProvisioningSessionResponseDecoder extends ProvisioningSessionResponse implements Serializable
  {
    private static final long serialVersionUID = 1L;

    private XMLSignatureWrapper signature;  // Optional


    public String getServerSessionID ()
      {
        return server_session_id;
      }


    public Date getServerTime ()
      {
        return server_time;
      }


    
    public ECPublicKey getClientEphemeralKey ()
      {
        return client_ephemeral_key;
      }


    public ServerCookie getServerCookie ()
      {
        return server_cookie;
      }


    public int getSessionLifeTime ()
      {
        return session_life_time;
      }

    
    public int getSessionKeyLimit ()
      {
        return session_key_limit;
      }


    public void verifySignature (SymKeyVerifierInterface verifier) throws IOException
      {
        new XMLSymKeyVerifier (verifier).validateEnvelopedSignature (this, null, signature, server_session_id);
      }


    public boolean isSigned ()
      {
        return signature != null;
      }


    protected void fromXML (DOMReaderHelper rd) throws IOException
      {
        DOMAttributeReaderHelper ah = rd.getAttributeHelper ();

        /////////////////////////////////////////////////////////////////////////////////////////
        // Read the top level attributes
        /////////////////////////////////////////////////////////////////////////////////////////

        server_session_id = ah.getString (ID_ATTR);

        server_time = ah.getDateTime (SERVER_TIME_ATTR).getTime ();

        session_key_limit = ah.getInt (SESSION_KEY_LIMIT_ATTR);
        
        session_life_time = ah.getInt (SESSION_LIFE_TIME_ATTR);

        rd.getChild ();


        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the client key
        /////////////////////////////////////////////////////////////////////////////////////////
        rd.getNext (SERVER_EPHEMERAL_KEY_ELEM);
        rd.getChild ();
        client_ephemeral_key = (ECPublicKey) XMLSignatureWrapper.readPublicKey (rd);
        rd.getParent ();

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the optional server cookie
        /////////////////////////////////////////////////////////////////////////////////////////
        if (rd.hasNext (ServerCookie.SERVER_COOKIE_ELEM))
          {
            server_cookie = ServerCookie.read (rd);
          }

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the mandatory provisioning session data signature
        /////////////////////////////////////////////////////////////////////////////////////////
        signature = (XMLSignatureWrapper)wrap (rd.getNext (XMLSignatureWrapper.SIGNATURE_ELEM));
      }

  }
