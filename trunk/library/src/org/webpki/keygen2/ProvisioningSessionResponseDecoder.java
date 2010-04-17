package org.webpki.keygen2;

import java.io.IOException;

import java.util.Date;

import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;

import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMAttributeReaderHelper;
import org.webpki.xml.ServerCookie;

import org.webpki.xmldsig.XMLSignatureWrapper;
import org.webpki.xmldsig.XMLSymKeyVerifier;

import org.webpki.crypto.SymKeyVerifierInterface;

import static org.webpki.keygen2.KeyGen2Constants.*;


public class ProvisioningSessionResponseDecoder extends ProvisioningSessionResponse
  {
    private XMLSignatureWrapper signature;  // Optional


    public String getServerSessionID ()
      {
        return server_session_id;
      }

    
    public String getClientSessionID ()
      {
        return client_session_id;
      }


    public Date getServerTime ()
      {
        return server_time;
      }

    
    public Date getClientTime ()
      {
        return client_time;
      }

    
    public ECPublicKey getClientEphemeralKey ()
      {
        return client_ephemeral_key;
      }


    public ServerCookie getServerCookie ()
      {
        return server_cookie;
      }


    public byte[] getSessionAttestation ()
      {
        return session_attestation;
      }


    public X509Certificate[] getDeviceCertificatePath ()
      {
        return device_certificate_path;
      }


    public void verifySignature (SymKeyVerifierInterface verifier) throws IOException
      {
        new XMLSymKeyVerifier (verifier).validateEnvelopedSignature (this, null, signature, client_session_id);
      }


    protected void fromXML (DOMReaderHelper rd) throws IOException
      {
        DOMAttributeReaderHelper ah = rd.getAttributeHelper ();

        /////////////////////////////////////////////////////////////////////////////////////////
        // Read the top level attributes
        /////////////////////////////////////////////////////////////////////////////////////////

        client_session_id = ah.getString (ID_ATTR);

        server_session_id = ah.getString (SERVER_SESSION_ID_ATTR);

        server_time = ah.getDateTime (SERVER_TIME_ATTR).getTime ();

        client_time = ah.getDateTime (CLIENT_TIME_ATTR).getTime ();

        session_attestation = ah.getBinary (SESSION_ATTESTATION_ATTR);
        
        rd.getChild ();

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the ephemeral client key
        /////////////////////////////////////////////////////////////////////////////////////////
        rd.getNext (CLIENT_EPHEMERAL_KEY_ELEM);
        rd.getChild ();
        client_ephemeral_key = (ECPublicKey) XMLSignatureWrapper.readPublicKey (rd);
        rd.getParent ();

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the device certificate path
        /////////////////////////////////////////////////////////////////////////////////////////
        rd.getNext (DEVICE_CERTIFICATE_ELEM);
        rd.getChild ();
        device_certificate_path = XMLSignatureWrapper.readSortedX509DataSubset (rd);
        rd.getParent ();

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the optional ServerCookie
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
