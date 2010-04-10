package org.webpki.keygen2;

import java.io.IOException;

import java.security.interfaces.RSAPublicKey;

import org.webpki.util.ImageData;
import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMAttributeReaderHelper;
import org.webpki.xml.ServerCookie;

import org.webpki.xmldsig.XMLSignatureWrapper;
import org.webpki.xmldsig.XMLVerifier;

import org.webpki.crypto.VerifierInterface;

import static org.webpki.keygen2.KeyGen2Constants.*;


public class PlatformNegotiationRequestDecoder extends PlatformNegotiationRequest
  {
    private String server_session_id;

    private String submit_url;
    
    private RSAPublicKey issuer_key_exchange_key;

    private ImageData issuer_logotype;      // Optional

    BasicCapabilities basic_capabilities;

    private ServerCookie server_cookie;     // Optional

    private XMLSignatureWrapper signature;  // Optional


    public String getServerSessionID ()
      {
        return server_session_id;
      }


    public String getSubmitURL ()
      {
        return submit_url;
      }


    public ServerCookie getServerCookie ()
      {
        return server_cookie;
      }


    public ImageData getIssuerLogotype ()
    {
      return issuer_logotype;
    }


    public void verifySignature (VerifierInterface verifier) throws IOException
      {
        new XMLVerifier (verifier).validateEnvelopedSignature (this, null, signature, server_session_id);
      }


    public boolean isSigned ()
      {
        return signature != null;
      }


    public RSAPublicKey getIssuerKeyExchangeKey ()
      {
        return issuer_key_exchange_key;
      }

    
    public BasicCapabilities getBasicCapabilities ()
      {
        return basic_capabilities;
      }


    protected void fromXML (DOMReaderHelper rd) throws IOException
      {
        DOMAttributeReaderHelper ah = rd.getAttributeHelper ();

        /////////////////////////////////////////////////////////////////////////////////////////
        // Read the top level attributes
        /////////////////////////////////////////////////////////////////////////////////////////

        server_session_id = ah.getString (ID_ATTR);

        submit_url = ah.getString (SUBMIT_URL_ATTR);

        rd.getChild ();
// TODO
/*
        rd.getNext (ISSUER_KEY_EXCHANGE_KEY_ELEM);
*/
        rd.getChild ();
        rd.getNext (XMLSignatureWrapper.KEY_INFO_ELEM);
        if (ah.getStringConditional (ID_ATTR) != null)
          {
            throw new IOException ("Unexpexted \"Id\" attribute on \"KeyInfo\"");
          }
        rd.getChild ();
        rd.getNext (XMLSignatureWrapper.KEY_VALUE_ELEM);
        rd.getChild ();
        issuer_key_exchange_key = (RSAPublicKey) XMLSignatureWrapper.readPublicKey (rd);
        rd.getParent ();
        if (rd.hasNext ()) throw new IOException ("Only one element allowed to \"KeyInfo\"");
        rd.getParent ();
        rd.getParent ();

        if (rd.hasNext (ISSUER_LOGOTYPE_ELEM))
          {
            issuer_logotype = new ImageData (rd.getBinary (ISSUER_LOGOTYPE_ELEM), ah.getString (MIME_TYPE_ATTR));
          }

        basic_capabilities = BasicCapabilities.read (rd);

        if (rd.hasNext ()) do
          {
            if (rd.hasNext (ServerCookie.SERVER_COOKIE_ELEM))
              {
                server_cookie = ServerCookie.read (rd);
              }
            else // Must be a Signature otherwise schema validation has gone wrong...
              {
                signature = (XMLSignatureWrapper)wrap (rd.getNext (XMLSignatureWrapper.SIGNATURE_ELEM));
              }
          }
        while (rd.hasNext ());
      }

  }
