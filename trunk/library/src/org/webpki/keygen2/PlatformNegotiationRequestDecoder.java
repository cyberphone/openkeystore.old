package org.webpki.keygen2;

import java.io.IOException;

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
