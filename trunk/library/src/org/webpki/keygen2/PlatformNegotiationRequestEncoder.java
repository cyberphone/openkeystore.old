package org.webpki.keygen2;

import java.io.IOException;

import org.w3c.dom.Document;

import org.webpki.xml.DOMWriterHelper;
import org.webpki.xml.ServerCookie;

import org.webpki.xmldsig.XMLSigner;

import org.webpki.crypto.SignerInterface;

import static org.webpki.keygen2.KeyGen2Constants.*;


public class PlatformNegotiationRequestEncoder extends PlatformNegotiationRequest
  {

    String server_session_id;

    String submit_url;

    private String prefix;  // Default: no prefix

    BasicCapabilities basic_capabilities = new BasicCapabilities ();

    ServerCookie server_cookie;



    // Constructors

    @SuppressWarnings("unused")
    private PlatformNegotiationRequestEncoder () {}


    public PlatformNegotiationRequestEncoder (String server_session_id, String submit_url)
      {
        this.server_session_id = server_session_id;
        this.submit_url = submit_url;
      }


    public ServerCookie setServerCookie (ServerCookie server_cookie)
      {
        return this.server_cookie = server_cookie;
      }


    public void setPrefix (String prefix)
      {
        this.prefix = prefix;
      }


    public void signRequest (SignerInterface signer) throws IOException
      {
        XMLSigner ds = new XMLSigner (signer);
        Document doc = getRootDocument ();
        ds.createEnvelopedSignature (doc, server_session_id);
      }

    public BasicCapabilities getBasicCapabilities ()
      {
        return basic_capabilities;
      }


    protected void toXML (DOMWriterHelper wr) throws IOException
      {
        wr.initializeRootObject (prefix);

        //////////////////////////////////////////////////////////////////////////
        // Set top-level attributes
        //////////////////////////////////////////////////////////////////////////
        wr.setStringAttribute (ID_ATTR, server_session_id);

        wr.setStringAttribute (SUBMIT_URL_ATTR, submit_url);

        ////////////////////////////////////////////////////////////////////////
        // Basic capabilities
        ////////////////////////////////////////////////////////////////////////
        basic_capabilities.write (wr);

        ////////////////////////////////////////////////////////////////////////
        // Optional ServerCookie
        ////////////////////////////////////////////////////////////////////////
        if (server_cookie != null)
          {
            server_cookie.write (wr);
          }

      }

  }
