package org.webpki.keygen2;

import java.io.IOException;

import org.w3c.dom.Document;

import org.webpki.util.MimeTypedObject;

import org.webpki.xml.DOMWriterHelper;
import org.webpki.xml.ServerCookie;

import org.webpki.xmldsig.XMLSignatureWrapper;
import org.webpki.xmldsig.XMLSigner;

import org.webpki.crypto.SignerInterface;

import static org.webpki.keygen2.KeyGen2Constants.*;


public class PlatformNegotiationRequestEncoder extends PlatformNegotiationRequest
  {

    String server_session_id;

    String submit_url;

    private String prefix;  // Default: no prefix

    MimeTypedObject issuer_logotype;
    
    BasicCapabilities basic_capabilities = new BasicCapabilities ();

    ServerCookie server_cookie;
    
    boolean needs_dsig_ns;

    // Constructors

    public PlatformNegotiationRequestEncoder (String server_session_id,
                                              String submit_url,
                                              MimeTypedObject issuer_logotype)
      {
        this.server_session_id = server_session_id;
        this.submit_url = submit_url;
        this.issuer_logotype = issuer_logotype;
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
        needs_dsig_ns = true;
        XMLSigner ds = new XMLSigner (signer);
        ds.removeXMLSignatureNS ();
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
        
        if (needs_dsig_ns) XMLSignatureWrapper.addXMLSignatureNS (wr);

        ////////////////////////////////////////////////////////////////////////
        // Issuer logotype(s)
        ////////////////////////////////////////////////////////////////////////
        if (issuer_logotype != null)
        {
          wr.addBinary (ISSUER_LOGOTYPE_ELEM, issuer_logotype.getData ());
          wr.setStringAttribute (MIME_TYPE_ATTR, issuer_logotype.getMimeType ());
        }

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
