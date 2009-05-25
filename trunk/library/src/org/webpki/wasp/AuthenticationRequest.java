// This is the base class which is extended by Web Authentication "AuthenticationRequest" Encoder and Decoder
package org.webpki.wasp;

import java.io.IOException;

import org.webpki.xml.XMLObjectWrapper;
import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMWriterHelper;

import org.webpki.xmldsig.XMLSignatureWrapper;

import static org.webpki.wasp.WASPConstants.*;


abstract class AuthenticationRequest extends XMLObjectWrapper 
  {
    AuthenticationRequest () {}

    static final String BACKGROUND_VIEW_ELEM        = "BackgroundView";

    static final String AUTHENTICATION_PROFILE_ELEM = "AuthenticationProfile";


    public void init () throws IOException
      {
        addWrapper (XMLSignatureWrapper.class);
        addSchema (WEBAUTH_SCHEMA_FILE);
      }


    protected boolean hasQualifiedElements ()
      {
        return true;
      }


    public String namespace ()
      {
        return WEBAUTH_NS;
      }

    
    public String element ()
      {
        return "AuthenticationRequest";
      }


    protected void fromXML (DOMReaderHelper helper) throws IOException
      {
        throw new IOException ("Should have been implemented in derived class");
      }


    protected void toXML (DOMWriterHelper helper) throws IOException
      {
        throw new IOException ("Should have been implemented in derived class");
      }

  }
