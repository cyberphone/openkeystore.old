// This is the base class which is extended by WASP "SignatureRequest" Encoder and Decoder
package org.webpki.wasp;

import java.io.IOException;

import org.webpki.xml.XMLObjectWrapper;
import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMWriterHelper;

import org.webpki.xmldsig.XMLSignatureWrapper;

import static org.webpki.wasp.WASPConstants.*;


abstract class SignatureRequest extends XMLObjectWrapper
  {

    SignatureRequest () {}
    static final String SIGNATURE_PROFILES_ELEM = "SignatureProfiles";

    static final String CF_SHA1_ATTR            = "SHA1";
    static final String CF_ISSUER_ATTR          = "Issuer";
    static final String CF_SUBJECT_ATTR         = "Subject";
    static final String CF_EMAIL_ATTR           = "Email";
    static final String CF_SERIAL_ATTR          = "Serial";
    static final String CF_POLICY_ATTR          = "Policy";
    static final String CF_CONTAINERS_ATTR      = "Containers";
    static final String CF_KEY_USAGE_ATTR       = "KeyUsage";
    static final String CF_EXT_KEY_USAGE_ATTR   = "ExtKeyUsage";
    public void init () throws IOException
      {
        addWrapper (XMLSignatureWrapper.class);
        addSchema (WASP_SCHEMA_FILE);
      }


    protected boolean hasQualifiedElements ()
      {
        return true;
      }


    public String namespace ()
      {
        return WASP_NS;
      }

    
    public String element ()
      {
        return "SignatureRequest";
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
