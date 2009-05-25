package org.webpki.wasp.test;

import java.io.IOException;

import org.webpki.xml.DOMWriterHelper;
import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.XMLObjectWrapper;
import org.webpki.wasp.SignatureProfileEncoder;


public class UnknownProfileRequestEncoder extends XMLObjectWrapper implements SignatureProfileEncoder
  {

    private static final String UNSUP_XML_SCHEMA_NAMESPACE = "http://example.com/doesnotexist";

    private String prefix = "pr";  // Default: "pr:"

    public void init () throws IOException
      {
        throw new IOException ("Must NOT be put in schema cache!");
      }


    public String namespace ()
      {
        return UNSUP_XML_SCHEMA_NAMESPACE;
      }

    public void setPrefix (String prefix)
      {
        this.prefix = prefix;
      }


    public String element ()
      {
        return "Unknown.Profile.Request";
      }


    protected boolean hasQualifiedElements ()
      {
        return true;
      }


    protected void toXML (DOMWriterHelper wr) throws IOException
      {
        wr.initializeRootObject (prefix);
        //////////////////////////////////////////////////////////////////////////
        // Set top-level attributes (which is all this profile got...)
        //////////////////////////////////////////////////////////////////////////
        wr.setStringAttribute ("BlahBlah", "This profile is not for real!");
      }

    protected void fromXML (DOMReaderHelper helper) throws IOException
      {
        throw new IOException ("Should NEVER be called");
      }


    public XMLObjectWrapper getXMLObjectWrapper ()
      {
        return this;
      }

  }
