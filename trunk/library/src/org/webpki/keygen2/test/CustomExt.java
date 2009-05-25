package org.webpki.keygen2.test;

import java.io.IOException;

import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMWriterHelper;
import org.webpki.xml.XMLObjectWrapper;


public class CustomExt extends XMLObjectWrapper
  {

    public void init () throws IOException
      {
        addSchema ("customext.xsd");
      }


    protected boolean hasQualifiedElements ()
      {
        return true;
      }


    public String namespace ()
      {
        return "urn:demo:schema";
      }

    
    public String element ()
      {
        return "CustomExt";
      }


    protected void fromXML (DOMReaderHelper helper) throws IOException
      {
      }


    protected void toXML (DOMWriterHelper helper) throws IOException
      {
        helper.initializeRootObject (null);
        helper.addString ("Data", "Hi there!");
      }

  }
