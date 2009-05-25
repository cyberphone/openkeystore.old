package org.webpki.xml;

import org.w3c.dom.Document;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;
import org.apache.xerces.jaxp.DocumentBuilderFactoryImpl;


public class XMLConfiguration
  {
    private XMLConfiguration () { }

    static DocumentBuilder document_builder;

    static
      {
        try
          {
            DocumentBuilderFactory dbf = new DocumentBuilderFactoryImpl ();
            dbf.setNamespaceAware (true);
            document_builder = dbf.newDocumentBuilder ();
          }
        catch (Exception e)
          {
            throw new RuntimeException (e.getMessage ());
          }
      }

    public static Document createDocument ()
      {
        return document_builder.newDocument ();
      }
    
  }

