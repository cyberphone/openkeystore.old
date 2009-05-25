package org.webpki.xml;

import java.io.IOException;
import java.io.Serializable;

import org.w3c.dom.Element;
import org.w3c.dom.Document;

import org.webpki.xmldsig.XPathCanonicalizer;
import org.webpki.xmldsig.CanonicalizationAlgorithms;

import org.webpki.util.ArrayUtil;

public class XMLCookie implements Serializable
  {
    private static final long serialVersionUID = 1L;

    Element element;

    XMLCookie () { }

    public XMLCookie (Element element)
      {
        this.element = element;
      }

    public XMLCookie (Document d)
      {
        this (d.getDocumentElement ());
      }


    public XMLCookie (XMLObjectWrapper wrapper) throws IOException
      {
        this (wrapper.toXMLDocument ().document);
      }


    public byte[] getData () throws IOException
      {
        return DOMUtil.writeXML (element);
      }


    public byte[] getC14NData () throws IOException
      {
        return XPathCanonicalizer.serializeSubset (element, CanonicalizationAlgorithms.C14N_EXCL);
      }

    public boolean equals (XMLCookie ref) throws IOException
      {
        return ArrayUtil.compare (getC14NData (), ref.getC14NData ());
      }

  }

