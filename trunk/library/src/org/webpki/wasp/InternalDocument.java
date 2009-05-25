package org.webpki.wasp;

import java.io.IOException;

import org.webpki.xml.DOMWriterHelper;


public class InternalDocument extends RootDocument
  {

    String uri;

    public void write (DOMWriterHelper wr) throws IOException
      {
        wr.addEmptyElement (INTERNAL_SUB_ELEM);
        wr.setStringAttribute (URI_ATTR, uri);
        super.write (wr);
      }


    public InternalDocument (String uri, String content_id)
      {
        super.content_id = content_id;
        this.uri = uri;
      }


    public String getURI ()
      {
        return uri;
      }


    public boolean equals (RootDocument d)
      {
        return d instanceof InternalDocument && content_id.equals (d.content_id) && uri.equals (((InternalDocument)d).uri);
      }

  }
