package org.webpki.wasp;

import java.io.IOException;

import org.webpki.xml.DOMWriterHelper;

import static org.webpki.wasp.WASPConstants.*;


public class BinaryDocument extends RootDocument
  {

    public void write (DOMWriterHelper wr) throws IOException
      {
        wr.addBinary (BINARY_SUB_ELEM, data);
        super.write (wr);
      }


    public BinaryDocument (byte[] data, String content_id)
      {
        super.data = data;
        super.content_id = content_id;
      }


    public boolean equals (RootDocument d)
      {
        return d instanceof BinaryDocument && dataEquality (d);
      }

  }
