package org.webpki.wasp;

import java.io.IOException;

import org.webpki.util.ArrayUtil;

import org.webpki.xml.DOMWriterHelper;
import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMAttributeReaderHelper;

import static org.webpki.wasp.WASPConstants.*;


public abstract class RootDocument
  {
    static final String INTERNAL_SUB_ELEM = "Internal";

    static final String DELETED_SUB_ELEM  = "Deleted";
    static final String REASON_ATTR  = "Reason";

    static final String URI_ATTR     = "Reason";

    String content_id;

    byte[] data;


    public void write (DOMWriterHelper wr) throws IOException
      {
        wr.setStringAttribute (CONTENT_ID_ATTR, content_id);
      }


    public byte[] getData () throws IOException
      {
        if (data == null) throw new IOException ("Value has not been set");
        return data;
      }


    public String getContentID () throws IOException
      {
        if (content_id == null) throw new IOException ("\"content_id\" has not been set");
        return content_id;
      }


    public static RootDocument read (DOMReaderHelper rd) throws IOException
      {
        DOMAttributeReaderHelper ah = rd.getAttributeHelper ();
        if (rd.hasNext (TEXT_SUB_ELEM))
          {
            byte[] local_data = rd.getString (TEXT_SUB_ELEM).getBytes ("UTF-8");
            boolean cdata = rd.wasCDATA ();
            return new TextDocument (local_data, ah.getString (CONTENT_ID_ATTR), cdata);
          }
        if (rd.hasNext (BINARY_SUB_ELEM))
          {
            byte[] local_data = rd.getBinary (BINARY_SUB_ELEM);
            return new BinaryDocument (local_data, ah.getString (CONTENT_ID_ATTR));
          }
        if (rd.hasNext (INTERNAL_SUB_ELEM))
          {
            rd.getNext ();
            return new InternalDocument (ah.getString (URI_ATTR), ah.getString (CONTENT_ID_ATTR));
          }
        if (rd.hasNext (DELETED_SUB_ELEM))
          {
            rd.getNext ();
            return new DeletedDocument (ah.getStringConditional (REASON_ATTR), ah.getString (CONTENT_ID_ATTR));
          }
        throw new IOException ("Bad or missing document entry");
      }


    public abstract boolean equals (RootDocument d);


    boolean dataEquality (RootDocument d)
      {
        return content_id.equals (d.content_id) && ArrayUtil.compare (data, d.data);
      }

  }
