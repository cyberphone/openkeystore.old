package org.webpki.wasp;

import java.io.IOException;

import org.webpki.xml.DOMWriterHelper;


public class DeletedDocument extends RootDocument
  {
    String reason;

    public void write (DOMWriterHelper wr) throws IOException
      {
        wr.addEmptyElement (DELETED_SUB_ELEM);
        if (reason != null)
          {
            wr.setStringAttribute (REASON_ATTR, reason);
          }
        super.write (wr);
      }


    public DeletedDocument (String reason, String content_id)
      {
        super.content_id = content_id;
        this.reason = reason;
      }


    public String getReason ()
      {
        return reason;
      }


    public boolean equals (RootDocument d)
      {
        return d instanceof DeletedDocument && content_id.equals (d.content_id) && reason.equals (((DeletedDocument)d).reason);
      }

 }
