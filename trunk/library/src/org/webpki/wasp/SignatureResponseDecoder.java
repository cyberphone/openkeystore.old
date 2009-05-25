package org.webpki.wasp;

import java.io.IOException;

import org.w3c.dom.Element;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMUtil;


public class SignatureResponseDecoder extends SignatureResponse
  {

    ////////////////////////////////////////////////////
    // Data coming from standard decoders
    ////////////////////////////////////////////////////
    private DocumentData doc_data;                                          // Optional (CopyData)

    private SignatureProfileResponseDecoder sign_prof_data;


    public DocumentData getDocumentData ()
      {
        return doc_data;
      }


    public SignatureProfileResponseDecoder getSignatureProfileResponseDecoder ()
      {
        return sign_prof_data;
      }


    private void bad (String what) throws IOException
      {
        throw new IOException (what);
      }


    public void checkRequestResponseIntegrity (SignatureRequestEncoder sreqenc, byte[] expected_sha1) throws IOException
      {
        // The DocumentData object
        if (sreqenc.copy_data)
          {
            if (doc_data == null) bad ("Missing DocumentData");
            if (!sreqenc.doc_data.equals (doc_data)) bad ("DocumentData mismatch");
          }
        else if (doc_data != null) bad ("Unexpected DocumentData");

        // For each candidate profile do a match try
        for (SignatureProfileEncoder spe : sreqenc.signature_profiles)
          {
            if (sign_prof_data.match (spe,
                                      sreqenc.doc_data,
                                      sreqenc.doc_refs,
                                      sreqenc.server_cookie,
                                      sreqenc.cert_filters,
                                      sreqenc.id,
                                      expected_sha1))
              {
                return;
              }
          }
        throw new IOException ("Mismatch between signature request and response");
      }


    public void copyDocumentData (SignatureRequestEncoder sre) throws IOException
      {
        if (doc_data != null)
          {
            throw new IOException ("DocumentData already present!");
          }
        Document owner = getRootDocument ();
        Element root = getRootElement ();
        sre.doc_data.setPrefix (DOMUtil.getPrefix (root));
        sre.doc_data.setNameSpaceMode (false);
        sre.doc_data.forcedDOMRewrite ();
        Node text =  root.appendChild (owner.createTextNode ("\n"));
        root.insertBefore (sre.doc_data.root = owner.importNode (sre.doc_data.getRootElement (), true), text);
        doc_data = sre.doc_data;
      }


    /////////////////////////////////////////////////////////////////////////////////////////////
    // XML Reader
    /////////////////////////////////////////////////////////////////////////////////////////////

    protected void fromXML (DOMReaderHelper rd) throws IOException
      {
        rd.getChild();
        
        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the signature profile response [1]
        /////////////////////////////////////////////////////////////////////////////////////////
        sign_prof_data = (SignatureProfileResponseDecoder) wrap (rd.getNext ());

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the optional document data [0..1]
        /////////////////////////////////////////////////////////////////////////////////////////
        if (rd.hasNext (DocumentData.DOCUMENT_DATA_ELEM))
          {
            doc_data = DocumentData.read (rd);
          }
      }

  }
