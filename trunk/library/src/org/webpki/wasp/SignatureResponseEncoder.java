package org.webpki.wasp;

import java.io.IOException;

import java.util.Date;

import org.webpki.xml.XMLObjectWrapper;
import org.webpki.xml.DOMWriterHelper;

import org.webpki.crypto.SignerInterface;


public class SignatureResponseEncoder extends SignatureResponse
  {

    private SignatureRequestDecoder sign_req_decoder;

    private SignatureProfileResponseEncoder sign_prof_resp_encoder;

    private boolean called_xml;
    private boolean called_sign;


    private String prefix;  // Default: no prefix


    private void check (boolean test, String error) throws IOException
      {
        if (test) throw new IOException (error);
      }


    public void setPrefix (String prefix) throws IOException
      {
        check (called_sign, "setPrefix MUST be called before createSignedResponse!");
        this.prefix = prefix;
      }


    public String getPrefix ()
      {
        return prefix;
      }


    public void createSignedResponse (SignerInterface signer,
                                      SignatureRequestDecoder sign_req_decoder,
                                      SignatureProfileResponseEncoder sign_prof_resp_encoder,
                                      String request_url,
                                      Date client_time,
                                      byte[] server_certificate_sha1) throws IOException
      {
        check (called_xml, "createSignedResponse MUST be called before XML generation!");
        called_sign = true;
        this.sign_req_decoder = sign_req_decoder;
        this.sign_prof_resp_encoder = sign_prof_resp_encoder;
        sign_prof_resp_encoder.createSignedData (signer,
                                                 this,
                                                 sign_req_decoder,
                                                 request_url,
                                                 client_time,
                                                 server_certificate_sha1);
      }


    protected void toXML (DOMWriterHelper wr) throws IOException
      {
        check (!called_sign, "createSignedResponse not called!");
        called_xml = true;
        wr.initializeRootObject (prefix);
        wr.addWrapped ((XMLObjectWrapper)sign_prof_resp_encoder);
        if (sign_req_decoder.getCopyData ())
          {
            sign_req_decoder.getDocumentData ().write (wr);
          }
      }

  }
