/*
 *  Copyright 2006-2013 WebPKI.org (http://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.webpki.android.wasp.prof.xds;

import java.io.IOException;

import java.util.Date;

import org.webpki.android.xml.DOMWriterHelper;
import org.webpki.android.xml.DOMReaderHelper;
import org.webpki.android.xml.XMLObjectWrapper;

import org.webpki.android.wasp.DocumentSignatures;
import org.webpki.android.wasp.SignatureResponseEncoder;
import org.webpki.android.wasp.SignatureRequestDecoder;
import org.webpki.android.wasp.SignatureProfileResponseEncoder;

import org.webpki.android.xmldsig.XMLSigner;

import org.webpki.android.crypto.SignerInterface;

import static org.webpki.android.wasp.WASPConstants.*;

import static org.webpki.android.wasp.prof.xds.XDSProfileConstants.*;


public class XDSProfileResponseEncoder extends XMLObjectWrapper implements SignatureProfileResponseEncoder
  {

    private String request_url;

    private Date client_time;

    private String id;

    private byte[] server_certificate_fingerprint;


    private SignatureResponseEncoder s_resp_enc;

    private SignatureRequestDecoder s_req_dec;

    private DocumentSignatures doc_sign;

    XDSProfileRequestDecoder to_decoder;

    String prefix = "pr";  // Default: "pr:"


    protected boolean hasQualifiedElements ()
      {
        return true;
      }


    public void init () throws IOException
      {
        addSchema (XML_SCHEMA_FILE);
      }


    public String namespace ()
      {
        return XML_SCHEMA_NAMESPACE;
      }


    public String element ()
      {
        return RESPONSE_ELEM;
      }


    XDSProfileResponseEncoder (XDSProfileRequestDecoder to_decoder)
      {
        this.to_decoder = to_decoder;
      }


    public XDSProfileResponseEncoder ()
      {
      }


    public void setPrefix (String prefix)
      {
        this.prefix = prefix;
      }


    protected void toXML (DOMWriterHelper wr) throws IOException
      {
        wr.initializeRootObject (prefix);
        //////////////////////////////////////////////////////////////////////////
        // Set top-level attributes
        //////////////////////////////////////////////////////////////////////////
        wr.setStringAttribute (ID_ATTR, id);

        wr.setStringAttribute (SERVER_TIME_ATTR, s_req_dec.getServerTime ());

        wr.setStringAttribute (SUBMIT_URL_ATTR, s_req_dec.getSubmitURL ());

        wr.setStringAttribute (REQUEST_URL_ATTR, request_url);
 
        wr.setDateTimeAttribute (CLIENT_TIME_ATTR, client_time);

        if (server_certificate_fingerprint != null)
          {
            wr.setBinaryAttribute (SERVER_CERT_FP_ATTR, server_certificate_fingerprint);
          }

        //////////////////////////////////////////////////////////////////////////
        // Set the top-level elements
        //////////////////////////////////////////////////////////////////////////
        wr.pushPrefix (s_resp_enc.getPrefix ());
        s_req_dec.getDocumentReferences ().write (wr, true);

        doc_sign.write (wr, true);

        wr.popPrefix ();
      }


    protected void fromXML (DOMReaderHelper helper) throws IOException
      {
        throw new IOException ("Should NEVER be called");
      }


    public void createSignedData (SignerInterface signer,
                                  SignatureResponseEncoder s_resp_enc,
                                  SignatureRequestDecoder s_req_dec,
                                  String request_url,
                                  Date client_time,
                                  byte[] server_certificate_fingerprint) throws IOException
      {
        this.s_resp_enc = s_resp_enc;
        this.s_req_dec = s_req_dec;
        this.request_url = request_url;
        this.client_time = client_time;
        this.id = s_req_dec.getID ();
        this.server_certificate_fingerprint = server_certificate_fingerprint;
        this.doc_sign = new DocumentSignatures (to_decoder.getDigestAlgorithm (),
                                                to_decoder.getDocumentCanonicalizationAlgorithm (),
                                                s_req_dec.getDocumentData ());
        forcedDOMRewrite ();
        getRootElement ().setAttributeNS ("http://www.w3.org/2000/xmlns/",
                                          s_resp_enc.getPrefix () == null ? "xmlns" : "xmlns:" + s_resp_enc.getPrefix (),
                                          WASP_NS);

        XMLSigner ds = new XMLSigner (signer);
        ds.setSignatureAlgorithm (to_decoder.getSignatureAlgorithm ());
        ds.setDigestAlgorithm (to_decoder.getDigestAlgorithm ());
        ds.setTransformAlgorithm (to_decoder.getCanonicalizationAlgorithm ());
        ds.setCanonicalizationAlgorithm  (to_decoder.getCanonicalizationAlgorithm ());
        ds.setExtendedCertPath (to_decoder.getExtendedCertPath ());
        ds.setSignedKeyInfo (to_decoder.getSignedKeyInfo ());

        ds.createEnvelopedSignature (getRootDocument (), id);

        getRootElement ().removeAttributeNS ("http://www.w3.org/2000/xmlns/", 
                                             s_resp_enc.getPrefix () == null ? "xmlns" : s_resp_enc.getPrefix ());
      }

  }
