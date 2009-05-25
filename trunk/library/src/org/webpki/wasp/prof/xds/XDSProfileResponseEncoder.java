package org.webpki.wasp.prof.xds;

import java.io.IOException;

import java.util.Date;

import org.webpki.xml.DOMWriterHelper;
import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.XMLObjectWrapper;
import org.webpki.xml.ServerCookie;

import org.webpki.wasp.DocumentSignatures;
import org.webpki.wasp.IdentityProviderAssertions;
import org.webpki.wasp.SignatureResponseEncoder;
import org.webpki.wasp.SignatureRequestDecoder;
import org.webpki.wasp.SignatureProfileResponseEncoder;

import org.webpki.xmldsig.XMLSigner;

import org.webpki.crypto.SignerInterface;

import static org.webpki.wasp.WASPConstants.*;
import static org.webpki.wasp.prof.xds.XDSProfileConstants.*;


public class XDSProfileResponseEncoder extends XMLObjectWrapper implements SignatureProfileResponseEncoder
  {

    private String request_url;

    private Date client_time;

    private String id;

    private byte[] server_certificate_sha1;


    private SignatureResponseEncoder s_resp_enc;

    private SignatureRequestDecoder s_req_dec;

    private DocumentSignatures doc_sign;

    private IdentityProviderAssertions idp_assertions;

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


    public void setIdentityProviderAssertions (IdentityProviderAssertions idp_assertions)
      {
        this.idp_assertions = idp_assertions;
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

        if (server_certificate_sha1 != null)
          {
            wr.setBinaryAttribute (SERVER_CERT_SHA1_ATTR, server_certificate_sha1);
          }

        //////////////////////////////////////////////////////////////////////////
        // Set the top-level elements
        //////////////////////////////////////////////////////////////////////////
        wr.pushPrefix (s_resp_enc.getPrefix ());
        s_req_dec.getDocumentReferences ().write (wr, true);

        doc_sign.write (wr, true);

        ServerCookie server_cookie = s_req_dec.getServerCookie ();
        if (server_cookie != null)
          {
            server_cookie.write (wr, WASP_NS);
          }

        if (idp_assertions != null)
          {
            idp_assertions.write (wr, true);
          }

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
                                  byte[] server_certificate_sha1) throws IOException
      {
        this.s_resp_enc = s_resp_enc;
        this.s_req_dec = s_req_dec;
        this.request_url = request_url;
        this.client_time = client_time;
        this.id = s_req_dec.getID ();
        this.server_certificate_sha1 = server_certificate_sha1;
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
