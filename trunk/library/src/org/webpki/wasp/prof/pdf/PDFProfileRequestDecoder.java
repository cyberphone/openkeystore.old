package org.webpki.wasp.prof.pdf;

import java.io.IOException;

import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMWriterHelper;
import org.webpki.xml.DOMAttributeReaderHelper;
import org.webpki.xml.XMLObjectWrapper;

import org.webpki.wasp.SignatureProfileDecoder;
import org.webpki.wasp.SignatureProfileResponseEncoder;
import org.webpki.xmldsig.CanonicalizationAlgorithms;

import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;

import static org.webpki.wasp.WASPConstants.*;
import static org.webpki.wasp.prof.pdf.PDFProfileConstants.*;

public class PDFProfileRequestDecoder extends XMLObjectWrapper implements SignatureProfileDecoder
  {

    boolean signed_key_info;

    boolean extended_cert_path;

    String canonicalization_algorithm;

    String digest_algorithm;

    String signature_algorithm;

    String document_canonicalization_algorithm;


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
        return REQUEST_ELEM;
      }


    public boolean getExtendedCertPath ()
      {
        return extended_cert_path;
      }


    /////////////////////////////////////////////////////////////////////////////////////////////
    // XML Reader
    /////////////////////////////////////////////////////////////////////////////////////////////

    protected void fromXML (DOMReaderHelper rd) throws IOException
      {
        DOMAttributeReaderHelper ah = rd.getAttributeHelper ();
        //////////////////////////////////////////////////////////////////////////
        // Get the top-level attributes (which is all this profile has...)
        //////////////////////////////////////////////////////////////////////////
        signed_key_info = ah.getBooleanConditional (SIGNED_KEY_INFO_ATTR);

        extended_cert_path = ah.getBooleanConditional (EXTENDED_CERT_PATH_ATTR);

        canonicalization_algorithm = ah.getStringConditional (CN_ALG_ATTR, CanonicalizationAlgorithms.C14N_EXCL.getURI ());

        digest_algorithm = ah.getStringConditional (DIGEST_ALG_ATTR, HashAlgorithms.SHA1.getURI ());

        signature_algorithm = ah.getStringConditional (SIGNATURE_ALG_ATTR, SignatureAlgorithms.RSA_SHA1.getURI ());

        document_canonicalization_algorithm = ah.getStringConditional (DOC_CN_ALG_ATTR, DOC_SIGN_CN_ALG);
      }

    protected void toXML (DOMWriterHelper helper) throws IOException
      {
        throw new IOException ("Should NEVER be called");
      }

    public SignatureProfileResponseEncoder createSignatureProfileResponseEncoder ()
      {
        return new PDFProfileResponseEncoder (this);
      }


    public boolean hasSupportedParameters ()
      {
        return CanonicalizationAlgorithms.testAlgorithmURI (canonicalization_algorithm) &&
               HashAlgorithms.testAlgorithmURI (digest_algorithm) &&
               SignatureAlgorithms.testAlgorithmURI (signature_algorithm) &&
               document_canonicalization_algorithm.equals (DOC_SIGN_CN_ALG);
      }

  }
