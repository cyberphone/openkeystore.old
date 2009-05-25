package org.webpki.wasp.prof.xds;

import java.io.IOException;

import org.webpki.xml.DOMWriterHelper;
import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.XMLObjectWrapper;

import org.webpki.xmldsig.CanonicalizationAlgorithms;

import org.webpki.wasp.SignatureProfileEncoder;

import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.crypto.HashAlgorithms;

import static org.webpki.wasp.WASPConstants.*;
import static org.webpki.wasp.prof.xds.XDSProfileConstants.*;


public class XDSProfileRequestEncoder extends XMLObjectWrapper implements SignatureProfileEncoder
  {

    String prefix = "pr";  // Default: "pr:"

    boolean signed_key_info;

    boolean extended_cert_path;

    CanonicalizationAlgorithms canonicalization_algorithm;

    HashAlgorithms digest_algorithm;

    SignatureAlgorithms signature_algorithm;

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

    public void setSignedKeyInfo (boolean flag)
      {
        signed_key_info = flag;
      }

    public void setExtendedCertPath (boolean flag)
      {
        extended_cert_path = flag;
      }

    public void setCanonicalizationAlgorithm (CanonicalizationAlgorithms canonicalization_algorithm)
      {
        this.canonicalization_algorithm = canonicalization_algorithm;
      }

    public void setDigestAlgorithm (HashAlgorithms digest_algorithm)
      {
        this.digest_algorithm = digest_algorithm;
      }

    public void setSignatureAlgorithm (SignatureAlgorithms signature_algorithm)
      {
        this.signature_algorithm = signature_algorithm;
      }

    public void setDocumentCanonicalizationAlgorithm (String document_canonicalization_algorithm)
      {
        this.document_canonicalization_algorithm = document_canonicalization_algorithm;
      }

    public void setPrefix (String prefix)
      {
        this.prefix = prefix;
      }


    protected void toXML (DOMWriterHelper wr) throws IOException
      {
        wr.initializeRootObject (prefix);
        //////////////////////////////////////////////////////////////////////////
        // Set top-level attributes (which is all this profile got...)
        //////////////////////////////////////////////////////////////////////////
        if (signed_key_info)
          {
            wr.setBooleanAttribute (SIGNED_KEY_INFO_ATTR, true);
          }

        if (extended_cert_path)
          {
            wr.setBooleanAttribute (EXTENDED_CERT_PATH_ATTR, true);
          }

        if (canonicalization_algorithm != null)
          {
            wr.setStringAttribute (CN_ALG_ATTR, canonicalization_algorithm.getURI ());
          }

        if (digest_algorithm != null)
          {
            wr.setStringAttribute (DIGEST_ALG_ATTR, digest_algorithm.getURI ());
          }

        if (signature_algorithm != null)
          {
            wr.setStringAttribute (SIGNATURE_ALG_ATTR, signature_algorithm.getURI ());
          }

        if (document_canonicalization_algorithm != null)
          {
            wr.setStringAttribute (DOC_CN_ALG_ATTR, document_canonicalization_algorithm);
          }
      }

    protected void fromXML (DOMReaderHelper helper) throws IOException
      {
        throw new IOException ("Should NEVER be called");
      }


  }
