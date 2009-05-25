package org.webpki.xmldsig;

import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.PublicKey;

import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.ECPublicKey;

import org.w3c.dom.Text;
import org.w3c.dom.Node;
import org.w3c.dom.Element;
import org.w3c.dom.Document;

import org.webpki.util.Base64;

import org.webpki.xml.XMLObjectWrapper;

import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.ECCDomains;


abstract class XMLSignerCore
  {
    XMLSignerCore () {}

    private XMLSignatureWrapper dsig_wrapper;

    private boolean write_keyinfo_ref_flag;

    private CanonicalizationAlgorithms canonicalization_algorithm = CanonicalizationAlgorithms.C14N_EXCL;

    private CanonicalizationAlgorithms transform_algorithm = CanonicalizationAlgorithms.C14N_EXCL;

    private HashAlgorithms digest_algorithm = HashAlgorithms.SHA256;

    private SignatureAlgorithms signature_algorithm;

    private boolean debug;

    private boolean remove_xml_ns;

    private boolean pretty_printing = true;


    public void setDigestAlgorithm (HashAlgorithms digest_algorithm)
      {
        if (digest_algorithm != null)
          {
            this.digest_algorithm = digest_algorithm;
          }
      }


    public void setSignatureAlgorithm (SignatureAlgorithms signature_algorithm)
      {
        if (signature_algorithm != null)
          {
            this.signature_algorithm = signature_algorithm;
          }
      }


    public void setTransformAlgorithm (CanonicalizationAlgorithms transformAlgorithm)
      {
        if (transformAlgorithm != null)
          {
            transform_algorithm = transformAlgorithm;
          }
      }
   

    public void setCanonicalizationAlgorithm (CanonicalizationAlgorithms canonicalizationAlgorithm)
      {
        if (canonicalizationAlgorithm != null)
          {
            canonicalization_algorithm = canonicalizationAlgorithm;
          }
      }


    public void setSignedKeyInfo (boolean flag)
      {
        write_keyinfo_ref_flag = flag;
      }


    public void setDebug (boolean flag)
      {
        debug = flag;
      }


    public void setPrettyPrinting (boolean flag)
      {
        pretty_printing = flag;
      }


    private void updateBase64Field (Text node, byte[] data) throws IOException
      {
        node.setNodeValue (new Base64(false).getBase64StringFromBinary (data));
      }


    abstract PublicKey populateKeys (XMLSignatureWrapper dsig_wrapper) throws GeneralSecurityException, IOException;

    abstract byte[] getSignatureBlob (byte[] data, SignatureAlgorithms sig_alg) throws GeneralSecurityException, IOException;

    
    private void setupSignatureData () throws GeneralSecurityException, IOException
      {
        dsig_wrapper = new XMLSignatureWrapper ();
        dsig_wrapper.pretty_printing = pretty_printing;
        dsig_wrapper.KeyInfo_Reference_create = write_keyinfo_ref_flag;
        PublicKey public_key = populateKeys (dsig_wrapper);
        if (signature_algorithm == null)
          {
            signature_algorithm = public_key instanceof RSAPublicKey 
                                         ?
                              SignatureAlgorithms.RSA_SHA256
                                         :
                              ECCDomains.getRecommendedSignatureAlgorithm ((ECPublicKey)public_key);
          }

        // Setup all declared algorithms
        dsig_wrapper.canonicalization_algorithm = canonicalization_algorithm;
        dsig_wrapper.transform_algorithm = transform_algorithm;
        dsig_wrapper.digest_algorithm = digest_algorithm;
        dsig_wrapper.signature_algorithm = signature_algorithm;
      }

    private XMLSignatureWrapper createSignature (XMLSignatureWrapper dsig_wrapper, Element root_to_sign)
    throws GeneralSecurityException, IOException
      {

        // Fix the Reference message digests
        byte [] ref1 = XPathCanonicalizer.serializeSubset (root_to_sign, dsig_wrapper.transform_algorithm);
        updateBase64Field (dsig_wrapper.SignedElement_Reference_node, dsig_wrapper.digest_algorithm.digest (ref1));
        if (debug)
          {
            System.out.println ("CREATE\n" + new String (ref1, "UTF-8"));
          }
        if (write_keyinfo_ref_flag)
          {
            byte [] ref2 = XPathCanonicalizer.serializeSubset (dsig_wrapper.KeyInfo_element, dsig_wrapper.transform_algorithm);
            updateBase64Field (dsig_wrapper.KeyInfo_Reference_node, dsig_wrapper.digest_algorithm.digest (ref2));
          }
        // Sign the Reference (SignedInfo)
        byte[] data = XPathCanonicalizer.serializeSubset (dsig_wrapper.SignedInfo_element, dsig_wrapper.canonicalization_algorithm);
        updateBase64Field (dsig_wrapper.SignatureValue_node, getSignatureBlob (data, dsig_wrapper.signature_algorithm));

        if (remove_xml_ns)
          {
            dsig_wrapper.root.removeAttributeNS ("http://www.w3.org/2000/xmlns/", XMLSignatureWrapper.XML_DSIG_NS_PREFIX);
          }
        
        return dsig_wrapper;
      }

 
    /**
     * <p>Creates an enveloped XML signature.  If target_elem <> null then the signature is inserted there
     * else it is inserted at the end of the document.
     * @param root Top node of document to be signed.
     * @param reference_id The mandatory ID element.
     * @param target_elem Where the top element is (null = element root).
     * @param insert_elem Where the Signature is to be inserted (null = element root).
     * @return "root" as is.
     */
    public Document createEnvelopedSignature (Document root, String reference_id, Element target_elem, Element insert_elem) throws IOException
      {
        try
          {
            setupSignatureData ();

            dsig_wrapper.envelope_id = reference_id;

            // Now all has been setup to create a template that is only lacking calculated result
            // However, we must have this template as a DOM tree.  This comes now...
            dsig_wrapper.forcedDOMRewrite ();

            Element elem = root.getDocumentElement ();
            if (target_elem == null)
              {
                target_elem = elem;
              }
            if (insert_elem == null)
              {
                insert_elem = elem;
              }
            Node text = insert_elem.appendChild (root.createTextNode ("\n"));
            insert_elem.insertBefore (root.importNode (createSignature (dsig_wrapper, target_elem).getRootElement (), true), text);
          }
        catch (GeneralSecurityException gse)
          {
            throw new IOException (gse.getMessage ());
          }
        return root;
      }

    /**
     * <p>Creates an enveloped XML signature at the end of the document.
     * @param root Top node of document to be signed.
     * @param reference_id The mandatory ID element.
     * @return "root" as is.
     */
    public Document createEnvelopedSignature (Document root, String reference_id) throws IOException
      {
        return createEnvelopedSignature (root, reference_id, null, null);
      }

    /**
     * <p>Creates an enveloped XML signature.
     * @param param A descriptor.
     * @return Root to signed XML document.
     */
    public Document createEnvelopedSignature (XMLEnvelopedInput param) throws IOException
      {
        return createEnvelopedSignature (param.getEnvelopeRoot (), 
                                         param.getReferenceURI (),
                                         param.getTargetElem (),
                                         param.getInsertElem ());
      }

   
    /**
     * <p>Creates an (enveloping) XML signature.
     * @param document The XML object to be signed.
     * @return XML signature.
     */
    public XMLSignatureWrapper signXMLWrapper (XMLObjectWrapper document, String object_id) throws IOException
      {
        try
          {
            setupSignatureData ();

            // Add the data that we want to sign
            dsig_wrapper.wrappedData = document;
            dsig_wrapper.object_id = object_id;

            // Now all has been setup to create a template that is only lacking calculated result
            // However, we must have this template as a DOM tree.  This comes now...
            dsig_wrapper.forcedDOMRewrite ();

            return createSignature (dsig_wrapper, dsig_wrapper.Object_element);
          }
        catch (GeneralSecurityException gse)
          {
            throw new IOException(gse.getMessage ());
          }
      }


    /**
     * <p>Creates an (enveloping) XML signature.
     * @param document The XML object to be signed.
     * @return XML signature.
     */
    public XMLSignatureWrapper signXMLWrapper (XMLObjectWrapper document) throws IOException
      {
        return signXMLWrapper (document, null);
      }


    public void removeXMLSignatureNS () throws IOException
      {
        if (dsig_wrapper != null)
          {
            throw new IOException ("removeXMLSignatureNS must be called before signatures are created!");
          }
        remove_xml_ns = true;
      }

  }
