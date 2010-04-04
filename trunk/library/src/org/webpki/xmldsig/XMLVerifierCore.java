package org.webpki.xmldsig;

import java.io.IOException;

import java.security.Signature;
import java.security.PublicKey;
import java.security.GeneralSecurityException;

import org.w3c.dom.Node;
import org.w3c.dom.Element;

import org.webpki.util.ArrayUtil;

import org.webpki.xml.XMLObjectWrapper;

import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.crypto.HashAlgorithms;


abstract class XMLVerifierCore
  {
    private SignedKeyInfoSpecifier KeyInfo_requirements = SignedKeyInfoSpecifier.FORBID_SIGNED_KEY_INFO;

    private HashAlgorithms digest_algorithm;  // Only tested for main Reference not for keyinfo types

    private SignatureAlgorithms signature_algorithm;

    private boolean debug;


    public void setDebug (boolean flag)
      {
        debug = flag;
      }


    private void checkReference (XMLSignatureWrapper.ReferenceObject ref) throws IOException, GeneralSecurityException
      {
        byte[] ref_cn = XPathCanonicalizer.serializeSubset (ref.element, ref.cn_alg);
        if (debug)
          {
            System.out.println ("READ\n" + new String (ref_cn));
          }
        if (!ArrayUtil.compare (ref.digest_alg.digest(ref_cn), ref.digest_val))
          {
            throw new IOException ("Incorrect message digest id=" + ref.id);
          }
      }
    

    abstract void verify (XMLSignatureWrapper signature) throws IOException, GeneralSecurityException;


    private void checkMainReference (XMLSignatureWrapper signature) throws IOException, GeneralSecurityException
      {
        // Check the mandatory Object/Outer container reference
        digest_algorithm = signature.reference_object_1.digest_alg;
        checkReference (signature.reference_object_1);
      }


    private void checkKeyInfoReference (XMLSignatureWrapper signature) throws IOException, GeneralSecurityException
      {
        // Check the optional KeyInfo reference
        if (signature.reference_object_2 == null)
          {
            if (KeyInfo_requirements == SignedKeyInfoSpecifier.REQUIRE_SIGNED_KEY_INFO)
              {
                throw new IOException ("KeyInfo Reference mode = REQUIRED");
              }
          }
        else
          {
            if (KeyInfo_requirements == SignedKeyInfoSpecifier.FORBID_SIGNED_KEY_INFO)
              {
                throw new IOException ("KeyInfo Reference mode = FORBIDDEN");
              }
            checkReference (signature.reference_object_2);
          }
      }


    void core_verify (XMLSignatureWrapper signature, PublicKey public_key) throws IOException, GeneralSecurityException
      {
        byte[] sign_cn = XPathCanonicalizer.serializeSubset (signature.signedinfo_object.element, signature.signedinfo_object.cn_alg);
        if (this instanceof XMLSymKeyVerifier)
          {
            XMLSymKeyVerifier xmlsym = (XMLSymKeyVerifier) this;
            if (xmlsym.optional_required_algorithm != null &&
                xmlsym.optional_required_algorithm != signature.signedinfo_object.sym_signature_alg)
              {
                throw new IOException ("Wrong HMAC algorithm: " + signature.signedinfo_object.sym_signature_alg.getURI ());
              }
            byte[] hmac = signature.signedinfo_object.sym_signature_alg.digest (xmlsym.symmetric_key, sign_cn);
            if (!ArrayUtil.compare (hmac, signature.signedinfo_object.signature_val))
              {
                throw new IOException ("Incorrect signature for element: " + signature.reference_object_1.element.getNodeName ());
              }
          }
        else
          {
            // Check signature
            signature_algorithm = signature.signedinfo_object.asym_signature_alg;
            Signature verifier = Signature.getInstance (signature.signedinfo_object.asym_signature_alg.getJCEName ());
    
            verifier.initVerify (public_key);
            verifier.update (sign_cn);
    
            if (!verifier.verify (signature.signedinfo_object.signature_val))
              {
                throw new IOException ("Incorrect signature for element: " + signature.reference_object_1.element.getNodeName ());
              }
          }
      }
    

    /**
     * Verifies a signed message and returns the signed data.
     * @param message The enveloping signed XML object.
     * @return the original XML object.
     */
    public XMLObjectWrapper verifyXMLWrapper (XMLSignatureWrapper message) throws IOException
      {
        if (message.wrappedData == null)
          {
            throw new IOException ("Message data not wrapped.");
          }
        try
          {      
            checkMainReference (message);
            checkKeyInfoReference (message);
            verify (message);
          }
        catch (GeneralSecurityException gse)
          {
            throw new IOException (gse.getMessage ());
          }
     
        return message.wrappedData;
      }


    public void setSignedKeyInfo (SignedKeyInfoSpecifier keyinforeq)
      {
        KeyInfo_requirements = keyinforeq;
      }


    public SignatureAlgorithms getSignatureAlgorithm ()
      {
        return signature_algorithm;
      }

    
    public HashAlgorithms getDigestAlgorithm ()
      {
        return digest_algorithm;
      }

    
    /**
     * Verifies an enveloped signed message and returns the signed data.
     * @param parent The enveloped signed XML object.
     * @param element The actual element (null => root).
     * @param signature The enveloped signature.
     * @param id The mandatory ID element.
     * @return XML document "as-is").
     */
    public XMLObjectWrapper validateEnvelopedSignature (XMLObjectWrapper parent,
                                                        Element element,
                                                        XMLSignatureWrapper signature,
                                                        String id) throws IOException
      {
        if (!signature.reference_object_1.enveloped)
          {
            throw new IOException ("Expected enveloped signature");
          }
        if(!signature.reference_object_1.id.equals (id))
          {
            throw new IOException ("Id mismatch (" + signature.reference_object_1.id + ", " + id + ").");
          }

        try
          {
            signature.reference_object_1.element = element == null ? parent.getRootElement () : element;
            checkKeyInfoReference (signature);
            Node signsin = signature.getRootElement ().getNextSibling ();
            Node signpar = signature.getRootElement ().getParentNode ();
            signpar.removeChild (signature.getRootElement ());
            checkMainReference (signature);
            signpar.insertBefore (signature.getRootElement (), signsin);
            verify (signature);
          }
        catch (GeneralSecurityException gse)
          {
            throw new IOException (gse.getMessage ());
          }
        return parent;
      }


    /**
     * Verifies an enveloped signed message.
     * @param parent The enveloped signed XML object.
     * @return "parent" as is.
     */
    public XMLObjectWrapper validateEnvelopedSignature (XMLObjectWrapper parent) throws IOException
      {
        if (!(parent instanceof XMLEnvelopedInput))
          {
            throw new IOException ("Must be an instance of XMLEnvelopedInput");
          }
        XMLEnvelopedInput xei = (XMLEnvelopedInput) parent;
        return validateEnvelopedSignature (parent, xei.getTargetElem (), xei.getSignature (), xei.getReferenceURI ());
      }

  }
