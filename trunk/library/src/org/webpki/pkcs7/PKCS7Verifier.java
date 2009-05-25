package org.webpki.pkcs7;

import java.io.IOException;

import java.math.BigInteger;

import java.security.cert.X509Certificate;
import java.security.Signature;
import java.security.GeneralSecurityException;

import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.crypto.AsymEncryptionAlgorithms;
import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.VerifierInterface;
import org.webpki.crypto.CertificateUtil;

import org.webpki.asn1.ASN1Util;
import org.webpki.asn1.ParseUtil;
import org.webpki.asn1.DerDecoder;
import org.webpki.asn1.Composite;
import org.webpki.asn1.BaseASN1Object;
import org.webpki.asn1.CompositeContextSpecific;
import org.webpki.asn1.ASN1Sequence;
import org.webpki.asn1.cert.DistinguishedName;


public class PKCS7Verifier
  {
    private X509Certificate[] certpath;

    private VerifierInterface verifier_interface;

    private HashAlgorithms digest_algorithm;

    private byte[] message;

    @SuppressWarnings("unused")
    private SignedData signed_data;

    private SignerInfo signer_info;


    class IssuerAndSerialNumber
      {
        DistinguishedName issuer;
        
        BigInteger serial;
        
        IssuerAndSerialNumber (BaseASN1Object issuer_and_serial) throws IOException
          {
            ASN1Sequence seq = ParseUtil.sequence (issuer_and_serial, 2);
            
            issuer = new DistinguishedName (seq.get (0));
            
            serial = ParseUtil.integer (seq.get (1)).value ();
          }
        
        IssuerAndSerialNumber (X509Certificate certificate) throws IOException, GeneralSecurityException
          {
            ASN1Sequence seq = ASN1Util.x509Certificate (certificate);
            
            issuer = DistinguishedName.issuerDN (seq);

            seq = ParseUtil.sequence (seq.get (0));
            
            serial = ParseUtil.integer (seq.get (ParseUtil.isContext (seq.get (0), 0) ? 1 : 0)).value ();
          }
      
        boolean matches (X509Certificate certificate) throws IOException, GeneralSecurityException
          {
            IssuerAndSerialNumber t = new IssuerAndSerialNumber (certificate);
        //System.out.println("SSSSSSSSSS " + serial + " --- " + t.serial);
            return issuer.equals (t.issuer) && serial.equals (t.serial);
          }
        
      }


    private class SignerInfo
      {
        private IssuerAndSerialNumber issuer_and_serial;

        private byte[] encrypted_digest;
        
        
        SignerInfo (BaseASN1Object signerInfo) throws IOException
          {
            ASN1Sequence seq = ParseUtil.sequence (signerInfo);
            
            if (ParseUtil.integer (seq.get (0)).intValue () > 2)
              {
                throw new IOException ("Version > 2");
              }
            
            issuer_and_serial = new IssuerAndSerialNumber (seq.get (1));
            
            if (HashAlgorithms.getAlgorithmFromOID (getAlgorithmIdentifier (seq.get (2))) != digest_algorithm)
              {
                throw new IOException ("Inconsistent digest algorithms");
              }

            int i = 3;
            
            if (seq.get(i) instanceof CompositeContextSpecific)
              {
                throw new IOException ("Authenticated not supported");
              }
            
            if (AsymEncryptionAlgorithms.getAlgorithmFromOID (getAlgorithmIdentifier (seq.get (i++))) != AsymEncryptionAlgorithms.RSA_PKCS_1)
              {
                throw new IOException ("Only RSA is supported by this implementation");
              }
            
            encrypted_digest = ParseUtil.octet (seq.get (i++));
            
            if (seq.size() > i)
              {
                throw new IOException ("Unauthenticated not supported");
              }
          }
  
      }


    private class SignedData
      {

        SignedData (BaseASN1Object signed_data, byte detached_data[]) throws IOException, GeneralSecurityException
          {
            ASN1Sequence contents;
            
            try
              {
                ASN1Sequence top = ParseUtil.sequence (signed_data, 2);

                ParseUtil.oid(top.get(0), PKCS7Signer.PKCS7_SIGNED_DATA);
            
                contents = ParseUtil.sequence (ParseUtil.compositeContext (top.get(1), 0, 1).get (0));
              }
            catch (IOException tme)
              {
                contents = ParseUtil.sequence (signed_data);
              }

            ParseUtil.integer (contents.get (0), 1);
            
            digest_algorithm = HashAlgorithms.getAlgorithmFromOID (getAlgorithmIdentifier (ParseUtil.set (contents.get (1), 1).get(0)));

            if (detached_data != null)
              {
                message = detached_data;
                ParseUtil.oid (ParseUtil.sequence (contents.get (2), 1).get (0), PKCS7Signer.PKCS7_DATA);
              }
            else
              {
                message = ParseUtil.octet (ParseUtil.compositeContext (ParseUtil.seqOIDValue (contents.get (2), PKCS7Signer.PKCS7_DATA), 0, 1).get (0));
              }
            
            int index = 3;
            
            CompositeContextSpecific certs = ParseUtil.compositeContext (contents.get (index), new int[]{ 0, 2 });
            index++;
            
            // Get certificates
            certpath = new X509Certificate [certs.size ()];
            for (int i = 0; i < certs.size (); i++)
              {
                certpath[i] = ParseUtil.sequence (certs.get (i)).x509Certificate ();
              }
            certpath = CertificateUtil.getSortedPath (certpath);

            try
              {
                ParseUtil.compositeContext (contents.get (index), new int[]{ 1, 3 });
                throw new IOException ("CRLs not supported");
              }
            catch (IOException tme)
              {
                // Assume the file contained no CRLs.
              }
            
            Composite signer_infos = ParseUtil.setOrSequence (contents.get (index));
            if (signer_infos.size () > 1)
              {
                throw new IOException ("Only one signature supported");
              }
            signer_info = new SignerInfo (ParseUtil.sequence (signer_infos.get (0)));
          }

        SignedData (BaseASN1Object signed_data) throws IOException, GeneralSecurityException
          {
            this (signed_data, null);
          }
      }


    static String getAlgorithmIdentifier (BaseASN1Object o) throws IOException
      {
        return ParseUtil.oid (ParseUtil.sequence (o).get (0)).oid ();
      }
        

    private void verify () throws IOException, GeneralSecurityException
      {
        if (!signer_info.issuer_and_serial.matches (certpath[0]))
          {
            throw new IOException ("Signer certificate descriptor error");
          }
        Signature verifier = Signature.getInstance (getSignatureAlgorithm ().getJCEName ());
        verifier.initVerify (certpath[0].getPublicKey ());
        verifier.update (message);
        if (!verifier.verify (signer_info.encrypted_digest))
          {
            throw new IOException ("Incorrect signature");
          }
        verifier_interface.verifyCertificatePath (certpath);
      }


    /**
     * Gets the signature algorithm.
     * @return The algorithm identifier.
     */
    public SignatureAlgorithms getSignatureAlgorithm () throws IOException
      {
        for (SignatureAlgorithms alg : SignatureAlgorithms.values ())
          {
            if (alg.getDigestAlgorithm () == digest_algorithm)
              {
                return alg;
              }
          }
        throw new IOException ("Unknown signature algorithm");
      }


    /**
     * Verifies a signed message and returns the signed data.
     * @param message the signed data (PKCS#7 message blob).
     * @return the original data.
     */
    public byte[] verifyMessage (byte message[]) throws IOException
      {
        try
          {
            signed_data = new SignedData (DerDecoder.decode (message));
            verify ();
            return this.message;
          }
        catch (GeneralSecurityException gse)
          {
            throw new IOException (gse.getMessage ());
          }
      }


    /**
     * Verifies a detached (not containing the actual data) signed message.
     * @param message the data to be verified.
     * @param signature the signature (PKCS#7 message blob).
     */
    public void verifyDetachedMessage (byte message[], byte signature[]) throws IOException
      {
        try
          {
            signed_data = new SignedData (DerDecoder.decode (signature), message);
            verify ();
          }
        catch (GeneralSecurityException gse)
          {
            throw new IOException (gse.getMessage ());
          }
      }


    /**
     * Creates a PKCS7Verifier using the given verifier object
     * @param verifier {@link VerifierInterface VerifierInterface} containing the
     * certificates and method needed.
     */
    public PKCS7Verifier (VerifierInterface verifier)
      {
        this.verifier_interface = verifier;
      }

  }
