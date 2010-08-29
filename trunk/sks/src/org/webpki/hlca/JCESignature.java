package org.webpki.hlca;

import java.io.IOException;

import java.security.SignatureSpi;
import java.security.SignatureException;
import java.security.GeneralSecurityException;
import java.security.AlgorithmParameters;
import java.security.spec.AlgorithmParameterSpec;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.InvalidKeyException;

import org.webpki.util.WrappedException;
import org.webpki.crypto.SignatureAlgorithms;


/**This class must be extended.
 *
 */
@SuppressWarnings("deprecation")
public abstract class JCESignature extends SignatureSpi
  {
    
    private JCEKeyStore.JCEPrivateKey private_key;

    private SignatureAlgorithms signature_algorithm; // RSA_SHA-1 etc.

    private Digester digester;
   
    
    /** Creates a new instance of JCESignature */
    public JCESignature (SignatureAlgorithms signature_algorithm)
      {
        this.signature_algorithm = signature_algorithm;
        try
          {
            digester = new Digester (signature_algorithm);
          }
        catch (GeneralSecurityException gse)
          {
            throw new WrappedException (gse);
          }
      }
    
    void setsignature_algorithmorithm (SignatureAlgorithms signature_algorithm)
      {
        this.signature_algorithm = signature_algorithm;
      }


    /**Returns a clone if the implementation is cloneable. */
    public Object clone ()
      {
        return null;
      }


    /** Deprecated.*/
    @Override
    protected Object engineGetParameter (String param)
      {
        return null;
      } 


    /**This method is overridden by providers to return the parameters 
     * used with this signature engine, or null if this signature engine 
     * does not use any parameters. */    
    @Override
    protected  AlgorithmParameters engineGetParameters ()
      {
        return null;
      }


    /**Initializes this signature object with the specified private key for 
     * signing operations. */
    @Override
    protected void engineInitSign (PrivateKey privateKey) throws InvalidKeyException
      {
        if (!(privateKey instanceof JCEKeyStore.JCEPrivateKey))
          {
            throw new InvalidKeyException ("Private key must be an instance of" +
                                           JCEKeyStore.JCEPrivateKey.class.getName ());
          }
        this.private_key = (JCEKeyStore.JCEPrivateKey)privateKey;
      }


    /**Initializes this signature object with the specified private key (and 
     * source of randomness for signing operations => not used). */
    @Override
    protected void engineInitSign (PrivateKey privateKey, SecureRandom random) throws InvalidKeyException
      {
        engineInitSign (privateKey);
      } 


    /**Initializes this signature object with the specified public key for 
     * verification operations. */
    @Override
    protected void engineInitVerify (PublicKey publicKey) throws InvalidKeyException
      {
        throw new InvalidKeyException ("Verification not implemented. Use another provider instead.");
      } 


    /**This method is overridden by providers to initialize this signature 
     * engine with the specified parameter set. */
    @Override
    protected void engineSetParameter (AlgorithmParameterSpec params)
      {
        return;
      }


    /**Deprecated. Replaced by engineSetParameter.*/
    @Override
    protected void engineSetParameter (String param, Object value)
      {
        return;
      }


    /**Returns the signature bytes of all the data updated so far.*/
    @Override
    protected byte[] engineSign () throws SignatureException
      {
        if (private_key == null)
          {
            throw new SignatureException ("initSign must be called first");
          }
        byte[] result = null;
        try
          {
            result = private_key.getSKS ().signHashedData (private_key.key_handle,
                                                           signature_algorithm.getURI (),
                                                           private_key.getAuthorization (),
                                                           digester.digest ());
          }
        catch (GeneralSecurityException gse)
          {
            throw new SignatureException (gse.getMessage());
          }
        catch (IOException e)
          {
            throw new SignatureException (e.getMessage());
          }
        return result;
      }


    /**Finishes this signature operation and stores the resulting signature 
     * bytes in the provided buffer outbuf, starting at offset. */
    @Override
    protected int engineSign (byte[] outbuf, int offset, int len) throws SignatureException
      {
        byte[] signature = engineSign ();
        if (len < signature.length)
          {
            throw new SignatureException ("buffer is too small");
          }
        System.arraycopy (signature, 0, outbuf, offset, signature.length);
        return signature.length;
      }


    /**Updates the data to be signed or verified using the specified byte array. */
    private void engineUpdate (byte[] data) throws SignatureException
      {
        if (private_key == null)
          {
            throw new SignatureException ("initSign must be called first.");
          }
        try
          {
            digester.update (data);
          }
        catch (GeneralSecurityException gse)
          {
            throw new SignatureException (gse.getMessage ());
          }
      } 


    /**Updates the data to be signed or verified using the specified byte. */
    @Override
    protected void engineUpdate (byte b) throws SignatureException
      {
        byte[] data = {b};
        engineUpdate (data);
      } 


    /**Updates the data to be signed or verified, using the specified array of 
     * bytes, starting at the specified offset. */
    @Override
    protected void engineUpdate (byte[] b, int off, int len) throws SignatureException
      {
        byte[] data = new byte[len];
        System.arraycopy (b, off, data, 0, len);
        engineUpdate (data);
      }
          

    /*Updates the data to be signed or verified using the specified ByteBuffer.
    protected void engineUpdate(ByteBuffer input) throws SignatureException{
    }
     */
          

    /**Verifies the passed-in signature. */
    @Override
    protected boolean engineVerify (byte[] sigBytes) throws SignatureException
      {
        throw new SignatureException ("not implemented");
      }
          

    /**Verifies the passed-in signature in the specified array of bytes, 
     * starting at the specified offset. */
    @Override
    protected boolean engineVerify (byte[] sigBytes, int offset, int length) throws SignatureException
      {
        throw new SignatureException ("not implemented");
      }
    

    public static class RSA_NONE extends JCESignature
      {
        public RSA_NONE ()
          {
            super (SignatureAlgorithms.RSA_NONE);
          }
      }

  
    public static class RSA_SHA1 extends JCESignature
      {
        public RSA_SHA1 ()
          {
            super (SignatureAlgorithms.RSA_SHA1);
          }
      }

    public static class RSA_SHA256 extends JCESignature
      {
        public RSA_SHA256 ()
          {
            super (SignatureAlgorithms.RSA_SHA256);
          }
      }

    public static class RSA_SHA384 extends JCESignature
      {
        public RSA_SHA384 ()
          {
            super (SignatureAlgorithms.RSA_SHA384);
          }
      }

    public static class RSA_SHA512 extends JCESignature
      {
        public RSA_SHA512 ()
          {
            super (SignatureAlgorithms.RSA_SHA512);
          }
      }

    public static class ECDSA_NONE extends JCESignature
      {
        public ECDSA_NONE ()
          {
            super (SignatureAlgorithms.ECDSA_NONE);
          }
      }

    public static class ECDSA_SHA1 extends JCESignature
      {
        public ECDSA_SHA1 ()
          {
            super (SignatureAlgorithms.ECDSA_SHA1);
          }
      }

    public static class ECDSA_SHA256 extends JCESignature
      {
        public ECDSA_SHA256 ()
          {
            super (SignatureAlgorithms.ECDSA_SHA256);
          }
      }

    public static class ECDSA_SHA384 extends JCESignature
      {
        public ECDSA_SHA384 ()
          {
            super (SignatureAlgorithms.ECDSA_SHA384);
          }
      }

    public static class ECDSA_SHA512 extends JCESignature
      {
        public ECDSA_SHA512 ()
          {
            super (SignatureAlgorithms.ECDSA_SHA512);
          }
      }

  }

