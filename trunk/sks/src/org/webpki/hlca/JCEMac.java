package org.webpki.hlca;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import java.security.spec.AlgorithmParameterSpec;
import java.security.InvalidKeyException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;

import javax.crypto.MacSpi;

import org.webpki.util.WrappedException;

import org.webpki.crypto.MacAlgorithms;


/**This class must be extended.
 *
 */
public abstract class JCEMac extends MacSpi
  {
    JCEKeyStore.JCESecretKey secret_key;

    MacAlgorithms mac_algorithm;

    int mac_length;
    
    ByteArrayOutputStream baos = new ByteArrayOutputStream ();


    public JCEMac (MacAlgorithms mac_algorithm, int mac_length)
      {
        this.mac_algorithm = mac_algorithm;
        this.mac_length = mac_length;
      }

    public Object clone ()
      {
        return null;
      }

    protected byte[] engineDoFinal ()
      {
        byte[] result = null;
        try
          {
            result = secret_key.getSKS ().performHMAC (secret_key.key_handle,
                                                       mac_algorithm.getURI (),
                                                       secret_key.getAuthorization (),
                                                       baos.toByteArray ());
          }
        catch (IOException e)
          {
            throw new WrappedException (e);
          }
        return result;
      }


    protected int engineGetMacLength ()
      {
        return mac_length;
      } 

    protected void engineInit (Key key, AlgorithmParameterSpec params)
    throws InvalidKeyException, InvalidAlgorithmParameterException
      {
        if (params != null)
          {
            throw new InvalidAlgorithmParameterException ("\"params\" must be null");
          }

        if (!(key instanceof JCEKeyStore.JCESecretKey))
          {
            throw new InvalidKeyException ("Secret key must be an instance of" +
                    JCEKeyStore.JCESecretKey.class.getName ());
          }
        secret_key = (JCEKeyStore.JCESecretKey) key;
      }


    protected void engineReset ()
      {
        baos = new ByteArrayOutputStream ();
      }

    protected void engineUpdate (byte b)
      {
        baos.write (b);
      } 


    protected void engineUpdate (byte[] buf, int off, int len)
      {
        baos.write (buf, off, len);
      }


    public static class MD5 extends JCEMac
      {
        public MD5 ()
          {
            super (MacAlgorithms.HMAC_MD5, 16);
          }
      }


    public static class SHA1 extends JCEMac
      {
        public SHA1 ()
          {
            super (MacAlgorithms.HMAC_SHA1, 20);
          }
      }


    public static class SHA256 extends JCEMac
      {
        public SHA256 ()
          {
            super (MacAlgorithms.HMAC_SHA256, 32);
          }
      }

    public static class SHA384 extends JCEMac
      {
        public SHA384 ()
          {
            super (MacAlgorithms.HMAC_SHA384, 48);
          }
      }

    public static class SHA512 extends JCEMac
      {
        public SHA512 ()
          {
            super (MacAlgorithms.HMAC_SHA512, 64);
          }
      }

  }
