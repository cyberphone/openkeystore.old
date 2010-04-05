package org.webpki.crypto.test;

import java.io.IOException;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.webpki.util.Base64;

public class ECKeys
  {
    private static ECPublicKey getPub (String s)
      {
        try
          {
            return (ECPublicKey) KeyFactory.getInstance ("EC").generatePublic (new X509EncodedKeySpec (new Base64 ().getBinaryFromBase64String (s)));
          } 
        catch (InvalidKeySpecException e)
          {
          } 
        catch (NoSuchAlgorithmException e)
          {
          } 
        catch (IOException e)
          {
          }
        throw new RuntimeException ("bad");
      }
    
    private static ECPrivateKey getPriv (String s)
      {
        try
          {
            PKCS8EncodedKeySpec key_spec = new PKCS8EncodedKeySpec (new Base64 ().getBinaryFromBase64String (s));
            return (ECPrivateKey) KeyFactory.getInstance ("EC").generatePrivate (key_spec);
          } 
        catch (IOException e1)
          {
          }
        catch (InvalidKeySpecException e)
          {
          }
        catch (NoSuchAlgorithmException e)
          {
          }
        throw new RuntimeException ("bad");
      }

    public static final ECPublicKey PUBLIC_KEY1 = getPub (
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENe7g157Yp0WeIBIgBAK20zWZsQGm+g+3BNM4Lc5a" +
        "ivX1e8INnGpew2NSkqpo3/7F7Ph/WyOhSvmKWpUVCD4m+g==");

    public static final ECPrivateKey PRIVATE_KEY1 = getPriv (
        "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCC8uViCQjj1CykmErhzTiO/XNwfQa8g" +
        "QIzUnNfxA7LFBA==");

    public static final ECPublicKey PUBLIC_KEY2 = getPub (
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELNmN4EKcLIrwkeS6Wp0DqfezIwVVcIxZElZEDUO5" +
        "QthN57nhgQ5FlM0CN3W27BTHLpMJNJrLdYvn46WzbuVUQg==");

    public static final ECPrivateKey PRIVATE_KEY2 = getPriv (
        "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCAwaFhNLbQeIVE4QLp4MH/D1eaRmnce" +
        "hVb7YDmj3N03Kg==");
    
    public static void main (String[] c)
      {
      }

   }
