package org.webpki.hlca;

import java.security.Provider;
import java.util.HashSet;
import java.util.ServiceLoader;

import org.webpki.crypto.MacAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.sks.DeviceInfo;
import org.webpki.sks.SKSException;
import org.webpki.sks.SecureKeyStore;


/**
 * JCE Provider.
 */
@SuppressWarnings("serial")
public final class JCEProvider extends Provider
  {
    private static String info = "WebPKI.org SecureKeyStore Provider v0.10";

    public static String PROVIDER_NAME = "WebPKI";
    
    private HashSet<String> algorithms;


    /**
     * Construct a new provider.  This should only be required when
     * using runtime registration of the provider using the
     * <code>Security.addProvider()</code> mechanism.
     */
    public JCEProvider ()
      {
        super (PROVIDER_NAME, 1.41, info);
        //KeyStore
        put ("KeyStore.WebPKI", JCEKeyStore.class.getName ());

        SecureKeyStore sks = ServiceLoader.load (SecureKeyStore.class).iterator ().next ();
        try
          {
            DeviceInfo di = sks.getDeviceInfo ();
            algorithms = di.getAlgorithms ();

            /////////////////////////////////////////////////////////////////////////////////
            //Signature
            /////////////////////////////////////////////////////////////////////////////////
            condSignature (SignatureAlgorithms.RSA_NONE,     JCESignature.RSA_NONE.class);
            condSignature (SignatureAlgorithms.RSA_SHA1,     JCESignature.RSA_SHA1.class);
            condSignature (SignatureAlgorithms.RSA_SHA256,   JCESignature.RSA_SHA256.class);
            condSignature (SignatureAlgorithms.RSA_SHA384,   JCESignature.RSA_SHA384.class);
            condSignature (SignatureAlgorithms.RSA_SHA512,   JCESignature.RSA_SHA512.class);
            condSignature (SignatureAlgorithms.ECDSA_NONE,   JCESignature.ECDSA_NONE.class);
            condSignature (SignatureAlgorithms.ECDSA_SHA1,   JCESignature.ECDSA_SHA1.class);
            condSignature (SignatureAlgorithms.ECDSA_SHA256, JCESignature.ECDSA_SHA256.class);
            condSignature (SignatureAlgorithms.ECDSA_SHA384, JCESignature.ECDSA_SHA384.class);
            condSignature (SignatureAlgorithms.ECDSA_SHA512, JCESignature.ECDSA_SHA512.class);

            /////////////////////////////////////////////////////////////////////////////////
            //Mac
            /////////////////////////////////////////////////////////////////////////////////
            condMac (MacAlgorithms.HMAC_MD5,    JCEMac.MD5.class);
            condMac (MacAlgorithms.HMAC_SHA1,   JCEMac.SHA1.class);
            condMac (MacAlgorithms.HMAC_SHA256, JCEMac.SHA256.class);
            condMac (MacAlgorithms.HMAC_SHA384, JCEMac.SHA384.class);
            condMac (MacAlgorithms.HMAC_SHA512, JCEMac.SHA512.class);
           
            // TODO
          }
        catch (SKSException e)
          {
            throw new RuntimeException (e);
          }

        //Mac
      }
    
    void condSignature (SignatureAlgorithms sig_alg, Class<?> class_name)
      {
        if (algorithms.contains (sig_alg.getURI ()))
          {
            put ("Signature." + sig_alg.getJCEName (), class_name.getName ());
          }
      }

    void condMac (MacAlgorithms mac_alg, Class<?> class_name)
      {
        if (algorithms.contains (mac_alg.getURI ()))
          {
            put ("Mac." + mac_alg.getJCEName (), class_name.getName ());
          }
      }
/*
  public void setParameter(String parameterName, Object parameter)
    {
        ProviderUtil.setParameter(parameterName, parameter);
    }
*/
}
