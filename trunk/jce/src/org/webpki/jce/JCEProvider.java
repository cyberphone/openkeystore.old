package org.webpki.jce;

import java.security.Provider;


/**
 * JCE Provider.
 */
@SuppressWarnings("serial")
public final class JCEProvider extends Provider
  {
    private static String info = "WebPKI.org Security Provider v0.10";

    public static String PROVIDER_NAME = "VSE";


    /**
     * Construct a new provider.  This should only be required when
     * using runtime registration of the provider using the
     * <code>Security.addProvider()</code> mechanism.
     */
    public JCEProvider ()
      {
        super (PROVIDER_NAME, 1.41, info);
        //KeyStore
        put ("KeyStore.VSE", JCEKeyStore.class.getName ());

        //Signature
        put ("Signature.SHA1withRSA",   JCESignature.SHA1.class.getName ());
        put ("Signature.SHA256withRSA", JCESignature.SHA256.class.getName ());
        put ("Signature.SHA384withRSA", JCESignature.SHA384.class.getName ());
        put ("Signature.SHA512withRSA", JCESignature.SHA512.class.getName ());

        //Mac
        put ("Mac.HmacMD5",    JCEMac.MD5.class.getName ());
        put ("Mac.HmacSHA1",   JCEMac.SHA1.class.getName ());
        put ("Mac.HmacSHA256", JCEMac.SHA256.class.getName ());
        put ("Mac.HmacSHA384", JCEMac.SHA384.class.getName ());
        put ("Mac.HmacSHA512", JCEMac.SHA512.class.getName ());
      }

/*
  public void setParameter(String parameterName, Object parameter)
    {
        ProviderUtil.setParameter(parameterName, parameter);
    }
*/
}
