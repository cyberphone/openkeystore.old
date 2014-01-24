package org.webpki.antcrypto;

import java.io.IOException;

import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.PrivateKey;

import javax.security.auth.x500.X500Principal;

import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;

import org.webpki.util.Base64URL;

import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.MACAlgorithms;
import org.webpki.crypto.CustomCryptoProvider;
import org.webpki.crypto.CertificateUtil;

import org.webpki.crypto.test.DemoKeyStore;

import org.webpki.json.test.Sign;


public class AntCrypto
{
    static
    {
    	CustomCryptoProvider.conditionalLoad ();
    }
    
    static KeyStore getKeyStore (String algorithm) throws Exception
    {
        return AsymSignatureAlgorithms.getAlgorithmFromURI (algorithm).isRSA () ?
        		                        DemoKeyStore.getMybankDotComKeyStore () : DemoKeyStore.getECDSAStore ();
    }

	public static String getPublicKey (String algorithm) throws Exception
	{
		return Base64URL.encode (((X509Certificate)getKeyStore (algorithm).getCertificate ("mykey")).getPublicKey ().getEncoded ());
	}
	
	public static String getKeyID () throws Exception
	{
		return Sign.SYMMETRIC_KEY_NAME;  // To maintain compatibility with the server-demo...
	}

	public static String getX509CertificateParams (String b64_data) throws Exception
	{
		X509Certificate cert = CertificateUtil.getCertificateFromBlob (Base64URL.decode (b64_data));
		return cert.getIssuerX500Principal ().getName () + '\n' + 
		       cert.getSubjectX500Principal ().getName () + '\n' + 
		       cert.getSerialNumber ().toString ();
	}

	public static String getX509Certificate (String algorithm) throws Exception
	{
		return Base64URL.encode (((X509Certificate)getKeyStore (algorithm).getCertificate ("mykey")).getEncoded ());
	}
	
	public static String getDistinguishedName (String b64_data) throws Exception
	{
		return new X500Principal (Base64URL.decode (b64_data)).getName ();
	}
	
	public static String convertToUTF8 (String string) throws Exception
	{
		return Base64URL.encode (string.getBytes ("UTF-8"));
	}

	public static String signData (String b64_data, String algorithm) throws Exception
	{
		if (MACAlgorithms.testAlgorithmURI (algorithm))
		{
			return Base64URL.encode (MACAlgorithms.getAlgorithmFromURI (algorithm).digest (Sign.SYMMETRIC_KEY,
					                                                                       Base64URL.decode (b64_data)));
		}
        Signature s = Signature.getInstance (AsymSignatureAlgorithms.getAlgorithmFromURI (algorithm).getJCEName ());
        s.initSign ((PrivateKey)getKeyStore (algorithm).getKey ("mykey", DemoKeyStore.getSignerPassword ().toCharArray ()));
        s.update (Base64URL.decode (b64_data));
		return Base64URL.encode (s.sign ());
	}

	public static boolean verifySignature (String b64_data, String b64_signature_value, String algorithm, String key_id_or_public_key_in_b64y) throws Exception
	{
		if (MACAlgorithms.testAlgorithmURI (algorithm))
		{
			return signData (b64_data, algorithm).equals (b64_signature_value);
		}
		AsymSignatureAlgorithms asym_alg = AsymSignatureAlgorithms.getAlgorithmFromURI (algorithm);
		Signature s = Signature.getInstance (asym_alg.getJCEName ());
		s.initVerify (KeyFactory.getInstance (asym_alg.isRSA () ? "RSA" : "EC").generatePublic (new X509EncodedKeySpec (Base64URL.decode (key_id_or_public_key_in_b64y))));
		s.update (Base64URL.decode (b64_data));
		return s.verify (Base64URL.decode (b64_signature_value));
	}

}