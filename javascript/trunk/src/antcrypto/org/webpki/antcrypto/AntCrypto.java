package org.webpki.antcrypto;

import java.io.IOException;

import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.PrivateKey;

import org.bouncycastle.jce.X509Principal;

import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;

import org.webpki.util.Base64URL;

import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.MACAlgorithms;
import org.webpki.crypto.CustomCryptoProvider;
import org.webpki.crypto.CertificateUtil;

import org.webpki.crypto.test.DemoKeyStore;

public class AntCrypto
{
    public static final byte[] SYMMETRIC_KEY = {(byte)0xF4, (byte)0xC7, (byte)0x4F, (byte)0x33, (byte)0x98, (byte)0xC4, (byte)0x9C, (byte)0xF4,
                                                (byte)0x6D, (byte)0x93, (byte)0xEC, (byte)0x98, (byte)0x18, (byte)0x83, (byte)0x26, (byte)0x61,
                                                (byte)0xA4, (byte)0x0B, (byte)0xAE, (byte)0x4D, (byte)0x20, (byte)0x4D, (byte)0x75, (byte)0x50,
                                                (byte)0x36, (byte)0x14, (byte)0x10, (byte)0x20, (byte)0x74, (byte)0x34, (byte)0x69, (byte)0x09};

    static
    {
    	CustomCryptoProvider.conditionalLoad (true);
    }
    
    static KeyStore getKeyStore (String algorithm) throws Exception
    {
        return AsymSignatureAlgorithms.getAlgorithmFromID (algorithm).isRSA () ?
        		                       DemoKeyStore.getMybankDotComKeyStore () : DemoKeyStore.getECDSAStore ();
    }

	public static String getPublicKey (String algorithm) throws Exception
	{
		return Base64URL.encode (((X509Certificate)getKeyStore (algorithm).getCertificate ("mykey")).getPublicKey ().getEncoded ());
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
		return new X509Principal (Base64URL.decode (b64_data)).getName ();
	}
	
	public static String convertToUTF8 (String string) throws Exception
	{
		return Base64URL.encode (string.getBytes ("UTF-8"));
	}

	public static String signData (String b64_data, String algorithm) throws Exception
	{
		if (MACAlgorithms.testAlgorithmURI (algorithm))
		{
			return Base64URL.encode (MACAlgorithms.getAlgorithmFromID (algorithm).digest (SYMMETRIC_KEY,
					                                                                      Base64URL.decode (b64_data)));
		}
        Signature s = Signature.getInstance (AsymSignatureAlgorithms.getAlgorithmFromID (algorithm).getJCEName ());
        s.initSign ((PrivateKey)getKeyStore (algorithm).getKey ("mykey", DemoKeyStore.getSignerPassword ().toCharArray ()));
        s.update (Base64URL.decode (b64_data));
		return Base64URL.encode (s.sign ());
	}

	public static boolean verifySignature (String b64_data, String b64_signature_value, String algorithm, String public_key_b64) throws Exception
	{
		if (MACAlgorithms.testAlgorithmURI (algorithm))
		{
			return signData (b64_data, algorithm).equals (b64_signature_value);
		}
		AsymSignatureAlgorithms asym_alg = AsymSignatureAlgorithms.getAlgorithmFromID (algorithm);
		Signature s = Signature.getInstance (asym_alg.getJCEName ());
		s.initVerify (KeyFactory.getInstance (asym_alg.isRSA () ? "RSA" : "EC").generatePublic (new X509EncodedKeySpec (Base64URL.decode (public_key_b64))));
		s.update (Base64URL.decode (b64_data));
		return s.verify (Base64URL.decode (b64_signature_value));
	}

}