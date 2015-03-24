package keygen;

import java.io.IOException;
import java.io.Serializable;

import java.util.HashMap;
import java.util.Date;
import java.util.GregorianCalendar;

import java.text.NumberFormat;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PublicKey;

import java.security.cert.X509Certificate;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.webpki.xml.XMLObjectWrapper;
import org.webpki.xml.XMLSchemaCache;

import org.webpki.keygen2.CredentialDeploymentResponseDecoder;
import org.webpki.keygen2.CredentialDeploymentRequestEncoder;
import org.webpki.keygen2.PlatformNegotiationResponseDecoder;
import org.webpki.keygen2.KeyInitializationResponseDecoder;
import org.webpki.keygen2.KeyInitializationRequestEncoder;
import org.webpki.keygen2.KeyGen2KeyUsage;
import org.webpki.keygen2.BasicCapabilities;

import org.webpki.crypto.KeyUsageBits;
import org.webpki.crypto.AsymKeySignerInterface;
import org.webpki.crypto.SignerInterface;
import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.crypto.SymEncryptionAlgorithms;
import org.webpki.crypto.AsymEncryptionAlgorithms;
import org.webpki.asn1.cert.DistinguishedName;

import org.webpki.ca.CertSpec;
import org.webpki.ca.CA;

import org.webpki.util.ImageData;
import org.webpki.util.DebugFormatter;

import org.webpki.infocard.InfoCardWriter;
import org.webpki.infocard.TokenType;
import org.webpki.infocard.ClaimType;

import org.webpki.webutil.ServletUtil;

import org.webpki.net.XBPP;
import misc.ProtectedServlet;
import misc.KeyCenterCommands;
import misc.MiscOTPAuth;


@SuppressWarnings("serial")
public abstract class KeyGenServlet extends ProtectedServlet
  {

    static final String SRV_PROV_STATE = "SRV_PROV_STATE";

    ProvisioningState getProvisioningState (HttpSession session)
      {
        return (ProvisioningState) session.getAttribute (SRV_PROV_STATE);
      }

    class ProvisioningState implements Serializable
      {
        private static final long serialVersionUID = 1L;

        String user_name;

        String email_address;
        boolean exportable_keys;

        String server_session_id;

        String client_session_id;

        KeyInitializationRequestEncoder key_op_req_enc;

        KeyInitializationResponseDecoder key_op_res_dec;

        HashMap<String,KeyInitializationRequestEncoder.KeyProperties> key_props = new HashMap<String,KeyInitializationRequestEncoder.KeyProperties> ();        PlatformNegotiationResponseDecoder platform_dec;

        KeyInitializationRequestEncoder.KeyProperties add (KeyInitializationRequestEncoder.KeyProperties key)
          {
            if (exportable_keys)
              {
                key.setExportable (true);
              }
            key_props.put (key.getID (), key);
            return key;
          }

        KeyInitializationRequestEncoder.KeyProperties get (String key) throws IOException
          {
            KeyInitializationRequestEncoder.KeyProperties found_key_props = key_props.get (key);
            if (found_key_props == null)
              {
                bad ("Missing key: " + key + " in message");
              }
            return found_key_props;
          }
      }

    static XMLSchemaCache schema_cache;

    static
      {
        try
          {
            schema_cache = new XMLSchemaCache ();
            schema_cache.addWrapper (PlatformNegotiationResponseDecoder.class);
            schema_cache.addWrapper (KeyInitializationResponseDecoder.class);
            schema_cache.addWrapper (CredentialDeploymentResponseDecoder.class);
          }
        catch (Exception e)
          {
          }
      }

    protected KeyCenterCommands getCommand ()
      {
        return KeyCenterCommands.USER_ACCOUNT;
      }


    XMLObjectWrapper getXMLObject (HttpServletRequest request) throws IOException
      {
        return schema_cache.parse (ServletUtil.getData (request));
      }


    String genApplicationURL (HttpServletRequest request, String relative_url) throws IOException
      {
        return ServletUtil.getContextURL (request) + "/" + relative_url;
      }


    void writeXMLObject (HttpServletResponse response, XMLObjectWrapper o) throws IOException
      {
        response.setContentType (XBPP.XBPP_MIME_TYPE);
        response.setHeader ("Pragma", "No-Cache");
        response.setDateHeader ("EXPIRES", 0);
        response.getOutputStream ().write (o.writeXML ());
      }


    static class CASignature implements AsymKeySignerInterface
      {
        SignerInterface signer;
        X509Certificate cert;

        CASignature (ServletContext context) throws IOException
          {
            signer = getIssuerCASignatureKey (context);
            cert = signer.prepareSigning (false)[0];
          }

        public byte[] signData (byte[] data, SignatureAlgorithms sign_alg) throws IOException, GeneralSecurityException
          {
            return signer.signData (data, sign_alg);
          }

        public PublicKey getPublicKey () throws IOException, GeneralSecurityException
          {
            return cert.getPublicKey ();
          }
      }


    void deployCredentials (ServletContext context, 
                            ProvisioningState prov_state,
                            int user_id,
                            HttpServletRequest request,
                            HttpServletResponse response)
    throws GeneralSecurityException, IOException
      {
        SymEncryptionAlgorithms sym_alg = SymEncryptionAlgorithms.AES256_CBC;
        AsymEncryptionAlgorithms asym_alg = AsymEncryptionAlgorithms.RSA_PKCS_1;
        BasicCapabilities capabilities = prov_state.platform_dec.getBasicCapabilities ();        if (!capabilities.getSymmetricKeyEncryptionAlgorithms ().isEmpty () &&
            !capabilities.getSymmetricKeyEncryptionAlgorithms ().contains (SymEncryptionAlgorithms.AES256_CBC))
          {
            sym_alg = SymEncryptionAlgorithms.AES128_CBC;
          }

        CredentialDeploymentRequestEncoder encoder =
            new CredentialDeploymentRequestEncoder (genApplicationURL (request, "kg2_finish"),
                                                    new Date (),
                                                    new CredentialDeploymentRequestEncoder.PresetValueSecurity (prov_state.key_op_res_dec.getDeviceKeyAttestationKey ()[0],                                                                                                                asym_alg,                                                                                                                sym_alg),
                                                    prov_state.key_op_req_enc);

        GenCardLogo card_logo = new GenCardLogo (prov_state.user_name);

        for (KeyInitializationResponseDecoder.GeneratedPublicKey key : prov_state.key_op_res_dec.getGeneratedPublicKeys ())
          {
            KeyInitializationRequestEncoder.KeyProperties key_prop = prov_state.get (key.getID ());
            boolean otp = key_prop.getKeyUsage () == KeyGen2KeyUsage.SYMMETRIC_KEY;
            boolean auth = key_prop.getKeyUsage () == KeyGen2KeyUsage.AUTHENTICATION;
            CertSpec cert_spec = new CertSpec ();
            if (!otp)
              {
                // OTP certificates are just for transport
                cert_spec.setEndEntityConstraint ();
                if (auth)
                  {
                    cert_spec.setKeyUsageBit (KeyUsageBits.digitalSignature);
                    cert_spec.setKeyUsageBit (KeyUsageBits.keyAgreement);
                  }
                else
                  {
                    cert_spec.setKeyUsageBit (KeyUsageBits.dataEncipherment);
                    cert_spec.setKeyUsageBit (KeyUsageBits.keyEncipherment);
                  }
              }
            cert_spec.setSubject ("CN=" + prov_state.user_name + ", E=" + prov_state.email_address +
                                  (otp ? ", OU=OTP Key" : ""));

            GregorianCalendar start = new GregorianCalendar ();
            GregorianCalendar end = (GregorianCalendar) start.clone ();
            end.set (GregorianCalendar.YEAR, end.get (GregorianCalendar.YEAR) + 25);

            CASignature ca_sign = new CASignature (context);
            X509Certificate certificate = 
                new CA ().createCert (cert_spec,
                                      DistinguishedName.subjectDN (ca_sign.cert),
                                      new BigInteger (String.valueOf (new Date ().getTime ())),
                                      start.getTime (),
                                      end.getTime (), 
                                      SignatureAlgorithms.RSA_SHA1,
                                      ca_sign,
                                      key.getPublicKey ());
            CredentialDeploymentRequestEncoder.CertifiedPublicKey cred = encoder.addCertifiedPublicKey (key.getID (), certificate);
            if (otp)
              {
                GenAppLogo app_logo = new GenAppLogo (user_id);
                NumberFormat nf = NumberFormat.getInstance ();
                nf.setMinimumIntegerDigits (6);
                nf.setGroupingUsed (false);
                cred.setSymmetricKey (DebugFormatter.getByteArrayFromHex (MiscOTPAuth.COMMON_HOTP_DEMO_SECRET),
                                      new String[]{"http://www.w3.org/2000/09/xmldsig#hmac-sha1"})
                      .setFriendlyName ("MyBank OTP")
                      .addLogotype (new ImageData (app_logo.getData (), app_logo.getMimeType ()), app_logo.getType ())
                      .addLogotype (new ImageData (card_logo.getData (), card_logo.getMimeType ()), card_logo.getType ())
                      .addPropertyBag (org.webpki.keygen2.KeyGen2URIs.OTPPROVIDERS.IETF_HOTP)
                        .addProperty ("LoginID", "C" + nf.format (user_id), false)
                        .addProperty ("Digits", "8", false)
                        .addProperty ("Counter", "0", true);
              }
            else if (auth)
              {
                InfoCardWriter icw = new InfoCardWriter (certificate,
                                                         TokenType.SAML_1_0,
                                                         "http://infocard.example.com/1234567",
                                                         "http://example.com",
                                                         "https://sts.example.com/tokenservice",
                                                         "https://sts.example.com/metadata");
                icw.addClaim (ClaimType.EMAIL_ADDRESS, "boss@fire.hell")
                   .addClaim (ClaimType.COUNTRY)
                   .setCardName ("WebPKI.org")
                   .setCardImage (card_logo)
                   .setRequireAppliesTo (true)
                   .setOutputSTSIdentity (true)
                   .setPrivacyNotice ("http://example.com/priv")
                   .addTokenType (TokenType.SAML_2_0);
                cred.addExtension (icw.getInfoCard (getIssuerCASignatureKey (context)),
                                   "http://schemas.xmlsoap.org/ws/2005/05/identity")
                  .addLogotype (new ImageData (card_logo.getData (), card_logo.getMimeType ()), card_logo.getType ());
              }
          }
        writeXMLObject (response, encoder);
      }

    boolean exportableKeys (ServletContext context) throws IOException
      {
        return new Boolean (context.getInitParameter ("exportable-keys"));
      }

    boolean wantEncryptedKey (ServletContext context) throws IOException
      {
        return new Boolean (context.getInitParameter ("want-encrypted-key"));
      }
    boolean wantDeferredCertification (ServletContext context) throws IOException
      {
        return new Boolean (context.getInitParameter ("deferred-certification"));
      }

  }
