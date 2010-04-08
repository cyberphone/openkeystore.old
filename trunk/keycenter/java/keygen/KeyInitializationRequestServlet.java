package keygen;

import java.io.IOException;

import java.util.Date;

import javax.servlet.ServletException;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

import org.webpki.util.WrappedException;

import org.webpki.keygen2.KeyInitializationRequestEncoder;
import org.webpki.keygen2.PlatformNegotiationResponseDecoder;
import org.webpki.keygen2.KeyGen2KeyUsage;
import org.webpki.keygen2.PassphraseFormats;
import org.webpki.keygen2.PINGrouping;
import org.webpki.keygen2.PatternRestrictions;
import org.webpki.crypto.ECDomains;


@SuppressWarnings("serial")
public class KeyInitializationRequestServlet extends KeyGenServlet
  {    private class KeyCreator      {        KeyInitializationRequestEncoder.PUKPolicy puk;

        KeyInitializationRequestEncoder.PINPolicy pin;

        ProvisioningState prov_state;        boolean preset;

        KeyCreator (KeyInitializationRequestEncoder.PUKPolicy puk, 
                    KeyInitializationRequestEncoder.PINPolicy pin,
                    boolean preset,
                    ProvisioningState prov_state)
          {            this.puk = puk;            this.pin = pin;            this.preset = preset;            this.prov_state = prov_state;
          }
        

        KeyInitializationRequestEncoder.KeyProperties create (KeyGen2KeyUsage key_usage, KeyInitializationRequestEncoder.KeyAlgorithmData key_alg) throws IOException          {
            KeyInitializationRequestEncoder.KeyProperties key_prop = preset ?                prov_state.key_op_req_enc.createKeyWithPresetPIN (key_usage,
                                                                  key_alg,
                                                                  pin,
                                                                  puk,
                                                                  "2478",
                                                                  true,
                                                                  false)                                                                       :
                prov_state.key_op_req_enc.createKey (key_usage,
                                                     key_alg,
                                                     pin,
                                                     puk);            return prov_state.add (key_prop);
          }

        KeyInitializationRequestEncoder.KeyProperties create (KeyGen2KeyUsage key_usage, int rsa_size) throws IOException          {            return create (key_usage, new KeyInitializationRequestEncoder.KeyAlgorithmData.RSA (rsa_size));
          }
      }
    public void protectedPost (HttpServletRequest request, HttpServletResponse response, HttpSession session) throws IOException, ServletException
      {
        ServletContext context = getServletContext ();

        ProvisioningState prov_state = getProvisioningState (session);

        prov_state.exportable_keys = exportableKeys (context);

        PlatformNegotiationResponseDecoder decoder = (PlatformNegotiationResponseDecoder) getXMLObject (request); 
        prov_state.platform_dec = decoder;
        prov_state.client_session_id = decoder.getClientSessionID ();
        KeyInitializationRequestEncoder encoder =
            new KeyInitializationRequestEncoder (decoder.getClientSessionID (),
                                            decoder.getServerSessionID (),
                                            genApplicationURL (request, "kg2_deploy"),
                                            new Date ());        // Not real line...  Cookies should be tested, used, etc.        encoder.setServerCookie (decoder.getServerCookie ());

        prov_state.key_op_req_enc = encoder;        KeyInitializationRequestEncoder.PUKPolicy puk =
                   encoder.createPUKPolicy ("01234567890123456789",
                                            PassphraseFormats.NUMERIC,
                                            3,
                                            true);

       KeyInitializationRequestEncoder.PINPolicy pin = 
                   encoder.createPINPolicy (PassphraseFormats.NUMERIC,
                                            4,
                                            8,
                                            3).setGrouping (PINGrouping.SHARED)
                                              .setPatternRestrictions (new PatternRestrictions[]
                                                  {PatternRestrictions.THREE_IN_A_ROW,
                                                   PatternRestrictions.SEQUENCE});

        KeyCreator key_creator = new KeyCreator (puk,                                                  pin,                                                 new Boolean (context.getInitParameter ("preset-pins")),                                                 prov_state);
        if (wantEncryptedKey (context))
          {
            try              {                KeyStore ks = getKeyArchivalKeyKeyStore (context);
                key_creator.create (KeyGen2KeyUsage.ENCRYPTION, 1024).setPrivateKeyArchivalKey ((X509Certificate) ks.getCertificate (ks.aliases ().nextElement ()));//                key_creator.create (KeyGen2KeyUsage.ENCRYPTION, new KeyInitializationRequestEncoder.KeyAlgorithmData.ECC (ECCDomains.P_256)).setPrivateKeyArchivalKey ((X509Certificate) ks.getCertificate (ks.aliases ().nextElement ()));              }            catch (GeneralSecurityException gse)              {
                throw new WrappedException (gse);              }
          }

        key_creator.create (KeyGen2KeyUsage.AUTHENTICATION, 2048);//        key_creator.create (KeyGen2KeyUsage.AUTHENTICATION, new KeyInitializationRequestEncoder.KeyAlgorithmData.ECC (ECCDomains.P_256));

        key_creator.create (KeyGen2KeyUsage.SYMMETRIC_KEY, 1024);

        KeyInitializationRequestEncoder.ManageObject kmc = encoder.createManageObject ();
        kmc.deleteKeysByContent ().setEmailAddress (getEmailAddress (request));
        kmc.signManageObject (getIssuerCASignatureKey (getServletContext ()));
        if (wantDeferredCertification (context))          {
            encoder.setDeferredCertification (true);          }

        writeXMLObject (response, encoder);
      }
  }
