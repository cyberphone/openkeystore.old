package org.webpki.webapps.wcppdemo;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.KeyStoreSigner;
import org.webpki.crypto.KeyStoreVerifier;
import org.webpki.crypto.VerifierInterface;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;
import org.webpki.json.JSONX509Signer;
import org.webpki.json.JSONX509Verifier;
import org.webpki.util.ArrayUtil;
import org.webpki.util.Base64URL;
import org.webpki.webutil.ServletUtil;

public class PaymentProviderServlet extends HttpServlet implements BaseProperties
  {
    private static final long serialVersionUID = 1L;

    static Logger logger = Logger.getLogger (PaymentProviderServlet.class.getName ());
    
    static int transaction_id = 164006;
    
    private X509Certificate verifyMerchantSignature (JSONObjectReader signed_object) throws IOException
      {
        VerifierInterface verifier = new KeyStoreVerifier (Init.merchant_root);
        signed_object.getSignature ().verify (new JSONX509Verifier (verifier));
        return verifier.getSignerCertificatePath ()[0];
      }

    public void doPost (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        JSONObjectWriter result = Messages.createBaseMessage (Messages.TRANSACTION_RESPONSE);
        try
          {
            JSONObjectReader trans_req = Messages.parseBaseMessage (Messages.TRANSACTION_REQUEST,
                                                                    JSONParser.parse (ServletUtil.getData (request)));
            logger.info ("Transaction Request:\n" + new String (new JSONObjectWriter (trans_req).serializeJSONObject (JSONOutputFormats.PRETTY_PRINT), "UTF-8"));
            JSONObjectReader encrypted_auth_data = trans_req.getObject (AUTH_DATA_JSON).getObject (ENCRYPTED_DATA_JSON);
            JSONObjectReader auth_data = null;
            if (Init.web_crypto)
              {
                auth_data = JSONParser.parse (Base64URL.decode (encrypted_auth_data.getString (CIPHER_TEXT_JSON)));
              }
            else
              {
                auth_data = JSONParser.parse (Base64URL.decode (encrypted_auth_data.getString (CIPHER_TEXT_JSON)));
              }
            JSONObjectReader payee = auth_data.getObject (PAYMENT_REQUEST_JSON);
            PaymentRequest.parseJSONData (payee);  // No DB to store in...
            if (Init.web_crypto)
              {
                if (!ArrayUtil.compare (trans_req.getBinary (REQUEST_HASH_JSON),
                                        HashAlgorithms.SHA256.digest (new JSONObjectWriter (payee).serializeJSONObject (JSONOutputFormats.CANONICALIZED))))
                  {
                    throw new IOException ("\"" + REQUEST_HASH_JSON + "\" mismatch");
                  }
                if (!verifyMerchantSignature (payee).equals (verifyMerchantSignature (trans_req)))
                  {
                    throw new IOException ("Non-matching outer/inner signer");
                  }
              }
            result.setObject (HTML.PAYMENT_REQUEST_JSON, payee);
            result.setString (TRANSACTION_ID_JSON, "#" + transaction_id++);
            String pan = auth_data.getString (PAN_JSON);
            StringBuffer payee_pan = new StringBuffer ();
            for (int i = 0; i < pan.length (); i++)
              {
                if (i != 0 && ((i % 4) == 0))
                  {
                    payee_pan.append (' ');
                  }
                payee_pan.append (i < 12 ? '*' : pan.charAt (i));
              }
            result.setString (REFERENCE_PAN_JSON, payee_pan.toString ());
            result.setString (CARD_TYPE_JSON, auth_data.getString (CARD_TYPE_JSON));
            auth_data.getString (DOMAIN_NAME_JSON);  // We have no DB...
            if (Init.web_crypto)
              {
                KeyStoreSigner signer = new KeyStoreSigner (Init.bank_eecert, null);
                signer.setExtendedCertPath (true);
                signer.setKey (null, Init.key_password);
                result.setSignature (new JSONX509Signer (signer).setSignatureCertificateAttributes (true));
              }
            trans_req.checkForUnread ();
          }
        catch (Exception e)
          {
            result = Messages.createBaseMessage (Messages.TRANSACTION_RESPONSE);
            result.setString (ERROR_JSON, e.getMessage ());
            logger.log (Level.SEVERE, e.getMessage ());
          }
        if (!Init.web_crypto)
          {
            String origin = request.getHeader ("Origin");
            response.setHeader ("Access-Control-Allow-Origin", origin);
          }
        response.setContentType ("application/json; charset=utf-8");
        response.setHeader ("Pragma", "No-Cache");
        response.setDateHeader ("EXPIRES", 0);
        response.getOutputStream ().write (result.serializeJSONObject (JSONOutputFormats.CANONICALIZED));
      }

    @Override
    public void doOptions (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        logger.info ("OPTIONS requested");
        //The following are CORS headers. Max age informs the 
        //browser to keep the results of this call for 1 day.
        response.setHeader ("Access-Control-Allow-Origin", "*");
        response.setHeader ("Access-Control-Allow-Methods", "GET, POST");
        response.setHeader ("Access-Control-Allow-Headers", "Content-Type");
        response.setHeader ("Access-Control-Max-Age", "86400");
        //Tell the browser what requests we allow.
        response.setHeader ("Allow", "GET, HEAD, POST, TRACE, OPTIONS");
      }
  }
