package org.webpki.webapps.wcppdemo;

import java.io.IOException;

import java.util.Date;

import java.util.logging.Logger;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.KeyStoreSigner;
import org.webpki.crypto.KeyStoreVerifier;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;
import org.webpki.json.JSONX509Signer;
import org.webpki.json.JSONX509Verifier;

import org.webpki.net.HTTPSWrapper;

import org.webpki.util.ArrayUtil;

public class AuthorizeRequestServlet extends HttpServlet implements BaseProperties
  {
    private static final long serialVersionUID = 1L;
    
    static Logger logger = Logger.getLogger (AuthorizeRequestServlet.class.getName ());
    
    static int next_transaction_id = 1000000;
    
    public void doPost (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        JSONObjectWriter transact = Messages.createBaseMessage (Messages.TRANSACTION_REQUEST);
        String error_message = null;
        PaymentRequest payment_request = null;
        String card_type = null;
        String reference_pan = null;
        JSONObjectReader authorized_result = null;
        try
          {
            JSONObjectReader auth_req = Messages.parseBaseMessage (Messages.AUTHORIZE,
                                                                   JSONParser.parse (request.getParameter ("authreq")));
            logger.info ("Authorize Request:\n" + new String (new JSONObjectWriter (auth_req).serializeJSONObject (JSONOutputFormats.PRETTY_PRINT), "UTF-8"));
            String auth_url = auth_req.getString (AUTH_URL_JSON);
            HttpSession session = request.getSession (false);
            if (session == null || session.getAttribute (CheckoutServlet.REQUEST_HASH_ATTR) == null)
              {
                throw new IOException ("\"" + CheckoutServlet.REQUEST_HASH_ATTR + "\" not available");
              }
            byte[] request_hash = (byte[])session.getAttribute (CheckoutServlet.REQUEST_HASH_ATTR);
            transact.setBinary (REQUEST_HASH_JSON, request_hash);
            transact.setObject (AUTH_DATA_JSON, auth_req.getObject (AUTH_DATA_JSON));
            transact.setString (CLIENT_IP_ADDRESS_JSON, request.getRemoteAddr());
            transact.setString (TRANSACTION_ID_JSON, "#" + next_transaction_id++);
            transact.setDateTime (DATE_TIME_JSON, new Date(), true);
            KeyStoreSigner signer = new KeyStoreSigner (Init.merchant_eecert_key, null);
            signer.setExtendedCertPath (true);
            signer.setKey (null, Init.key_password);
            transact.setSignature (new JSONX509Signer (signer).setSignatureCertificateAttributes (true));
            HTTPSWrapper https_wrapper = new HTTPSWrapper ();
            https_wrapper.setRequireSuccess (true);
            https_wrapper.makePostRequest (auth_url, transact.serializeJSONObject (JSONOutputFormats.CANONICALIZED));
            authorized_result = Messages.parseBaseMessage (Messages.TRANSACTION_RESPONSE,
                                                           JSONParser.parse (https_wrapper.getData ()));
            logger.info ("Authorized Result:\n" + new String (new JSONObjectWriter (authorized_result).serializeJSONObject (JSONOutputFormats.PRETTY_PRINT), "UTF-8"));
            if (authorized_result.hasProperty (ERROR_JSON))
              {
                logger.severe (error_message = authorized_result.getString (ERROR_JSON));
              }
            else
              {
                JSONObjectReader copy = authorized_result.getObject (PAYMENT_REQUEST_JSON);
                payment_request = PaymentRequest.parseJSONData (copy);
                copy.getSignature ();                   // Just to keep the parser happy...
                if (!ArrayUtil.compare (HashAlgorithms.SHA256.digest (new JSONObjectWriter (copy).serializeJSONObject (JSONOutputFormats.CANONICALIZED)),
                                        request_hash))
                  {
                    throw new IOException ("Request copy mis-match");
                  }
                card_type = authorized_result.getString (CARD_TYPE_JSON);
                reference_pan = authorized_result.getString (REFERENCE_PAN_JSON);
              }
            authorized_result.getSignature ().verify (new JSONX509Verifier (new KeyStoreVerifier (Init.payment_root)));
            authorized_result.getBinary (PAYMENT_TOKEN_JSON);   // No DB etc yet...
            authorized_result.getString (TRANSACTION_ID_JSON);  // No DB etc yet...
            authorized_result.getDateTime (DATE_TIME_JSON);     // No DB etc yet...
            authorized_result.checkForUnread ();
          }
        catch (Exception e)
          {
            logger.severe (error_message = "Exception: " + e.getMessage ());
          }
        HTML.resultPage (response,
                         error_message,
                         payment_request,
                         card_type, 
                         reference_pan,
                         new String (transact.serializeJSONObject (JSONOutputFormats.CANONICALIZED), "UTF-8"),
                         authorized_result == null ? "N/A" : new String (new JSONObjectWriter (authorized_result).serializeJSONObject (JSONOutputFormats.CANONICALIZED), "UTF-8"));
      }
  }
