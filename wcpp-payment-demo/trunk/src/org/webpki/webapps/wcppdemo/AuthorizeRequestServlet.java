package org.webpki.webapps.wcppdemo;

import java.io.IOException;
import java.util.logging.Logger;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.webpki.crypto.KeyStoreSigner;
import org.webpki.crypto.KeyStoreVerifier;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;
import org.webpki.json.JSONX509Signer;
import org.webpki.json.JSONX509Verifier;
import org.webpki.net.HTTPSWrapper;

public class AuthorizeRequestServlet extends HttpServlet implements BaseProperties
  {
    private static final long serialVersionUID = 1L;
    
    static Logger logger = Logger.getLogger (AuthorizeRequestServlet.class.getName ());
    
    static int next_transaction_id = 1000000;
    
    public void doPost (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        JSONObjectWriter transact = Messages.createBaseMessage (Messages.TRANSACTION_REQUEST);
        try
          {
            JSONObjectReader auth_req = Messages.parseBaseMessage (Messages.AUTHORIZE,
                                                                   JSONParser.parse (request.getParameter ("authreq")));
            logger.info ("Authorize Request:\n" + new String (new JSONObjectWriter (auth_req).serializeJSONObject (JSONOutputFormats.PRETTY_PRINT), "UTF-8"));
            String auth_url = auth_req.getString (AUTH_URL_JSON);
            if (Init.web_crypto)
              {
                HttpSession session = request.getSession (false);
                if (session == null || session.getAttribute (CheckoutServlet.REQUEST_HASH_ATTR) == null)
                  {
                    throw new IOException ("\"" + CheckoutServlet.REQUEST_HASH_ATTR + "\" not available");
                  }
                transact.setBinary (REQUEST_HASH_JSON, (byte[])session.getAttribute (CheckoutServlet.REQUEST_HASH_ATTR));
              }
            transact.setObject (AUTH_DATA_JSON, auth_req.getObject (AUTH_DATA_JSON));
            if (Init.web_crypto)
              {
                KeyStoreSigner signer = new KeyStoreSigner (Init.merchant_eecert_key, null);
                signer.setExtendedCertPath (true);
                signer.setKey (null, Init.key_password);
                transact.setSignature (new JSONX509Signer (signer).setSignatureCertificateAttributes (true));
              }
            HTTPSWrapper https_wrapper = new HTTPSWrapper ();
            https_wrapper.setRequireSuccess (true);
            https_wrapper.makePostRequest (auth_url, transact.serializeJSONObject (JSONOutputFormats.CANONICALIZED));
            JSONObjectReader authorized_result = JSONParser.parse (https_wrapper.getData ());
            logger.info ("Authorized Result:\n" + new String (new JSONObjectWriter (authorized_result).serializeJSONObject (JSONOutputFormats.PRETTY_PRINT), "UTF-8"));
            boolean success = true;
            if (authorized_result.hasProperty (ERROR_JSON))
              {
                logger.severe (authorized_result.getString (ERROR_JSON));
                success = false;
              }
            authorized_result.getSignature ().verify (new JSONX509Verifier (new KeyStoreVerifier (Init.payment_root)));
            HTML.resultPage (response, success, authorized_result, new String (transact.serializeJSONObject (JSONOutputFormats.CANONICALIZED), "UTF-8"));
          }
        catch (Exception e)
          {
            logger.severe (e.getLocalizedMessage ());
          }
      }
  }
