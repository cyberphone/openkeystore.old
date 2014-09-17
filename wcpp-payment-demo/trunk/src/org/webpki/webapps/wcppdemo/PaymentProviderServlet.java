package org.webpki.webapps.wcppdemo;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.KeyStoreSigner;
import org.webpki.crypto.KeyStoreVerifier;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;
import org.webpki.json.JSONX509Signer;
import org.webpki.json.JSONX509Verifier;

import org.webpki.util.ArrayUtil;

import org.webpki.webutil.ServletUtil;

public class PaymentProviderServlet extends HttpServlet
  {
    private static final long serialVersionUID = 1L;

    static Logger logger = Logger.getLogger (PaymentProviderServlet.class.getName ());
    
    static int transaction_id = 164006;

    public void doPost (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        JSONObjectWriter result = JSONProperties.createJSONBaseObject (Messages.TRANS_RES);
        try
          {
            JSONObjectReader json = JSONProperties.parsePaymentMessage (Messages.TRANS_REQ, ServletUtil.getData (request));
            logger.info ("Transaction Request:\n" + new String (new JSONObjectWriter (json).serializeJSONObject (JSONOutputFormats.PRETTY_PRINT), "UTF-8"));
            JSONObjectReader payee = json.getObject (JSONProperties.PAYMENT_REQUEST_JSON);
            PaymentRequest payment_request = PaymentRequest.parseJSONData (payee);
            if (Init.web_crypto)
              {
                if (!ArrayUtil.compare (json.getBinary (JSONProperties.REQUEST_HASH_JSON),
                                        HashAlgorithms.SHA256.digest (new JSONObjectWriter (payee).serializeJSONObject (JSONOutputFormats.CANONICALIZED))))
                  {
                    throw new IOException ("\"" + JSONProperties.REQUEST_HASH_JSON + "\" mismatch");
                  }
              }
            result.setObject (HTML.PAYMENT_REQUEST_JSON, payee);
            if (Init.web_crypto)
              {
                payee.getSignature ().verify (new JSONX509Verifier (new KeyStoreVerifier (Init.merchant_root)));
              }
            result.setString (JSONProperties.TRANSACTION_ID_JSON, "#" + transaction_id++);
            String pan = json.getString (JSONProperties.PAN_JSON);
            StringBuffer payee_pan = new StringBuffer ();
            for (int i = 0; i < pan.length (); i++)
              {
                if (i != 0 && ((i % 4) == 0))
                  {
                    payee_pan.append (' ');
                  }
                payee_pan.append (i < 12 ? '*' : pan.charAt (i));
              }
            result.setString (JSONProperties.PAYEE_PAN_JSON, payee_pan.toString ());
            result.setString (JSONProperties.CARD_TYPE_JSON, json.getString (JSONProperties.CARD_TYPE_JSON));
            if (Init.web_crypto)
              {
                KeyStoreSigner signer = new KeyStoreSigner (Init.bank_eecert, null);
                signer.setExtendedCertPath (true);
                signer.setKey (null, Init.key_password);
                result.setSignature (new JSONX509Signer (signer).setSignatureCertificateAttributes (true));
              }
            json.checkForUnread ();
          }
        catch (Exception e)
          {
            result = JSONProperties.createJSONBaseObject (Messages.TRANS_RES);
            result.setString (JSONProperties.ERROR_JSON, e.getMessage ());
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
