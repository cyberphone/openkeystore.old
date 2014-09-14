package org.webpki.webapps.wcppdemo;

import java.io.IOException;
import java.util.logging.Logger;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.json.JSONDecoderCache;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;
import org.webpki.net.HTTPSWrapper;

public class AuthorizeRequestServlet extends HttpServlet
  {
    private static final long serialVersionUID = 1L;
    
    static Logger logger = Logger.getLogger (AuthorizeRequestServlet.class.getName ());
    
    static int next_transaction_id = 1000000;
    
    public void doPost (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        JSONObjectWriter transact = JSONProperties.createJSONBaseObject (Messages.TRANS_REQ);
        try
          {
            JSONObjectReader authorize_request = JSONParser.parse (request.getParameter ("authreq"));
            logger.info ("Authorize Request:\n" + new String (new JSONObjectWriter (authorize_request).serializeJSONObject (JSONOutputFormats.PRETTY_PRINT), "UTF-8"));
            JSONObjectReader payment_request = authorize_request.getObject (HTML.PAYMENT_REQUEST_JSON);
            String url = authorize_request.getString (HTML.AUTHORIZATION_URL_JSON);
            transact.setObject (HTML.PAYMENT_REQUEST_JSON, payment_request);
            transact.setString (HTML.PAN_JSON, authorize_request.getString (HTML.PAN_JSON));
            transact.setString (HTML.CARD_TYPE_JSON, authorize_request.getString (HTML.CARD_TYPE_JSON));
            HTTPSWrapper https_wrapper = new HTTPSWrapper ();
            https_wrapper.setRequireSuccess (true);
            https_wrapper.makePostRequest (url, transact.serializeJSONObject (JSONOutputFormats.CANONICALIZED));
            JSONObjectReader authorized_result = JSONParser.parse (https_wrapper.getData ());
            logger.info ("Authorized Result:\n" + new String (new JSONObjectWriter (authorized_result).serializeJSONObject (JSONOutputFormats.PRETTY_PRINT), "UTF-8"));
            HTML.resultPage (response, authorized_result, new String (transact.serializeJSONObject (JSONOutputFormats.CANONICALIZED), "UTF-8"));
          }
        catch (Exception e)
          {
            logger.severe (e.getLocalizedMessage ());
          }
      }
  }
