package org.webpki.webapps.wcppdemo;

import java.io.IOException;

import java.util.logging.Logger;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;

import org.webpki.webutil.ServletUtil;

public class PaymentProviderServlet extends HttpServlet
  {
    private static final long serialVersionUID = 1L;

    static Logger logger = Logger.getLogger (PaymentProviderServlet.class.getName ());
    
    static int transaction_id = 164006;

    public void doPost (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        JSONObjectReader json = JSONParser.parse (ServletUtil.getData (request));
        logger.info ("Authorization Request:\n" + new String (new JSONObjectWriter (json).serializeJSONObject (JSONOutputFormats.PRETTY_PRINT), "UTF-8"));
        JSONObjectWriter result = new JSONObjectWriter ();
        result.setObject ("Request", json.getObject ("Request"));
        result.setString ("TransactionID", "#" + transaction_id++);
        String pan = json.getString ("PAN");
        StringBuffer payee_pan = new StringBuffer ();
        for (int i = 0; i < pan.length (); i++)
          {
            if (i != 0 && ((i % 4) == 0))
              {
                payee_pan.append (' ');
              }
            payee_pan.append (i < 12 ? '*' : pan.charAt (i));
          }
        result.setString ("PayeePAN", payee_pan.toString ());
        result.setString ("CardType", json.getString ("CardType"));
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
