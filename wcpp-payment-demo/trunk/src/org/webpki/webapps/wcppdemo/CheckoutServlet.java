package org.webpki.webapps.wcppdemo;

import java.io.IOException;
import java.util.logging.Logger;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.json.JSONArrayReader;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONParser;

public class CheckoutServlet extends HttpServlet
  {
    private static final long serialVersionUID = 1L;
    
    static Logger logger = Logger.getLogger (CheckoutServlet.class.getName ());
    
    static int next_transaction_id = 1000000;
    
    public void doPost (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        JSONArrayReader ar = JSONParser.parse (request.getParameter ("shoppingcart")).getJSONArrayReader ();
        logger.info ("Checkout");
        HTML.checkoutPage (response, JSONParser.parse (request.getParameter ("shoppingcart")).getJSONArrayReader ());
      }
  }
