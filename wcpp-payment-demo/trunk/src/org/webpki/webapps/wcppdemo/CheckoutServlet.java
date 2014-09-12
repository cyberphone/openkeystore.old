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
        SavedShoppingCart saved_shopping_cart = new SavedShoppingCart ();
        int total = 0;
        while (ar.hasMore ())
          {
            JSONObjectReader or = ar.getObject ();
            int units = or.getInt ("units");
            if (units != 0)
              {
                String sku = or.getString ("sku");
                saved_shopping_cart.items.put (sku, units);
                logger.info ("SKU=" + sku + " Units=" + units);
                total += units * or.getInt ("price_mult_100");
              }
          }
        saved_shopping_cart.total = total;
        request.getSession (true).setAttribute (SavedShoppingCart.SAVED_SHOPPING_CART, saved_shopping_cart);
        HTML.checkoutPage (response, saved_shopping_cart);
      }
  }
