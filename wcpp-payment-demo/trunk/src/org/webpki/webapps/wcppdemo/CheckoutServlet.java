package org.webpki.webapps.wcppdemo;

import java.io.IOException;
import java.util.logging.Logger;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.crypto.CustomCryptoProvider;
import org.webpki.crypto.HashAlgorithms;
import org.webpki.json.JSONArrayReader;
import org.webpki.json.JSONArrayWriter;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;

public class CheckoutServlet extends HttpServlet
  {
    private static final long serialVersionUID = 1L;
    
    static final String REQUEST_HASH_ATTR = "REQHASH";
    
    static
      {
        CustomCryptoProvider.forcedLoad ();
      }
    
    static Logger logger = Logger.getLogger (CheckoutServlet.class.getName ());
    
    static int next_reference_id = 1000000;
    
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
        JSONObjectWriter writer = JSONProperties.createJSONBaseObject (Messages.INVOKE);
        JSONArrayWriter aw = writer.setArray (JSONProperties.CARD_TYPES_JSON);
        aw.setString ("NeverHeardOfCard");
        for (CardTypes card_type : MerchantServlet.compatible_with_merchant)
          {
            aw.setString (card_type.toString ());
          }
        JSONObjectWriter payment_request = new PaymentRequest (total).serialize ();
        request.getSession (true).setAttribute (REQUEST_HASH_ATTR, HashAlgorithms.SHA256.digest (payment_request.serializeJSONObject (JSONOutputFormats.CANONICALIZED)));
        writer.setObject (JSONProperties.PAYMENT_REQUEST_JSON, payment_request);
        HTML.checkoutPage (response,
                           saved_shopping_cart,
                           new String (writer.serializeJSONObject (JSONOutputFormats.JS_STRING), "UTF-8"));
      }
  }
