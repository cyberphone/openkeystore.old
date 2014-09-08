package org.webpki.webapps.wcppdemo;

import java.io.IOException;

import java.util.EnumSet;
import java.util.Set;
import java.util.Vector;
import java.util.logging.Logger;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class MerchantServlet extends HttpServlet
  {
    private static final long serialVersionUID = 1L;
    
    static Logger logger = Logger.getLogger (MerchantServlet.class.getName ());
    
    static Set<CardTypes> compatible_with_merchant = EnumSet.noneOf (CardTypes.class);

    static
      {
        compatible_with_merchant.add (CardTypes.SuperCard);
        compatible_with_merchant.add (CardTypes.CoolCard);
  //      compatible_with_merchant.add (CardTypes.UNUSUAL_CARD);
      }

    static Vector<ProductEntry> products = new Vector<ProductEntry> ();
    
    static
      {
        products.add (new ProductEntry ("product-car.png", "Sports Car", 8599900, "7d688")); 
        products.add (new ProductEntry ("product-icecream.png", "Ice Cream", 325, "90555")); 
      }
    
    public void doGet (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        HTML.merchantPage (response);
      }
  }
