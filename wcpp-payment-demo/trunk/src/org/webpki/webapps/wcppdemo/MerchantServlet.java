package org.webpki.webapps.wcppdemo;

import java.io.IOException;

import java.util.EnumSet;
import java.util.Set;

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
        compatible_with_merchant.add (CardTypes.SUPER_CARD);
        compatible_with_merchant.add (CardTypes.COOL_CARD);
  //      compatible_with_merchant.add (CardTypes.UNUSUAL_CARD);
      }
  
    public void doGet (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
    	HTML.merchantPage (response);
      }
  }
