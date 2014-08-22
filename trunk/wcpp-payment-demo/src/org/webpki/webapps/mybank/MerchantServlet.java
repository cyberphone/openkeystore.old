package org.webpki.webapps.mybank;

import java.io.IOException;

import java.util.logging.Logger;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class MerchantServlet extends HttpServlet
  {
    private static final long serialVersionUID = 1L;
    
    static Logger logger = Logger.getLogger (MerchantServlet.class.getName ());

    public void doGet (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
    	HTML.merchantPage (response, this.getServletContext ());
      }
  }
