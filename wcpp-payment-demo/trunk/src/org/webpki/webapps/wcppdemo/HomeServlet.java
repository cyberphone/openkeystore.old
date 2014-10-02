package org.webpki.webapps.wcppdemo;

import java.io.IOException;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

public class HomeServlet extends HttpServlet
  {
    private static final long serialVersionUID = 1L;
    
    static final String WEB_CRYPTO_ENABLED = "WebCryptoEnabled";
    
    static boolean isWebCryptoEnabled (HttpServletRequest request)
      {
        HttpSession session = request.getSession (false);
        if (session != null)
          {
            Boolean bool = (Boolean) session.getAttribute (WEB_CRYPTO_ENABLED);
            if (bool != null)
              {
                return bool;
              }
          }
        return false;
      }
    
    public void doGet (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        if (Init.web_crypto)
          {
            HttpSession session = request.getSession ();
            session.setAttribute (WEB_CRYPTO_ENABLED, new Boolean (cryptoEnabled ()));
          }
        HTML.homePage (cryptoEnabled (), response);
      }

    boolean cryptoEnabled ()
      {
        return false;
      }
  }
