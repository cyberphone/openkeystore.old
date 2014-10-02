package org.webpki.webapps.wcppdemo;

public class WebCryptoHomeServlet extends HomeServlet
  {
    private static final long serialVersionUID = 1L;

    @Override
    boolean cryptoEnabled ()
      {
        return true;
      }
  }
