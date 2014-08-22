package org.webpki.webapps.mybank;

import java.io.IOException;

import javax.servlet.ServletException;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.webpki.webutil.ServletUtil;

public class WebCryptoServlet extends HttpServlet
  {
    private static final long serialVersionUID = 1L;
    
    public static final String BROWSER_COOKIE = "BROWSER";
    public static final String MSIE           = "MSIE";
    public static final String STD            = "WebCrypto";
    
    public void doGet (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
      }
  }
