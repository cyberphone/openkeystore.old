package org.webpki.webapps.json.jcs;

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
        HttpSession session = request.getSession (false);
        if (session == null)
          {
            request.getSession (true);
            HTML.browserCheck (response);
          }
        else
          {
            for (Cookie cookie : request.getCookies ())
              {
                if (cookie.getName ().equals (BROWSER_COOKIE))
                  {
                    HTML.webCryptoPage (response, 
                                        ServletUtil.getContextURL (request) + "/request?" + RequestServlet.JCS_ARGUMENT + "=",
                                        cookie.getValue ().equals (MSIE));
                    return;
                  }
              }
            System.out.println ("NO SUPPORT");
            HTML.errorPage (response,  "Unsupported browser");
          }
      }
  }
