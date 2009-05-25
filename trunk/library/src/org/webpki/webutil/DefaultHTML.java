package org.webpki.webutil;

import java.io.IOException;

import org.webpki.util.HTMLEncoder;
import org.webpki.util.HTMLHeader;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServletResponse;

public class DefaultHTML
  {

    private DefaultHTML () {}


    public static void setHTMLMode (HttpServletResponse response)
      {
        response.setContentType ("text/html; charset=utf-8");
        response.setHeader ("Pragma", "No-Cache");
        response.setDateHeader ("EXPIRES", 0);
      }

    public static void setErrorHTML (HttpServletResponse response, String message, boolean html) throws IOException, ServletException
      {
        setHTMLMode (response);

        StringBuffer s = HTMLHeader.createHTMLHeader (true, false, "Error", null).
           append ("<body><table width=\"100%\" height=\"100%\"><tr><td align=\"center\" valign=\"middle\">" +
           "<table><tr><td align=\"center\" class=\"headline\">Standard Error Report<br>&nbsp;</td></tr><tr><td align=\"left\">").
           append (html ? message : HTMLEncoder.encode (message)).append ("</td></tr></table></td></tr></table></body></html>");

        response.getOutputStream ().print (s.toString ());
     }

  }
