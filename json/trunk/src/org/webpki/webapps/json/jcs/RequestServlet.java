package org.webpki.webapps.json.jcs;

import java.io.IOException;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.json.JSONDecoderCache;
import org.webpki.json.JSONObjectWriter;

import org.webpki.util.Base64URL;

public class RequestServlet extends HttpServlet
  {
    private static final long serialVersionUID = 1L;
    
    static final String JCS_ARGUMENT = "JCS";
    
    JSONDecoderCache json_cache;
    
    void error (HttpServletResponse response, String error_message) throws IOException, ServletException
      {
        HTML.errorPage (response, error_message);
      }
    
    @Override
    public
    void init ()
      {
        try
          {
            super.init ();
            json_cache = new JSONDecoderCache ();
            json_cache.addToCache (ReadSignature.class);
          }
        catch (ServletException e)
          {
            throw new RuntimeException (e);
          }
        catch (IOException e)
          {
            throw new RuntimeException (e);
          }
      }

    public void doGet (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        request.setCharacterEncoding ("UTF-8");
        String json = request.getParameter (JCS_ARGUMENT);
        if (json == null)
          {
            error (response, "Request didn't contain a \"" + JCS_ARGUMENT + "\" argment");
            return;
          }
        try
          {
            byte[] binary_signature = Base64URL.getBinaryFromBase64URL (json);
            ReadSignature doc = (ReadSignature) json_cache.parse (binary_signature);
            HTML.printResultPage (response, "<table>"  +
                "<tr><td align=\"center\" style=\"font-weight:bolder;font-size:10pt;font-family:arial,verdana\">Verification Result<br>&nbsp;</td></tr>" +
//              "<tr><td align=\"center\">Click <a href=\"" + baseurl + "/browser\">here</a> for testing JCS with a browser</td></tr>" +
              "<tr><td align=\"left\">" + HTML.newLines2HTML (doc.getResult ()) + "</td></tr>" +
              "<tr><td align=\"left\">Received Message:<pre style=\"max-width:800px\">" + HTML.encode (new String (binary_signature, "UTF-8")) + "</pre></td></tr>" +
            "</table></td></td>");

          }
        catch (IOException e)
          {
            HTML.errorPage (response,  e.getMessage ());
            return;
          }
      }
  }
