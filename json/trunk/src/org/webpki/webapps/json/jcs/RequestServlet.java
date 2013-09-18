package org.webpki.webapps.json.jcs;

import java.io.IOException;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.json.JSONDecoderCache;

import org.webpki.util.Base64URL;

import org.webpki.webutil.ServletUtil;

public class RequestServlet extends HttpServlet
  {
    private static final long serialVersionUID = 1L;
    
    static final String JCS_ARGUMENT = "JCS";
    
    JSONDecoderCache json_cache;
    
    static void error (HttpServletResponse response, String error_message) throws IOException, ServletException
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

    void verifySignature (HttpServletRequest request, HttpServletResponse response, byte[] signed_json) throws IOException, ServletException
      {
        ReadSignature doc = (ReadSignature) json_cache.parse (signed_json);
        request.getSession ().setAttribute (JCS_ARGUMENT, signed_json);
        HTML.printResultPage (response,
            "<table>"  +
            "<tr><td align=\"center\" style=\"font-weight:bolder;font-size:10pt;font-family:arial,verdana\">Verification Result<br>&nbsp;</td></tr>" +
            "<tr><td align=\"left\">" + HTML.newLines2HTML (doc.getResult ()) + "</td></tr>" +
 //           "<tr><td align=\"left\">Received Message:<br>" + new String (JSONObjectWriter.parseAndPrint (signed_json, JSONOutputFormats.PRETTY_HTML), "UTF-8") + "</td></tr>" +
            "<tr><td align=\"left\">Received Message:</td></tr>" +
            "<tr><td align=\"left\"><iframe src=\"" + ServletUtil.getContextURL (request) + "/iframe\" width=\"800\" height=\"500\">NO FRAMES?</iframe></td></tr>" +
            "</table></td></td>");
      }
    
    public void doPost (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        if (!request.getContentType ().startsWith ("application/json"))
          {
            error (response, "Request didn't have the proper mime-type: " + request.getContentType ());
            return;
          }
        try
          {
            verifySignature (request, response, ServletUtil.getData (request));
          }
        catch (IOException e)
          {
            HTML.errorPage (response,  e.getMessage ());
            return;
          }
      }

    public void doGet (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        String json = request.getParameter (JCS_ARGUMENT);
        if (json == null)
          {
            error (response, "Request didn't contain a \"" + JCS_ARGUMENT + "\" argment");
            return;
          }
        try
          {
            verifySignature (request, response, Base64URL.getBinaryFromBase64URL (json));
          }
        catch (IOException e)
          {
            HTML.errorPage (response,  e.getMessage ());
            return;
          }
      }
  }
