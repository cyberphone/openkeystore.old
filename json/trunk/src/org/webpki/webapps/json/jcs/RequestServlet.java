package org.webpki.webapps.json.jcs;

import java.io.IOException;

import java.util.logging.Logger;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;

import org.webpki.util.Base64URL;

import org.webpki.webutil.ServletUtil;

public class RequestServlet extends HttpServlet
  {
    private static final long serialVersionUID = 1L;
    
    static Logger logger = Logger.getLogger (RequestServlet.class.getName ());

    static final String JCS_ARGUMENT = "JCS";
    
    static void error (HttpServletResponse response, String error_message) throws IOException, ServletException
      {
        HTML.errorPage (response, error_message);
      }
    
    void verifySignature (HttpServletRequest request, HttpServletResponse response, byte[] signed_json) throws IOException, ServletException
      {
        logger.info ("JSON Signature Verification Entered");
        ReadSignature doc = new ReadSignature ();
        doc.recurseObject (JSONParser.parse (signed_json));
        HTML.printResultPage (response,
            "<table>"  +
            "<tr><td align=\"center\" style=\"font-weight:bolder;font-size:10pt;font-family:arial,verdana\">Verification Result<br>&nbsp;</td></tr>" +
            "<tr><td align=\"left\">" + HTML.newLines2HTML (doc.getResult ()) + "</td></tr>" +
            "<tr><td align=\"left\">Received Message:</td></tr>" +
            "<tr><td align=\"left\">" + HTML.fancyBox ("verify", 
                                                       new String (JSONObjectWriter.parseAndFormat (signed_json, JSONOutputFormats.PRETTY_HTML), "UTF-8")) +
            "</td></tr>" +
            "</table>");
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
            verifySignature (request, response, Base64URL.decode (json));
          }
        catch (IOException e)
          {
            HTML.errorPage (response,  e.getMessage ());
            return;
          }
      }
  }
