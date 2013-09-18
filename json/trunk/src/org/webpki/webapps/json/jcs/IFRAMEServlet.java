package org.webpki.webapps.json.jcs;

import java.io.IOException;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;

public class IFRAMEServlet extends HttpServlet
  {
    private static final long serialVersionUID = 1L;
    
    public void doGet (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        byte[] signed_json = (byte[]) request.getSession ().getAttribute (RequestServlet.JCS_ARGUMENT);
        if (signed_json == null)
          {
            RequestServlet.error (response, "Request didn't contain a \"" + RequestServlet.JCS_ARGUMENT + "\" argment");
            return;
          }
        try
          {
            StringBuffer s = new StringBuffer (HTML.HTML_INIT).append ("</head><body style=\"padding:10px;background:#F8F8F8\">");
            s.append (new String (JSONObjectWriter.parseAndFormat (signed_json, JSONOutputFormats.PRETTY_HTML), "UTF-8"));
            s.append ("</body></html>");
            HTML.output (response, s.toString ());
          }
        catch (IOException e)
          {
            HTML.errorPage (response,  e.getMessage ());
            return;
          }
      }
  }
