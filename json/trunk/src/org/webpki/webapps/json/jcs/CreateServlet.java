package org.webpki.webapps.json.jcs;

import java.io.IOException;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONParser;

import org.webpki.util.Base64URL;

import org.webpki.webutil.ServletUtil;

public class CreateServlet extends HttpServlet
  {
    private static final long serialVersionUID = 1L;
    
    static final String KEY_TYPE = "keytype";
    
    public void doGet (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        HTML.createPage (response, request);
      }
    
    static public String getTextArea (HttpServletRequest request) throws IOException
      {
        String string = request.getParameter (RequestServlet.JCS_ARGUMENT);
        if (string == null)
          {
            throw new IOException ("Missing data for: " + RequestServlet.JCS_ARGUMENT);
          }
        StringBuffer s = new StringBuffer ();
        for (char c : string.toCharArray ())
          {
            if (c != '\r')
              {
                s.append (c);
              }
          }
        return s.toString ();
      }

    public void doPost (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        request.setCharacterEncoding ("UTF-8");
        String json_object = getTextArea (request);
        MySignature.ACTION action = MySignature.ACTION.EC;
        String key_type = request.getParameter (KEY_TYPE);
        for (MySignature.ACTION a : MySignature.ACTION.values ())
          {
            if (a.toString ().equals (key_type))
              {
                action = a;
                break;
              }
          }
        try
          {
            byte[] signed_json = new MySignature ().sign (new JSONObjectWriter (JSONParser.parse (json_object)), action);
            response.sendRedirect (ServletUtil.getContextURL (request) + 
                                   "/request?" + RequestServlet.JCS_ARGUMENT + "=" + 
                                   Base64URL.encode (signed_json));
          }
        catch (IOException e)
          {
            HTML.errorPage (response,  e.getMessage ());
          }
      }
  }
