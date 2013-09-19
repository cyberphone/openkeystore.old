package org.webpki.webapps.json.jcs;

import java.io.IOException;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;
import org.webpki.util.Base64URL;
import org.webpki.webutil.ServletUtil;

public class CreateServlet extends HttpServlet
  {
    private static final long serialVersionUID = 1L;
    
    static final String MY_DATA_TO_BE_SIGNED = "mydata";
    static final String KEY_TYPE = "keytype";
    
    public void doGet (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        HTML.createPage (response, request);
      }

    public void doPost (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        request.setCharacterEncoding ("UTF-8");
        String data_to_be_signed = request.getParameter (MY_DATA_TO_BE_SIGNED);
        MySignature.ACTION action = MySignature.ACTION.ASYM;
        String key_type = request.getParameter (KEY_TYPE);
        for (MySignature.ACTION a : MySignature.ACTION.values ())
          {
            if (a.toString ().equals (key_type))
              {
                action = a;
                break;
              }
          }
        JSONObjectWriter wr = new JSONObjectWriter ();
        new MySignature (action, data_to_be_signed).writeJSONData (wr);
        response.sendRedirect (ServletUtil.getContextURL (request) + 
                               "/request?" + RequestServlet.JCS_ARGUMENT + "=" + 
                               Base64URL.getBase64URLFromBinary (wr.serializeJSONObject (JSONOutputFormats.PRETTY_PRINT)));
      }
  }
