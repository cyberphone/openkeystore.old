package org.webpki.webapps.json.jcs;

import java.io.IOException;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.util.Base64URL;
import org.webpki.webutil.ServletUtil;

public class CreateServlet extends HttpServlet
  {
    private static final long serialVersionUID = 1L;
    
    static final String MY_DATA_TO_BE_SIGNED = "mydata";
    
    public void doGet (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        HTML.createPage (response, request);
      }

    public void doPost (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        request.setCharacterEncoding ("UTF-8");
        String data_to_be_signed = request.getParameter (MY_DATA_TO_BE_SIGNED);
        response.sendRedirect (ServletUtil.getContextURL (request) + 
                               "/request?" + RequestServlet.JCS_ARGUMENT + "=" + 
                               Base64URL.getBase64URLFromBinary (new MySignature (MySignature.ACTION.ASYM, data_to_be_signed).getJSONData ()));
      }
  }
