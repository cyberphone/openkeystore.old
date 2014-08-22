package org.webpki.webapps.mybank;

import java.io.IOException;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.util.ArrayUtil;
import org.webpki.util.Base64URL;

import org.webpki.webutil.ServletUtil;

public class VerifyServlet extends HttpServlet
  {
    private static final long serialVersionUID = 1L;
    
    String signature;
    
    @Override
    public
    void init (ServletConfig config)
      {
        try
          {
            super.init (config);
            try
              {
                signature = new String (ArrayUtil.getByteArrayFromInputStream (config.getServletContext ().getResourceAsStream ("/signature.json")), "UTF-8");
              }
            catch (IOException e)
              {
                throw new RuntimeException (e);
              }
          }
        catch (ServletException e)
          {
            throw new RuntimeException (e);
          }
      }
    
    public void doGet (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
      }

    public void doPost (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
      }
  }
