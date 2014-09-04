package org.webpki.webapps.wcppdemo;

import java.io.IOException;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class HomeServlet extends HttpServlet
  {
    private static final long serialVersionUID = 1L;
    
    public void doGet (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        HTML.homePage (response);
      }
  }
