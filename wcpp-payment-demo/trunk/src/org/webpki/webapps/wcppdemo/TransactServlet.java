package org.webpki.webapps.wcppdemo;

import java.io.IOException;
import java.util.logging.Logger;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.webutil.ServletUtil;

public class TransactServlet extends HttpServlet
  {
    private static final long serialVersionUID = 1L;

    static Logger logger = Logger.getLogger (TransactServlet.class.getName ());

    public void doPost (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        byte[] json = ServletUtil.getData (request);
        String origin = request.getHeader ("Origin");
        logger.info ("POST[" + origin + "]=" + new String (json,"UTF-8"));
        response.setContentType ("application/json; charset=utf-8");
        response.setHeader ("Pragma", "No-Cache");
        response.setHeader ("Access-Control-Allow-Origin", origin);
        response.setDateHeader ("EXPIRES", 0);
        response.getOutputStream ().write ("{\"hi\":4}".getBytes ("UTF-8"));
      }

    @Override
    public void doOptions (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        logger.info ("OPTIONS requested");
        //The following are CORS headers. Max age informs the 
        //browser to keep the results of this call for 1 day.
        response.setHeader ("Access-Control-Allow-Origin", "*");
        response.setHeader ("Access-Control-Allow-Methods", "GET, POST");
        response.setHeader ("Access-Control-Allow-Headers", "Content-Type");
        response.setHeader ("Access-Control-Max-Age", "86400");
        //Tell the browser what requests we allow.
        response.setHeader ("Allow", "GET, HEAD, POST, TRACE, OPTIONS");
      }
  }
