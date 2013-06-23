package misc;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


import org.webpki.webutil.xmlview.XMLViewerServlet;


@SuppressWarnings("serial")
public class MiscXMLViewer extends XMLViewerServlet
  {

    public void doGet (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        if (RestrictedMode.isUnrestrictedWarnOtherwise (request, response, getServletContext ()))
          {
            super.doGet (request, response);
          }
      }

    protected byte[] getData (String what, HttpServletRequest request) throws IOException, ServletException
      {
        return (byte[]) request.getSession (false).getAttribute (ProtectedServlet.XMLDATA);
      }


    protected String getSchemaViewerName ()
      {
        return null;
      }


    protected String getXMLViewerName ()
      {
        return "xmlviewer";
      }

  }
