package phone;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.webutil.xmlview.XMLViewerServlet;

import misc.RestrictedMode;

@SuppressWarnings("serial")
public class PhoneXMLViewer extends XMLViewerServlet
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
        return PhoneDebugWin.getXMLData (request.getSession (false), Integer.valueOf (what));
      }


    protected String getSchemaViewerName ()
      {
        return "schemaviewer";
      }


    protected String getXMLViewerName ()
      {
        return "phonexmlviewer";
      }

  }
