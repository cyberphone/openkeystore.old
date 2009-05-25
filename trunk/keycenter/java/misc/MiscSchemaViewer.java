package misc;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.webutil.xmlview.SchemaViewerServlet;

import org.webpki.xml.XMLSchemaCache;


@SuppressWarnings("serial")
public class MiscSchemaViewer extends SchemaViewerServlet
  {
    public void doGet (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        if (RestrictedMode.isUnrestrictedWarnOtherwise (request, response, getServletContext ()))
          {
            super.doGet (request, response);
          }
      }

    protected String getXMLViewerName ()
      {
        return "xmlviewer";
      }


    protected String getSchemaViewerName ()
      {
        return "schemaviewer";
      }


    protected ReturnValue getData (String url, HttpServletRequest request) throws IOException, ServletException
      {
        XMLSchemaCache sc = ProtectedServlet.getSchemaCache (getServletContext ());
        byte[] data = sc.getSchema (url);
        if (data == null) return null;
        return new ReturnValue (data, sc.getFile (url)); 
      }
  }
