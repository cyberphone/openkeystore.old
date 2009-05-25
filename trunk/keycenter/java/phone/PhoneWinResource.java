package phone;

import java.io.IOException;
import java.io.Serializable;

import java.util.Vector;

import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


@SuppressWarnings("serial")
class CachedEmbeddedResourceHandle implements Serializable
  {
    byte[] resource;
    String mime;

    protected CachedEmbeddedResourceHandle ()
      {
      }

    CachedEmbeddedResourceHandle (byte[] resource, String mime)
      {
        this.resource = resource;
        this.mime = mime;
      }
  }


@SuppressWarnings("serial")
public class PhoneWinResource extends PhoneWinServlet
  {
    private static final String RESVECT = "EMBEDDEDRESOURCEVECTOR";

    private static int counter;


    public static void clearResourceList (HttpSession session)
      {
        session.setAttribute (RESVECT, null);
      }


    public static String addResource (HttpSession session, byte[] resource, String mime) throws IOException
      {
        @SuppressWarnings("unchecked")
        Vector<CachedEmbeddedResourceHandle> v = (Vector<CachedEmbeddedResourceHandle>) session.getAttribute (RESVECT);
        if (v == null) session.setAttribute (RESVECT, v = new Vector<CachedEmbeddedResourceHandle> ());
        int i = v.size ();
        if (i > 100) throw new IOException ("More than 100 cached resources - Must be wrong!");
        v.addElement (new CachedEmbeddedResourceHandle (resource, mime));
        String url = "phonewinresource?res=" + i + "&counter=" + counter++;
        if (mime.equals ("application/pdf"))
          {
            return url + "&FILE=a.pdf";  // Acrobat Reader is stupid
          }
        return url;
      }


    public void protectedGet (HttpServletRequest request, HttpServletResponse response, HttpSession session) throws IOException, ServletException
      {
        @SuppressWarnings("unchecked")
        Vector<CachedEmbeddedResourceHandle> v = (Vector<CachedEmbeddedResourceHandle>) session.getAttribute (RESVECT);
        if (v == null) throw new IOException ("No resource vector!!!");
        int i = Integer.parseInt (request.getParameter ("res"));
        CachedEmbeddedResourceHandle h = v.elementAt (i);
        response.setContentType (h.mime);
        if (!request.isSecure ())
          {
            response.setHeader ("Pragma", "No-Cache");  // I hate proxies
          }
        response.setDateHeader("EXPIRES", 0);
        response.getOutputStream ().write (h.resource);
      }

  }
