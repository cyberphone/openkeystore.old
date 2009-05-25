package phone;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.util.DebugFormatter;

import org.webpki.webutil.ServletUtil;


@SuppressWarnings("serial")
public class PhoneWinProxy extends PhoneWinServlet
  {
    public static String createProxyURL (HttpServletRequest request, String url) throws IOException
      {
        return ServletUtil.getContextURL (request) + "/phonewinbrowser/" + DebugFormatter.getHexString (url.getBytes ("UTF-8"));
      }
    

    public void protectedPost (HttpServletRequest request, HttpServletResponse response, HttpSession session) throws IOException, ServletException
      {
        protectedGet (request, response, session);
      }


    public void protectedGet (HttpServletRequest request, HttpServletResponse response, HttpSession session) throws IOException, ServletException
      {
        byte[] post_data = null;
        String method = request.getMethod ();
        if (method.equals ("POST"))
          {
            post_data = ServletUtil.getData (request);
          }

        /* Get URL argument. */
        String url = request.getPathInfo ();
        String querystring = request.getQueryString ();

        if (url != null && url.length () > 10)
          {
            url = new String (DebugFormatter.getByteArrayFromHex (url.substring (1)), "UTF-8");
            if (querystring != null && querystring.length () > 0)
              {
                url += (querystring.charAt (0) == '?' ? querystring : "?" + querystring);
              }
                
            if (method.equals ("POST"))
              {
                /* Handle as any POST */
                PhoneUtil.makePostRequest (request, response, url, post_data, request.getContentType ());
              }
            else
              {
                /* Make GET request */
                PhoneUtil.makeGetRequest (request, response, url);
              }
          }
        else
          {
            bad ("Unable to process request, no URL parameter!");
          }
      }
  }




