package misc;

import java.io.IOException;

import java.net.URLEncoder;

import javax.servlet.ServletException;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import user.UserHome;


public class RestrictedMode
  {
    public static boolean isUnrestrictedWarnOtherwise (HttpServletRequest request, HttpServletResponse response, ServletContext context) throws IOException, ServletException
      {
        if (isRestricted (request, response, context))
          {
            response.sendRedirect (ProtectedServlet.getHomeURL (request) + "?" + 
                                   UserHome.ATTENTION + "=" + 
                                   URLEncoder.encode ("This site is currently running in &quot;restricted mode&quot; requiring you to be logged-in in order to access this resource.", "UTF-8"));
            return false;
          }
        return true;
      }


    public static boolean isRestricted (HttpServletRequest request, HttpServletResponse response, ServletContext context)
      {
        return request.getSession (false) == null && new Boolean (context.getInitParameter ("restricted-mode"));
      }
  }
