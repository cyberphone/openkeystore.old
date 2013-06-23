package phone;

import java.io.IOException;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import java.net.URLEncoder;

import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.webutil.ServletUtil;


@SuppressWarnings("serial")
public class PhoneWinAuthentication extends PhoneWinServlet
  {

    public void protectedGet (HttpServletRequest request, HttpServletResponse response, HttpSession session) throws IOException, ServletException
      {
        try
          {
            String staged = request.getParameter ("staged");
            setQuickRunFlag (session, staged);
            if (staged != null)
              {
                PhoneDebugWin.clearDebugWin (session);
                PhoneDebugWin.initDebugWin (session);
              }
            Connection conn = getDatabaseConnection ();
            PreparedStatement pstmt = conn.prepareStatement ("SELECT Password, Email FROM USERS WHERE UserID=?");
            pstmt.setInt (1, getUserID (session));
            ResultSet rs = pstmt.executeQuery ();
            rs.next ();
            String pwd = rs.getString (1);
            String email = rs.getString (2);
            rs.close ();
            pstmt.close ();
            conn.close ();
            response.sendRedirect (PhoneWinProxy.createProxyURL (request, 
                                   ServletUtil.getContextURL (request) +
                                      "/kg2_login?email=" + URLEncoder.encode (email, "UTF-8") +
                                      "&pwd=" + URLEncoder.encode (pwd, "UTF-8")));
          }
        catch (SQLException e)
          {
            bad (e.getMessage ());
          }
      }
  }
