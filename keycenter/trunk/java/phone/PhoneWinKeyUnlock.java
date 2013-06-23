package phone;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.sks.KeyMetadataProvider;
import org.webpki.sks.KeyDescriptor;

import org.webpki.webutil.ServletUtil;


@SuppressWarnings("serial")
public class PhoneWinKeyUnlock extends PhoneWinServlet
  {

    public void protectedGet (HttpServletRequest request, HttpServletResponse response, HttpSession session) throws IOException, ServletException
      {
        String key_id = request.getParameter ("keyid");
        String disp = request.getParameter ("disp");
        KeyDescriptor kd = new KeyMetadataProvider (getSKS (session)).getKeyDescriptor (new Integer (key_id));
        String puk = request.getParameter ("puk");
        if (puk != null && kd.unlockKey (puk))
          {
            PhoneDebugWin.setDebugEvent (session, "Succeeded unlocking key!");
            response.sendRedirect (ServletUtil.getContextURL (request) + "/phonewinkeyexplorer");
            return;
          }
        StringBuffer s = createHeader ("Unlock Key #" + disp).
          append ("<form method=\"GET\" action=\"").
          append (request.getRequestURL ().toString ()).
          append ("\"><input type=\"hidden\" name=\"keyid\" value=\"").
          append (key_id).
          append ("\"><input type=\"hidden\" name=\"disp\" value=\"").
          append (disp).
          append ("\">").
          append (divSection ()).
          append ("<table cellpadding=\"0\" cellspacing=\"0\">" +
                  "<tr><td>The key in question has locked-up due to incorrect PIN "+
                  "codes.  With this dialog you can unlock it to its orginal value "+
                  "if you have the associated PUK code.</td></tr>" +
                  "<tr><td height=\"10\"></td></tr>");
        if (puk != null)
          {
            s.append ("<tr><td align=\"center\"><font color=\"red\"><b>").
              append (kd.isPUKLocked () ? "Key is now PERMANENTELY LOCKED" : "Bad PUK Code!").
              append ("</b></font></td></tr><tr><td height=\"7\"></td></tr>");
          }
        s.append ("<tr><td align=\"center\"><table cellpadding=\"0\" cellspacing=\"0\" border=\"0\">"+
                  "<tr><td align=\"left\">PUK code:</td></tr>" +
                  "<tr><td height=\"4\"></td></tr>" +
                  "<tr><td><input type=\"text\" size=\"20\" name=\"puk\"></td></tr></table></td></tr>" +
                  "<tr><td height=\"10\"></td></tr>" +
                  "<tr><td align=\"center\"><input type=\"submit\" value=\"Enter\"></td></tr>" +
                  "</table></div></form>").
          append (createFooter ("phonewinkeyexplorer"));

        setHTMLMode (response);
        response.getOutputStream ().print (s.toString ());
      }
  }
