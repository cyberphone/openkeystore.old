package phone;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import misc.ProtectedServlet;
import misc.KeyCenterCommands;


@SuppressWarnings("serial")
public class PhoneAJAXHandler extends ProtectedServlet
  {

    static final String SESS_SYNCHRONIZER = "SYNCHRONIZER";

    static final String SESS_BACKUP_SYNC = "BACKUP_SYNCHRONIZER";

    static class Synchronizer
      {

        static final long TIMEOUT = 120000;  // 120 seconds

        boolean touched;
        boolean timeout_flag;
        int instance;


        synchronized boolean perform (boolean in_touched) throws IOException
          {
            touched = in_touched;
            while (!touched && !timeout_flag)
              {
                try
                  {
                    wait (TIMEOUT);
                  }
                catch (InterruptedException e)
                  {
                    return false;
                  }
                timeout_flag = true;
              }
            return touched;
          }


        synchronized void haveData4You ()
          {
            touched = true;
            notify ();
          }

      }


    public static void notifyData (HttpSession session) throws IOException
      {
        Synchronizer sync = (Synchronizer) session.getAttribute (SESS_SYNCHRONIZER);
        if (sync != null)
          {
            sync.haveData4You ();
          }
        session.setAttribute (SESS_BACKUP_SYNC, "yes");
      }


    protected KeyCenterCommands getCommand ()
      {
        return null;
      }

    public void protectedGet (HttpServletRequest request, HttpServletResponse response, HttpSession session) throws IOException, ServletException
      {
        Synchronizer sync = new Synchronizer ();
        synchronized (session)
          {
            notifyData (session);
            if (session.getAttribute (SESS_BACKUP_SYNC) != null)
              {
                sync.haveData4You ();
                session.setAttribute (SESS_BACKUP_SYNC, null);
              }
            session.setAttribute (SESS_SYNCHRONIZER, sync);
          }
        response.setContentType ("text/xml");
        response.setHeader ("Pragma", "No-Cache");
        response.setDateHeader ("EXPIRES", -1);
        response.getOutputStream ().print (sync.perform (PhoneDebugWin.needsRefresh (session)) ? "<yes/>" : "<no/>" );
      }
  }
