package phone;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.sks.Provisioning;


@SuppressWarnings("serial")
public class PhoneWinKeyGen2DelayedGenerate extends PhoneWinKeyGen2Generate
  {
    public void protectedGet (HttpServletRequest request, HttpServletResponse response, HttpSession session) throws IOException, ServletException
      {
        try
          {
            deployAndFinish (request,
                             response,
                             session,
                             new Provisioning (getSKS (session), new LocalDebug (session)),                             null);
          }
        catch (Exception e)
          {
            internalPhoneError (response, e);
          }
      }

  }
