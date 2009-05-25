package misc;

import java.io.IOException;

import java.security.cert.X509Certificate;

import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServletRequest;

import org.webpki.crypto.CertificateInfo;

import org.webpki.webutil.certview.CertificateViewer;


@SuppressWarnings("serial")
public class MiscCertViewer extends CertificateViewer
  {
    public boolean trustModeWanted () throws IOException
      {
        return false;
      }


    public CertificateInfo getCertificateInfo (HttpServletRequest request) throws IOException, ServletException
      {
        HttpSession session = request.getSession (false);
        if (session == null)
          {
            return null;
          }
        X509Certificate cert = (X509Certificate) session.getAttribute (ProtectedServlet.CERTIFICATE);
        if (cert == null)
          {
            return null;
          }
        return new CertificateInfo (cert);
      }

  }
