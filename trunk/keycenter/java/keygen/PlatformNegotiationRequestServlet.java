package keygen;

import java.io.IOException;

import java.util.Date;

import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.security.SecureRandom;
import org.webpki.crypto.SymEncryptionAlgorithms;

import org.webpki.keygen2.PlatformNegotiationRequestEncoder;


@SuppressWarnings("serial")
public class PlatformNegotiationRequestServlet extends KeyGenServlet
  {

    public void protectedGet (HttpServletRequest request, HttpServletResponse response, HttpSession session) throws IOException, ServletException
      {
        String server_session_id = "R." + Long.toHexString (new Date().getTime()) + Long.toHexString(new SecureRandom().nextLong());
        ProvisioningState prov_state = new ProvisioningState ();
        session.setAttribute (SRV_PROV_STATE, prov_state);
        prov_state.server_session_id = server_session_id;        prov_state.user_name = (String) session.getAttribute (SESS_NAME);        prov_state.email_address = getEmailAddress (request);

        PlatformNegotiationRequestEncoder encoder =
           new PlatformNegotiationRequestEncoder (server_session_id,
                                                  genApplicationURL (request, "kg2_generate"));
        if (!wantStrongCrypto (getServletContext ()))          {
            encoder.getBasicCapabilities ()
                .addSymmetricKeyEncryptionAlgorithm (SymEncryptionAlgorithms.AES128_CBC)
                .setComment ("\nGodaddy's hosting does not support 256 bit AES!\n");          }
/*        org.w3c.dom.Document d = org.webpki.xml.XMLConfiguration.createDocument ();
        org.w3c.dom.Element e = d.createElementNS ("http://example.com/def", "SomeTextingXML");
        e.setAttributeNS ("http://www.w3.org/2000/xmlns/", "xmlns", "http://example.com/def");
        e.setAttribute ("kurtz","700");
        d.appendChild (e);
        encoder.setServerCookie (new org.webpki.xml.ServerCookie ().addXMLCookie (new org.webpki.xml.XMLCookie (d)));
*/
        writeXMLObject (response, encoder);
      }
  }
