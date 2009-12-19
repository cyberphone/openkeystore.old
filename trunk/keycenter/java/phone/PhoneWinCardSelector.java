package phone;

import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.io.ByteArrayInputStream;

import java.awt.Graphics2D;

import java.awt.image.BufferedImage;

import javax.imageio.ImageIO;

import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.keygen2.KeyGen2URIs;

import org.webpki.sks.OTPProvider;
import org.webpki.sks.KeyDescriptor;
import org.webpki.sks.Logotype;

@SuppressWarnings("serial")
public class PhoneWinCardSelector extends PhoneWinServlet
  {
    static BufferedImage cardframewithinfo;

    static
      {
        try
          {
            cardframewithinfo = ImageIO.read (PhoneWinCardSelector.class.getResourceAsStream ("cardframewithinfo.png"));
          }
        catch (IOException iox)
          {
          }
      }


    public void protectedGet (HttpServletRequest request, HttpServletResponse response, HttpSession session) throws IOException, ServletException
      {

        OTPProvider otp_prov = PhoneWinOTP.getOTPProvider (session);
        KeyDescriptor kd = otp_prov.getKeyDescriptor ();

        /*======================================================*/
        /* An issuer application logotype is nice but optional. */
        /*======================================================*/
        Logotype logotype = kd.getLogotype (KeyGen2URIs.LOGOTYPES.CARD);
        if (logotype == null)
          {
            logotype = Logotype.getDefaultLogotype (KeyGen2URIs.LOGOTYPES.CARD);
          }

        //////////////////////////////////////////////////////////////////
        // The following code is adapted for the actual card logo
        //////////////////////////////////////////////////////////////////
        BufferedImage bufferedImage = new BufferedImage (cardframewithinfo.getWidth (null), cardframewithinfo.getHeight (null), BufferedImage.TYPE_INT_ARGB);  
          
        Graphics2D g = bufferedImage.createGraphics ();

        g.drawImage (ImageIO.read (new ByteArrayInputStream (logotype.getData ())), 0, 0, null);

        g.drawImage (cardframewithinfo, 0, 0, null);

        g.dispose ();  
          
        ByteArrayOutputStream baos = new ByteArrayOutputStream ();
        ImageIO.write (bufferedImage, "png", baos);
        byte[] image_data = baos.toByteArray ();

        PhoneWinResource.clearResourceList (session);
        String url = PhoneWinResource.addResource (session, image_data, "image/png");

        StringBuffer s = createHeader ("Card Selector").
          append ("<form name=\"shoot\" method=\"GET\" action=\"phonewinauthentication\">" +
                  "<input type=\"hidden\" name=\"staged\" value=\"true\">").
          append (divSection (50, 300)).
          append ("<table cellpadding=\"2\" cellspacing=\"0\">" +
                  "<tr><td align=\"center\"><img src=\"").
          append (url).
          append ("\"></td></tr>" +
                  "<tr><td height=\"10\"></td></tr>" +
                  "<tr><td>This is work-in-progress...</td></tr>" +
                  "</table></div></form>").
          append (createFooter ());

        setHTMLMode (response);
        response.getOutputStream ().print (s.toString ());
      }
  }
