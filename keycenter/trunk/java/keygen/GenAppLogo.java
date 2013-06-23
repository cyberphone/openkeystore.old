package keygen;

import java.io.IOException;
import java.io.ByteArrayOutputStream;

import java.awt.Graphics2D;

import java.awt.image.BufferedImage;

import javax.imageio.ImageIO;

import org.webpki.util.MimeTypedObject;

import org.webpki.keygen2.KeyGen2URIs;


public class GenAppLogo implements MimeTypedObject
  {
    static BufferedImage applogo;

    static BufferedImage applogin;

    static
      {
        try
          {
            applogo = ImageIO.read (GenAppLogo.class.getResourceAsStream ("applogo.png"));
            applogin = ImageIO.read (GenAppLogo.class.getResourceAsStream ("applogin.png"));
          }
        catch (IOException iox)
          {
          }
      }

    byte[] image_data;


    public GenAppLogo (int user_id) throws IOException
      {
        //////////////////////////////////////////////////////////////////
        // The following code is adapted for the actual application logo
        //////////////////////////////////////////////////////////////////
        BufferedImage bufferedImage = new BufferedImage (applogo.getWidth (null), applogo.getHeight (null), BufferedImage.TYPE_INT_RGB);  
          
        Graphics2D g = bufferedImage.createGraphics ();

        g.drawImage (applogo, 0, 0, null);

        /////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // The Java font scheme wasn't used because it doesn't produce consistent results between Windows and Linux
        ////////////////////////////////////7////////////////////////////////////////////////////////////////////////
        g.drawImage (applogin.getSubimage (0, 0, 9, 9), 113, 41, null);  // The C used as first character

        int factor = 100000;
        for (int i = 0; i < 6; i++)
          {
            //////////////////////////
            // The six-digit user id
            //////////////////////////
            g.drawImage (applogin.getSubimage (10 + (user_id / factor) * 8, 0, 8, 9), 113 + 10 + i * 8, 41, null);
            user_id = user_id % factor;
            factor /= 10;
          }

        g.dispose ();  
          
        ByteArrayOutputStream baos = new ByteArrayOutputStream ();
        ImageIO.write (bufferedImage, "png", baos);
        image_data = baos.toByteArray ();
      }


    public String getMimeType ()
      {
        return "image/png";
      }


    public byte[] getData () throws IOException
      {
        return image_data;
      }


    public String getType ()
      {
        return KeyGen2URIs.LOGOTYPES.APPLICATION;
      }

  }
