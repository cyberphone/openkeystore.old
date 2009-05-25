package keygen;

import java.io.IOException;
import java.io.ByteArrayOutputStream;

import java.awt.Graphics2D;
import java.awt.Color;
import java.awt.Font;
import java.awt.RenderingHints;
import java.awt.geom.Rectangle2D;

import java.awt.image.BufferedImage;

import javax.imageio.ImageIO;

import org.webpki.util.MimeTypedObject;

import org.webpki.keygen2.KeyGen2URIs;


public class GenCardLogo implements MimeTypedObject
  {
    static BufferedImage otpcardlogo;

    static
      {
        try
          {
            otpcardlogo = ImageIO.read (GenAppLogo.class.getResourceAsStream ("greenbankotpcard.png"));
          }
        catch (IOException iox)
          {
          }
      }

    byte[] image_data;


    public GenCardLogo (String name) throws IOException
      {
        //////////////////////////////////////////////////////////////////
        // The following code is adapted for the actual card logo
        //////////////////////////////////////////////////////////////////
        int width = otpcardlogo.getWidth (null);
        BufferedImage bufferedImage = new BufferedImage (width, otpcardlogo.getHeight (null), BufferedImage.TYPE_INT_RGB);  
          
        Graphics2D g = bufferedImage.createGraphics ();

        g.drawImage (otpcardlogo, 0, 0, null);

        g.setColor (Color.black); 
        g.setFont (new Font ("Helvetica", Font.PLAIN, 9));
        g.setRenderingHint (RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g.setRenderingHint (RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
        g.setRenderingHint (RenderingHints.KEY_STROKE_CONTROL , RenderingHints.VALUE_STROKE_PURE );

        Rectangle2D rectum = g.getFontMetrics ().getStringBounds (name, g);

        g.drawString (name, (int)((width - rectum.getWidth ()) / 2), 68);

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
        return KeyGen2URIs.LOGOTYPES.CARD;
      }

  }
