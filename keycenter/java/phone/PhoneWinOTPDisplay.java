package phone;

import java.io.IOException;

import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import javax.imageio.ImageIO;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


@SuppressWarnings("serial")
public class PhoneWinOTPDisplay extends HttpServlet
  {
    static BufferedImage back;

    static BufferedImage digits;

    static BufferedImage password;

    static
      {
        try
          {
            back = ImageIO.read (PhoneWinOTPDisplay.class.getResourceAsStream ("otpback.gif"));
            digits = ImageIO.read (PhoneWinOTPDisplay.class.getResourceAsStream ("otpdigits.gif"));
            password = ImageIO.read (PhoneWinOTPDisplay.class.getResourceAsStream ("otppassword.gif"));
          }
        catch (IOException iox)
          {
          }
      }

    static final int BACK_IMAGE_WIDTH = 130;

    static final int BACK_IMAGE_HEIGHT = 26;

    static final int PASSWORD_HEIGHT = 10;

    static final int DIGIT_WIDTH = 11;

    static final int DIGIT_HEIGHT = 13;

    static final int DIGITS_LEFT_MARGIN = 8;

    static final int DIGITS_RIGHT_MARGIN = 7;

    static final int DIGITS_TOP_MARGIN = 17;

    static final int BORDER_WIDTH = 3;

    static final int DIGIT_GUTTER = 2;

    static int getWidth (String value)
      {
        return value.length () * (DIGIT_WIDTH + DIGIT_GUTTER) + DIGITS_LEFT_MARGIN + DIGITS_RIGHT_MARGIN - DIGIT_GUTTER;
      }


    public void doGet (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {

        String value = request.getParameter ("value");

        int width = getWidth (value);
          
        BufferedImage bufferedImage = new BufferedImage (width, BACK_IMAGE_HEIGHT + PASSWORD_HEIGHT, BufferedImage.TYPE_INT_RGB);
          
        Graphics2D g = bufferedImage.createGraphics ();

        g.drawImage (password, (width - BACK_IMAGE_WIDTH) / 2, 0, null);
        g.drawImage (back, 0, PASSWORD_HEIGHT, null);
        g.drawImage (back.getSubimage (BACK_IMAGE_WIDTH - BORDER_WIDTH, 0, BORDER_WIDTH, BACK_IMAGE_HEIGHT), width - BORDER_WIDTH, PASSWORD_HEIGHT, null);

        for (int i = 0; i < value.length (); i++)
          {
            g.drawImage (digits.getSubimage ((value.charAt (i) - 48) * DIGIT_WIDTH, 0, DIGIT_WIDTH, DIGIT_HEIGHT),
                         i * (DIGIT_WIDTH + DIGIT_GUTTER) + DIGITS_LEFT_MARGIN,
                         DIGITS_TOP_MARGIN,
                         null);  
          }

        g.dispose ();  
          
        response.setContentType ("image/png");  
        response.setHeader ("Pragma", "No-Cache");
        response.setDateHeader ("EXPIRES", 0);
        ImageIO.write (bufferedImage, "png", response.getOutputStream ());  
      }
  }
