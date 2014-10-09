package org.webpki.webapps.wcppdemo;

import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;

import java.awt.geom.Rectangle2D;

import java.awt.image.BufferedImage;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import java.security.SecureRandom;

import java.util.Vector;

import javax.imageio.ImageIO;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.webpki.util.Base64;

public class CardServlet extends HttpServlet
  {
    private static final long serialVersionUID = 1L;

    Vector<CardEntry> initBlankCards (HttpServletRequest request, String user, String pin) throws IOException
      {
        String name_on_card = user == null ? CardEntry.DEFAULT_USER : user;
        Vector<CardEntry> card_entries = new Vector<CardEntry> ();
        int font_size = 14;
        for (CardTypes card_type : CardTypes.values ())
          {
            CardEntry card_entry = new CardEntry ();
            card_entry.card_type = card_type;
            card_entry.user = user;
            card_entry.pin = pin;
            card_entry.authorization_url = Init.bank_url + "/transact";
            card_entry.bank_encryption_key = Init.bank_encryption_key;
            card_entry.client_key = Init.client_private_key;
            card_entry.client_certificate = Init.client_eecert;
            card_entry.cert_data = Init.cert_data;
            byte[] pan = new byte[16];
            new SecureRandom ().nextBytes (pan);
            StringBuffer pan_text = new StringBuffer ();
            for (byte b : pan)
              {
                pan_text.append ((char)(((b & 0xFF) % 10) + '0'));
              }
            card_entry.pan = pan_text.toString ();
            card_entries.add (card_entry);
            int width = card_type.image.getWidth (null);
            int height = card_type.image.getHeight (null);
            BufferedImage card_image = new BufferedImage (width, height, BufferedImage.TYPE_INT_RGB);  
            Graphics2D g = card_image.createGraphics ();
            g.drawImage (card_type.image, 0, 0, null);
            if (card_entry.active = request == null || request.getParameter (card_type.toString ()) != null)
              {
                FontMetrics font_metrics = null;
                Rectangle2D string_bounds = null;
                do
                  {
                    g.setColor (card_type.font_color); 
                    g.setFont (new Font (Init.card_font, Font.TRUETYPE_FONT, font_size));
                    g.setRenderingHint (RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY);
                    g.setRenderingHint (RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                    g.setRenderingHint (RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
                    g.setRenderingHint (RenderingHints.KEY_STROKE_CONTROL , RenderingHints.VALUE_STROKE_PURE );
        
                    font_metrics = g.getFontMetrics ();
                    string_bounds = font_metrics.getStringBounds (name_on_card, g);
                    if (string_bounds.getWidth () > (width - font_metrics.charWidth (' ') * 2))
                      {
                        font_size--;
                      }
                    else
                      {
                        break;
                      }
                  }
                while (font_size > 5);
                g.drawString (name_on_card, 
                              (int)((width - string_bounds.getWidth ()) / 2),
                              ((height * 2) / 3) + ((height / 3) - (int) font_metrics.getLeading ()) / 2);
              }
            g.dispose ();
            ByteArrayOutputStream baos = new ByteArrayOutputStream ();
            ImageIO.write (card_image, "png", baos);
            card_entry.base64_image = new Base64 (false).getBase64StringFromBinary (baos.toByteArray ());
          }
        return card_entries;
      }

    @SuppressWarnings("unchecked")
    public void doGet (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        Vector<CardEntry> card_entries = null;
        HttpSession session = request.getSession (false);
        if (session != null)
          {
            card_entries = (Vector<CardEntry>) session.getAttribute (CardEntry.CARD_LIST);
          }
        if (card_entries == null)
          {
            card_entries = initBlankCards (null, null, null);
            request.getSession (true).setAttribute (CardEntry.CARD_LIST, card_entries);
          }
        HTML.initCards (response, request, card_entries);
      }
    
    String getArgument (HttpServletRequest request, String param) throws IOException
      {
        String res = request.getParameter (param);
        if (res == null)
          {
            throw new IOException ("Missing parameter: " + param);
          }
        res = res.trim ();
        return res.length () == 0 ? null : res;
      }

    public void doPost (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        request.setCharacterEncoding ("UTF-8");
        request.getSession (true).setAttribute (CardEntry.CARD_LIST, initBlankCards (request, 
                                                                                     getArgument (request, CardEntry.USER_FIELD),
                                                                                     getArgument (request, CardEntry.PIN_FIELD)));
        response.sendRedirect (request.getRequestURL ().toString ());
      }
  }
