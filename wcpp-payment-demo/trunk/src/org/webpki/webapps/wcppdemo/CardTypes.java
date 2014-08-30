package org.webpki.webapps.wcppdemo;

import java.awt.Color;

import java.awt.image.BufferedImage;

import java.io.IOException;

import javax.imageio.ImageIO;

public enum CardTypes
  {
	SUPER_CARD   ("supercard.png",   Color.BLUE), 
	COOL_CARD    ("coolcard.png",    Color.BLACK),
	UNUSUAL_CARD ("unusualcard.png", Color.GRAY);
	
	BufferedImage image;
	Color color;
	
	CardTypes (String file, Color color)
	  {
		try 
		  {
			image = ImageIO.read (CardTypes.class.getResourceAsStream (file));
	      }
		catch (IOException e)
		  {
			throw new RuntimeException (e);
		  }
		this.color = color;
	  }
  }
