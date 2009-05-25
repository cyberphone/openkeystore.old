<%@ page import="java.awt.*, java.awt.image.*, javax.imageio.*" %><%
response.setContentType("image/png");  
  
// Create an image 200 x 200  
BufferedImage bufferedImage = new BufferedImage(200, 200, BufferedImage.TYPE_INT_RGB);  
  
//Draw an oval  
Graphics2D g = bufferedImage.createGraphics();  
g.setColor(Color.white);  
g.fillOval(0, 0, 199,199);  

g.setColor(Color.black); 
g.setFont (new Font ("Helvetica", Font.PLAIN, 9));
 
        g.setRenderingHint (RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g.setRenderingHint (RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
        g.setRenderingHint (RenderingHints.KEY_STROKE_CONTROL , RenderingHints.VALUE_STROKE_PURE );

/**/
g.drawString("Anders Rundgren", 5,100);  
  
// Free graphic resources  
g.dispose();  
  
//Write the image as a jpg  
ImageIO.write(bufferedImage, "png", response.getOutputStream());  
%>