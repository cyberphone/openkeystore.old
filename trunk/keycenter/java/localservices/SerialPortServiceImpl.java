package localservices;

import java.io.IOException;

import org.webpki.sks.SerialPortService;

import phone.PhoneWinServlet;

public class SerialPortServiceImpl implements SerialPortService
  {

    public String getPortID () throws IOException
      {
        return PhoneWinServlet.serial_port;
      }

    public int getBaudRate () throws IOException
      {
        return PhoneWinServlet.baud_rate;
      }

  }
