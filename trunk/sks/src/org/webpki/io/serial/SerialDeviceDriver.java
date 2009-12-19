package org.webpki.io.serial;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import java.math.BigInteger;

import java.util.Hashtable;

import gnu.io.CommPort;
import gnu.io.CommPortIdentifier;
import gnu.io.SerialPort;


/**
 * This class implements a serial-port-based API between a PC and
 * an embedded device.
 */
public abstract class SerialDeviceDriver
  {
    private static final int DEVICE_INPUT_BUFFER_LENGTH = 40000;
    
    private static final int STANDARD_COMMAND_TIMEOUT = 10000;
    
    private static final int CHARACTER_BY_CHARACTER_TIMEOUT = 100;
    
    private static final int RETURN_STATUS_OK = 0;

    private static Hashtable<String,Object> _ports = new Hashtable<String,Object> ();
    
    private String _port;
    
    private int _baud_rate;
    
    private Object _port_lock;
    
    private SerialPort _serial_port;
    
    private OutputStream _serial_out;
    
    private InputStream _serial_in;
    
    private String _error_string;
    
    private int _return_status;
    
    private String _last_log_message;
    
    protected SerialDeviceDriver (String port, int baud_rate)
      {
        this._port = port;
        this._baud_rate = baud_rate;
        synchronized (_ports)
          {
            if (_ports.containsValue (_ports))
              {
                _port_lock = _ports.get (_port);
              }
            else
              {
                _ports.put (port, _port_lock = new Object ());
              }
          }
      }


    public String getErrorString ()
      {
        return _error_string;
      }

    
    public int getLastStatus ()
      {
        return _return_status;
      }


    public String getOptionalLogMessage ()
      {
        return _last_log_message;
      }


    public static final class OutputBuffer
      {
        SerialDeviceDriver _serial_device_driver;
        
        byte[] buffer;
        
        int length;
        
        boolean make_output_too_short;  // For testing purposes only
        
        public OutputBuffer (SerialDeviceDriver serial_device_driver)
          {
            this._serial_device_driver = serial_device_driver;
            buffer = new byte[DEVICE_INPUT_BUFFER_LENGTH];
          }

        private OutputBuffer add (byte[] parameter) throws IOException
          {
            if (length + parameter.length >= DEVICE_INPUT_BUFFER_LENGTH)
              {
                throw new IOException ("Device input buffer exceeded!");
              }
            System.arraycopy (parameter, 0, buffer, length, parameter.length);
            length += parameter.length;
            return this;
          }
 
        public InputBuffer sendBuffer (InputBuffer input) throws IOException
          {
            _serial_device_driver._return_status = RETURN_STATUS_OK;
            _serial_device_driver._error_string = null;
            synchronized (_serial_device_driver._port_lock)
              {
                try
                  {
                    CommPortIdentifier portIdentifier = CommPortIdentifier.getPortIdentifier (_serial_device_driver._port);
                    if (portIdentifier.isCurrentlyOwned ())
                      {
                        throw new IOException ("Error: Port '" + _serial_device_driver._port + "' is currently in use");
                      }
                    CommPort commPort = portIdentifier.open (this.getClass().getName(), 2000);
                    if (!(commPort instanceof SerialPort))
                      {
                        throw new IOException ("Error: Port '" + _serial_device_driver._port + "' is not a serial port");
                      }
                    _serial_device_driver._serial_port = (SerialPort) commPort;
                    _serial_device_driver._serial_port.enableReceiveTimeout (STANDARD_COMMAND_TIMEOUT);
                    _serial_device_driver._serial_port.setSerialPortParams (_serial_device_driver._baud_rate, 
                                                                            SerialPort.DATABITS_8,
                                                                            SerialPort.STOPBITS_1,
                                                                            SerialPort.PARITY_NONE);
                    _serial_device_driver._serial_port.setFlowControlMode (SerialPort.FLOWCONTROL_RTSCTS_IN | SerialPort.FLOWCONTROL_RTSCTS_OUT);
                     _serial_device_driver._serial_in = _serial_device_driver._serial_port.getInputStream ();
                    input._serial_device_driver = _serial_device_driver;
                    _serial_device_driver._serial_out = _serial_device_driver._serial_port.getOutputStream ();
                    _serial_device_driver._serial_out.write (length >> 8);
                    _serial_device_driver._serial_out.write (length & 0xFF);
                    if (make_output_too_short)
                      {
                        length--;
                      }
                    _serial_device_driver._serial_out.write (buffer, 0, length);
                    input._readResponse ();
                  }
                catch (Exception e)
                  {
                    String msg = e.getMessage ();
                    IOException iox = new IOException (msg == null ? e.getClass ().getName (): msg);
                    iox.setStackTrace (e.getStackTrace ());
                    throw iox;
                  }
                finally
                  {
                    if (_serial_device_driver._serial_out != null)
                      {
                        _serial_device_driver._serial_out.close ();
                        _serial_device_driver._serial_out = null;
                      }
                    if (_serial_device_driver._serial_in != null)
                      {
                        _serial_device_driver._serial_in.close ();
                        _serial_device_driver._serial_in = null;
                      }
                    if (_serial_device_driver._serial_port != null)
                      {
                        _serial_device_driver._serial_port.close ();
                        _serial_device_driver._serial_port = null;
                      }
                  }
              }
            return input;
          }


        public OutputBuffer putByte (int value) throws IOException
          {
            return add (new byte[] {(byte)value});
          }


        public OutputBuffer putByte (boolean value) throws IOException
          {
            return putByte (value ? 1 : 0);
          }

        
        public OutputBuffer putArray (byte[] array) throws IOException
          {
            putShort (array.length);
            return add (array);
          }


        public OutputBuffer putString (String string) throws IOException
          {
            return putArray (string.getBytes ("UTF-8"));
          }
        
        
        public OutputBuffer putOptionalString (String string) throws IOException
          {
            if (string == null)
              {
                return putByte (0);
              }
            putByte (1);
            return putString (string);
          }


        public OutputBuffer putShort (int value) throws IOException
          {
            return add (new byte[] {(byte) ((value >> 8) & 0xff), (byte) (value & 0xff)});
          }


        public OutputBuffer putOptionalBigInteger (BigInteger big) throws IOException
          {
            if (big == null)
              {
                return putByte (0);
              }
            putByte (1);
            return putArray (big.toByteArray ());
          }
        
     }


    public static abstract class InputBuffer 
      {
        SerialDeviceDriver _serial_device_driver;

        private int _hold_exception_status;

        protected InputBuffer ()
          {
          }

        protected InputBuffer (int hold_exception_status)
          {
            this._hold_exception_status = hold_exception_status;
          }

        
        protected abstract void readInput () throws IOException;
        

        protected boolean supportsLogging (SerialDeviceDriver serial_device_driver)
          {
            return false;
          }

        
        public byte readChar () throws IOException
          {
            int i = _serial_device_driver._serial_in.read ();
            if (i < 0)
              {
                throw new IOException ("Read timeout on serial port");
              }
            return (byte) i;
          }
 
        
        public int readShort () throws IOException
          {
            return (readChar () << 8) + (readChar () & 0xFF);
          }
        
        
        public byte[] readArray () throws IOException
          {
            int len = readShort () & 0xFFFF;
            byte b[] = new byte[len];
            for (int i = 0; i < len; i++)
              {
                b[i] = readChar ();
              }
            return b;
          }
        
        
        public String readString () throws IOException
          {
            return new String (readArray (), "UTF-8");
          }

        
        public String readOptionalString () throws IOException
          {
            int cond = readChar ();
            if (cond == 0)
              {
                return null;
              }
            return readString ();
          }

        
        private void _readResponse () throws Exception
          {
            while (_serial_device_driver._serial_in.available () > 0)
              {
                readChar ();
              }
            _serial_device_driver._return_status = readChar ();
            _serial_device_driver._serial_port.enableReceiveTimeout (CHARACTER_BY_CHARACTER_TIMEOUT);
            if (_serial_device_driver._return_status != RETURN_STATUS_OK)
              {
                _serial_device_driver._error_string = readString ();
                if (_hold_exception_status == _serial_device_driver._return_status)
                  {
                    return;
                  }
                throw new IOException (_serial_device_driver._error_string);
              }
            readInput ();
            if (supportsLogging (_serial_device_driver))
              {
                _serial_device_driver._last_log_message = readOptionalString ();
              }
         }
       
      }


    public static class ByteArrayReturn extends InputBuffer
      {
        private byte[] byte_array;

        public ByteArrayReturn (int hold_exception_status)
          {
            super (hold_exception_status);
          }

        public ByteArrayReturn ()
          {
          }
        
        protected void readInput () throws IOException
          {
            byte_array = readArray ();
          }

        public byte[] getArray ()
          {
            return byte_array;
          }
      }

    public static class VoidReturn extends InputBuffer
      {
        protected void readInput () throws IOException
          {
          }
      }


    private static class Test extends SerialDeviceDriver
      {
        private static final byte CAPACITY_COMMAND       = 1;
        
        private static final byte MISSING_DATA_COMMAND   = 2;
        
        private static final byte DEVICE_TIMEOUT_COMMEND = 3;

      
        Test (String port, int baud_rate)
          {
            super (port, baud_rate);
          }
        
        void capacityCommand (int in_buffer_size, int out_buffer_size) throws IOException
          {
            byte[] in_buffer = new byte[in_buffer_size];
            for (int i = 0; i < in_buffer_size; i++)
              {
                in_buffer[i] = (byte) i;
              }
            byte[] result = ((ByteArrayReturn) new OutputBuffer (this)
                                                   .putByte (CAPACITY_COMMAND)
                                                   .putShort (out_buffer_size)
                                                   .putArray (in_buffer)
                                                   .sendBuffer (new ByteArrayReturn ())).getArray ();
            if (result.length != out_buffer_size)
              {
                throw new IOException ("Returned buffer size error:" + result.length);
              }
          }

   
        void missingDataCommand () throws IOException
          {
            OutputBuffer output = new OutputBuffer (this)
                                      .putByte (MISSING_DATA_COMMAND)
                                      .putShort (678);
            output.make_output_too_short = true;
            output.sendBuffer (new VoidReturn ());
          }


        void deviceTimeoutCommand () throws IOException
          {
            new OutputBuffer (this)
                .putByte (DEVICE_TIMEOUT_COMMEND)
                .sendBuffer (new VoidReturn ());
          }
        
      }

    public static void main (String[] args)
      {
        if ((args.length != 5 && args.length != 7) ||
            ((args.length == 7) != args[0].equals ("cap")))
          {
            System.out.println (SerialDeviceDriver.class.getName () + " command port baud-rate count delay_in_millis [options]\n" +
                                           "          Command:\n" +
                                           "                cap - Capacity testing\n" +
                                           "                tim - Device timeout\n" +
                                           "                mis - Missing data to device\n" +
                                           "          Options for 'cap' inbuffer-size outbuffer-size");
            System.exit (3);
          }
        Test test = new Test (args[1], Integer.parseInt (args[2]));
                           
        for (int i = 0; i < Integer.parseInt (args[3]); i++)
          {
            try
              {
                if (i > 0 && Integer.parseInt (args[4]) > 0)
                  {
                    Thread.sleep (Integer.parseInt (args[4]));
                  }
                if (args[0].equals ("cap"))
                  {
                    test.capacityCommand (Integer.parseInt (args[5]), Integer.parseInt (args[6]));
                  }
                else if (args[0].equals ("tim"))
                  {
                    test.deviceTimeoutCommand ();
                  }
                else if (args[0].equals ("mis"))
                  {
                    test.missingDataCommand ();
                  }
                else
                  {
                    System.out.println ("Bad command:" + args[0]);
                    System.exit (3);
                  }
              }
            catch (Exception e)
              {
                System.out.println (e);
              }
          }
      }

  }
