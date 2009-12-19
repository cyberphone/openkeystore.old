#include "mbed.h"

Serial pc(USBTX, USBRX); // tx, rx

DigitalOut myled_4(LED4);
DigitalOut myled_3(LED3);
DigitalOut myled_2(LED2);
DigitalOut myled_1(LED1);

Timer serial_timeout;

const int MAX_DELAY_BETWEEN_CHARCTERS_IN_MS = 2000;

const int BAUD_RATE = 460800;

const int CAPACITY_COMMAND       = 1;
const int MISSING_DATA_COMMAND   = 2;
const int DEVICE_TIMEOUT_COMMEND = 3;

static int counter;

static int length;
static int curr_pos;

static bool buffer_full;

static int readCharTimed ()
  {
    serial_timeout.reset ();
    while (!pc.readable ())
      {
        if (serial_timeout.read_ms () > MAX_DELAY_BETWEEN_CHARCTERS_IN_MS)
          {
            myled_1 = 1;
            return -1;
          }
      }
    return pc.getc ();
  }

int getCommand (int first_char)
  {
    buffer_full = false;
    serial_timeout.start ();
    int next_char = readCharTimed ();
    if (next_char < 0)
      {
        myled_2 = 1;
        return -1;
      }
    length = ((first_char << 8) + next_char) & 0xFFFF;
    curr_pos = 1;
    return readCharTimed ();  // This is the command (pos 0 in expected buffer)
  }

#define OUTPUT_TIMED

void putByte (int c)
  {
#ifdef OUTPUT_TIMED
    if (!buffer_full)
      {
        serial_timeout.start ();
        while (true)
          {
            if (pc.writeable ())
              {
#endif
                pc.putc (c);
#ifdef OUTPUT_TIMED
                break;
              }
            if (serial_timeout.read_ms () > MAX_DELAY_BETWEEN_CHARCTERS_IN_MS)
              {
                myled_1 = 1;
                myled_4 = 1;
                buffer_full = true;
                break;
              }
          }
      }
#endif
  }


void putSuccessStatus ()
  {
    if (curr_pos != length)
      {
        myled_1 = 1;
        myled_2 = 1;
        myled_3 = 1;
      }
    putByte (0);
  }


void putShort (int v)
  {
    putByte (v >> 8);
    putByte (v & 0xFF);
  }


void putString (char *string)
  {
    int len = strlen (string);
    putShort (len);
    for (int i = 0; i < len; i++)
      {
        pc.putc (string[i]);
      }
  }


int getChar ()
  {
    if (curr_pos++ >= length)
      {
        myled_3 = 1;
      }
    return readCharTimed() & 0xFF;
  }

int getShort ()
  {
    int v = getChar () << 8;
    return v + getChar ();
  }

int main()
  {
    pc.baud (BAUD_RATE);
    while (1)
      {
        counter++;
        switch (getCommand (pc.getc ()))
          {
            case CAPACITY_COMMAND:
              int out_buffer_size;
              out_buffer_size = getShort () & 0xFFFF;
              int in_buffer_size;
              in_buffer_size = getShort () & 0xFFFF;
              while (in_buffer_size-- > 0)
                {
                  getChar ();
                }
              putSuccessStatus ();
              putShort (out_buffer_size);
              while (out_buffer_size-- > 0)
                {
                  putByte (0);
                }    
              break;

            case MISSING_DATA_COMMAND:
              getShort ();
              putSuccessStatus ();
              break;

            case DEVICE_TIMEOUT_COMMEND:
              wait (30);
              putSuccessStatus ();
              break;
              
            default:
              myled_2 = 1;
              pc.putc (7);
              putString ("No such command...");
          }
      }
  }
