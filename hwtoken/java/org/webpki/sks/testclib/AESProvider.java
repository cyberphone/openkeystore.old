package org.webpki.sks.testclib;

public class AESProvider
  {
    static 
      { 
        System.loadLibrary ("jni-crypto"); 
      } 

    long cpp_pointer;
    
    public AESProvider ()
      {
        cpp_pointer = createAESProvider ();
      }
    
    private native long createAESProvider ();
    
    private native void deleteAESProvider (long cpp_pointer);
    
    private native void setKey (long cpp_pointer, byte[] raw_key, boolean encrypt);

    private native byte[] encrypt (long cpp_pointer, byte[] data, byte[] iv, boolean pad);


    public void dispose ()
      {
        if (cpp_pointer != 0)
          {
            deleteAESProvider (cpp_pointer);
            cpp_pointer = 0;
          }
      }
    
    public void setKey (byte[] raw_key, boolean encrypt)
      {
        setKey (cpp_pointer, raw_key, encrypt);
      }
    
    
    public byte[] encrypt (byte[] data, byte[] iv, boolean pad)
      {
        return encrypt (cpp_pointer, data, iv, pad);
      }

  }
