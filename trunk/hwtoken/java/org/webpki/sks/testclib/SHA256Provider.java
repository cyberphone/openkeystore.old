package org.webpki.sks.testclib;

public class SHA256Provider
  {
    static 
      { 
        System.loadLibrary ("jni-crypto"); 
      } 

    long cpp_pointer;
    
    public SHA256Provider ()
      {
        cpp_pointer = createSHA256Provider ();
      }
    
    private native long createSHA256Provider ();
    
    private native void deleteSHA256Provider (long cpp_pointer);
    
    private native void update (long cpp_pointer, byte[] data);

    private native byte[] doFinal (long cpp_pointer);


    public void dispose ()
      {
        if (cpp_pointer != 0)
          {
            deleteSHA256Provider (cpp_pointer);
            cpp_pointer = 0;
          }
      }
    
    public void update (byte[] data)
      {
        update (cpp_pointer, data);
      }
    
    
    public byte[] doFinal ()
      {
        return doFinal (cpp_pointer);
      }

  }
