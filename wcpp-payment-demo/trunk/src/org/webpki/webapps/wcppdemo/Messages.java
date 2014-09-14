package org.webpki.webapps.wcppdemo;

public enum Messages
  {
    INITIALIZE ("Initialize"),
    INVOKE     ("Invoke"),
    ABORT      ("Abort"),
    AUTHORIZE  ("Authorize"),
    TRANS_REQ  ("TransactionRequest"),
    TRANS_RES  ("TransactionResponse");
    
    String json_name;
    
    Messages (String json_name)
      {
        this.json_name = json_name;
      }

    @Override
    public String toString ()
      {
        return json_name;
      }
  }
