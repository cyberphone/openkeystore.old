public class dummyusers
  {    public static void main (String argc[])
      {
        int c = 0;
        for (int i = 0; i < 40; i++)
          {
            for (char j = 'a'; j < 'z'; j++)
              {
                StringBuffer sql = new StringBuffer ();
                sql.append ("INSERT INTO USERS (Password, Email, Name) VALUES ('secret','");
                sql.append (j);
                if (i < 10) sql.append ('0');
                sql.append (i).append ("@buggaboo.com','Just me").append (c++).append ("');");
                System.out.println (sql);
              }
          }
      }

  }
