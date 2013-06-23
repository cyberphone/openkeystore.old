package misc;


public enum KeyCenterCommands
  {
    RESOURCES            ("Resource&nbsp;Center",     "resources",       false,  false),
    PHONE_LAUNCH         ("Phone&nbsp;Emulator",      "phonelaunchpad",   true,  false),    SETUP_CREDENTIALS    ("Setup&nbsp;Credentials",   "setupcreds",       true,  false),
    LIST_CREDENTIALS     ("List&nbsp;Credentials",    "listcreds",        true,  false),    USER_ACCOUNT         ("User&nbsp;Account",        "account",          true,  false),
    REGISTER             ("Register/Unregister",      "register",        false,  false),
    ADMINISTRATION       ("Administration",           "adm_main",         true,   true),
    LOGIN                ("Login",                    "login",           false,  false);

    private final String button_text;

    private final String servlet_name;

    private final boolean needs_login;

    private final boolean admin_only;

    private KeyCenterCommands (String button_text, String servlet_name, boolean needs_login, boolean admin_only)
      {
        this.button_text = button_text;
        this.servlet_name = servlet_name;
        this.needs_login = needs_login;
        this.admin_only = admin_only;
      }


    public String getButtonText ()
      {
        return button_text;
      }


    public String getServletName ()
      {
        return servlet_name;
      }


    public boolean needsLogin ()
      {
        return needs_login;
      }


    public boolean needsAdmin ()
      {
        return admin_only;
      }

  }
