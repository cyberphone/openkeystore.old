/*
 *  Copyright 2006-2011 WebPKI.org (http://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
namespace org.webpki.sks.ws.client
{
    using System.Security.Cryptography;
    using System.Windows.Forms;
    using System.IO;

    internal class SKSAuthorizationDialog : Form
    {
        internal string password;
        private bool retry_warning;
        private int retriesleft; 

        internal SKSAuthorizationDialog(PassphraseFormat format,
                                        Grouping grouping,
                                        AppUsage app_usage,
                                        int zero_or_retriesleft)
        {
            retry_warning = zero_or_retriesleft != 0;
            retriesleft = zero_or_retriesleft;
            InitializeComponent();
        }

        private void SKSAuthorizationDialog_Load(object sender, System.EventArgs e)
        {

        }

        private void authorization_OK_Button_Click(object sender, System.EventArgs e)
        {
            password = authorization_TextBox.Text;
            Close();
        }

        private System.ComponentModel.IContainer components = null;

        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        private void InitializeComponent()
        {
            components = new System.ComponentModel.Container();
            
            authorization_ToolTip = new ToolTip(components);
            
            authorization_Cancel_Button = new Button();
            authorization_OK_Button = new Button();
            authorization_TextBox = new TextBox();
            authorization_ToolTip.SetToolTip(authorization_TextBox, "This it it!");
            if (retry_warning)
            {
            	retry_warning_Label = new Label();
            }
            SuspendLayout();
            if (retry_warning)
            {
                retry_warning_Label.AutoSize = true;
                retry_warning_Label.Font =  new System.Drawing.Font(retry_warning_Label.Font, retry_warning_Label.Font.Style | System.Drawing.FontStyle.Bold);
                retry_warning_Label.ForeColor = System.Drawing.Color.FromArgb(((int)(((byte)(192)))), ((int)(((byte)(0)))), ((int)(((byte)(0)))));
                retry_warning_Label.Location = new System.Drawing.Point(101, 13);
                retry_warning_Label.Name = "retry_warning_Label";
                retry_warning_Label.TabIndex = 3;
                retry_warning_Label.Text = "Bad stuff =" + retriesleft;
            }
            // 
            // authorization_OK_Button
            //
            int lower_margin; 
            authorization_OK_Button.Location = new System.Drawing.Point(lower_margin = authorization_OK_Button.Size.Width / 3, 80);
            authorization_OK_Button.Name = "authorization_OK_Button";
            authorization_OK_Button.TabIndex = 1;
            authorization_OK_Button.Text = "OK";
            authorization_OK_Button.UseVisualStyleBackColor = true;
            authorization_OK_Button.DialogResult = DialogResult.OK;
            authorization_OK_Button.Click += new System.EventHandler(authorization_OK_Button_Click);
			int total_width = authorization_OK_Button.Size.Width * 4;
            // 
            // authorization_Cancel_Button
            // 
            authorization_Cancel_Button.DialogResult = DialogResult.Cancel;
            authorization_Cancel_Button.Location = new System.Drawing.Point((authorization_OK_Button.Size.Width * 8) / 3, 80);
            authorization_Cancel_Button.Name = "authorization_Cancel_Button";
            authorization_Cancel_Button.TabIndex = 2;
            authorization_Cancel_Button.Text = "Cancel";
            authorization_Cancel_Button.UseVisualStyleBackColor = true;
            // 
            // authorization_TextBox
            //
            authorization_TextBox.Width = authorization_OK_Button.Size.Width * 2;
            authorization_TextBox.PasswordChar = '\u25CF';            
            authorization_TextBox.Location = new System.Drawing.Point((total_width - authorization_TextBox.Size.Width) / 2, 42);
            authorization_TextBox.Name = "authorization_TextBox";
            authorization_TextBox.TabIndex = 0;
            // 
            // SKSAuthorizationDialog
            // 
			CancelButton = authorization_Cancel_Button;
            AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            AutoScaleMode = AutoScaleMode.Font;
            ClientSize = new System.Drawing.Size(total_width, authorization_OK_Button.Size.Height + lower_margin + authorization_OK_Button.Top);
            MaximizeBox = false;
            MinimizeBox = false;
            Controls.Add(authorization_TextBox);
            Controls.Add(authorization_OK_Button);
            Controls.Add(authorization_Cancel_Button);
            if (retry_warning)
            {
	            Controls.Add(retry_warning_Label);
            }
            Name = "SKSAuthorizationDialog";
            StartPosition = FormStartPosition.CenterParent;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            Text = "PIN Code";
            Load += new System.EventHandler(SKSAuthorizationDialog_Load);
            TopMost = true;
            ResumeLayout(false);
            PerformLayout();
        }

        private Button authorization_Cancel_Button;
        private Button authorization_OK_Button;
        private TextBox authorization_TextBox;
        private ToolTip authorization_ToolTip;
        private Label retry_warning_Label;
        
    }

    public partial class SKSWSProxy
    {
        private static byte[] SHARED_SECRET_32 = {0,1,2,3,4,5,6,7,8,9,1,0,3,2,5,4,7,6,9,8,9,8,7,6,5,4,3,2,1,0,3,2};
        
        public bool GetTrustedGUIAuthorization (int KeyHandle, ref byte[] Authorization)
        {
            KeyProtectionInfo kpi = getKeyProtectionInfo(KeyHandle);
            if ((kpi.ProtectionStatus & KeyProtectionInfo.PROTSTAT_PIN_PROTECTED) != 0)
            {
                if (kpi.InputMethod == InputMethod.TRUSTED_GUI)
                {
                    if (Authorization != null)
                    {
                        throw new System.ArgumentException ("Redundant \"Authorization\"");
                    }
                }
                else if (kpi.InputMethod == InputMethod.PROGRAMMATIC || Authorization != null)
                {
                    return false;
                }
	            if ((kpi.ProtectionStatus & KeyProtectionInfo.PROTSTAT_PIN_BLOCKED) != 0)
	            {
	                MessageBox.Show("The key is blocked due to previous PIN errors",
	                                "Authorization Error",
                                    MessageBoxButtons.OK,
                                    MessageBoxIcon.Exclamation);
	            	return false;
	            }
	            KeyAttributes ka = getKeyAttributes (KeyHandle);
                SKSAuthorizationDialog authorization_form = new SKSAuthorizationDialog((PassphraseFormat)kpi.Format,
                                                                                       (Grouping)kpi.Grouping,
                                                                                       (AppUsage)ka.AppUsage,
                                                                                       kpi.PINErrorCount == 0 ? 0 : kpi.RetryLimit - kpi.PINErrorCount);
                if (authorization_form.ShowDialog() == DialogResult.OK)
                {
                	Authorization = System.Text.Encoding.UTF8.GetBytes(authorization_form.password);
                    using (AesManaged aes = new AesManaged())
                    {
	                    byte[] IV = new byte[16];
	                    using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
	                    {
			            	rng.GetBytes(IV);
			            }
	                    aes.Key = SHARED_SECRET_32;
	                    aes.IV = IV;
	                    byte[] encrypted;
	                    using (MemoryStream total = new MemoryStream())
	                    {
		                    using (MemoryStream ms_encrypt = new MemoryStream())
		                    {
		                        using (CryptoStream cs_encrypt = new CryptoStream(ms_encrypt, aes.CreateEncryptor(), CryptoStreamMode.Write))
		                        {
		 	                        cs_encrypt.Write(Authorization, 0, Authorization.Length);
		 	                        cs_encrypt.FlushFinalBlock(); 
		                    	}
		                    	ms_encrypt.Flush();
	        	                encrypted = ms_encrypt.ToArray();
		                 	}
		                 	total.Write (IV, 0, IV.Length);
		                 	total.Write (encrypted, 0, encrypted.Length);
		                 	encrypted = total.ToArray();
		                 	total.SetLength(0);
	                        using (HMACSHA256 hmac = new HMACSHA256(SHARED_SECRET_32))
	    				    {
	    				    	total.Write(hmac.ComputeHash(encrypted), 0, 32);
	    				    	total.Write(encrypted, 0, encrypted.Length);
	    				    }
	    				    Authorization = total.ToArray();
	                 	}
                 	}
                 	return true;
           		}
           	}
            return false;
        }
    }
}