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

    internal class Form1 : Form
    {
        internal string password;

        internal Form1()
        {
            InitializeComponent();
        }

        private void Form1_Load(object sender, System.EventArgs e)
        {

        }

        private void button1_Click(object sender, System.EventArgs e)
        {
            password = textBox1.Text;
            Close();
        }

        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.button1 = new Button();
            this.textBox1 = new TextBox();
            this.SuspendLayout();
            // 
            // button1
            // 
            this.button1.Location = new System.Drawing.Point(101, 80);
            this.button1.Name = "button1";
            this.button1.Size = new System.Drawing.Size(75, 23);
            this.button1.TabIndex = 1;
            this.button1.Text = "OK";
            this.button1.UseVisualStyleBackColor = true;
            this.button1.DialogResult = DialogResult.OK;
            this.button1.Click += new System.EventHandler(this.button1_Click);
            // 
            // textBox1
            // 
            this.textBox1.Location = new System.Drawing.Point(86, 42);
            this.textBox1.Name = "textBox1";
            this.textBox1.Size = new System.Drawing.Size(100, 20);
            this.textBox1.TabIndex = 0;
            this.textBox1.UseSystemPasswordChar = true;
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(284, 130);
            this.Controls.Add(this.textBox1);
            this.Controls.Add(this.button1);
            this.Name = "Form1";
            this.StartPosition = FormStartPosition.CenterParent;
            this.Text = "PIN Code";
            this.Load += new System.EventHandler(this.Form1_Load);
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        private Button button1;
        private TextBox textBox1;
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
                Form1 f1 = new Form1();
                if (f1.ShowDialog() == DialogResult.OK)
                {
                	Authorization = System.Text.Encoding.UTF8.GetBytes(f1.password);
                    using (AesManaged aes = new AesManaged())
                    {
	                    byte[] IV = new byte[16];
	                    using (RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider())
	                    {
			            	rngCsp.GetBytes(IV);
			            }
	                    aes.Key = SHARED_SECRET_32;
	                    aes.IV = IV;
	                    byte[] encrypted;
	                    using (MemoryStream total = new MemoryStream())
	                    {
		                    using (MemoryStream msEncrypt = new MemoryStream())
		                    {
		                        using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, aes.CreateEncryptor(), CryptoStreamMode.Write))
		                        {
		 	                        csEncrypt.Write(Authorization, 0, Authorization.Length);
		 	                        csEncrypt.FlushFinalBlock(); 
		                    	}
		                    	msEncrypt.Flush();
	        	                encrypted = msEncrypt.ToArray();
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