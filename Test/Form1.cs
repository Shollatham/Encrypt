
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Test
{
    public partial class Form1 : Form
    {
        string secretKey = "Special for DEV. In production it's going to be different";
        public Form1()
        {
            InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            //output.Text = EncryptionHelper.DecodeAndDecrypt(input.Text);
            output.Text = AESGCM.SimpleDecrypt(input.Text, secretKey, "CNV");
        }
        private void button2_Click(object sender, EventArgs e)
        {
            //input.Text = EncryptionHelper.EncryptAndEncode(output.Text);
            input.Text = AESGCM.SimpleEncrypt(output.Text, secretKey, "test");
        }
    }
}
