using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.IO;
using Mono.Security.Cryptography;
using LibNPKI;

namespace NPKIIdentication
{
    public partial class Form1 : Form
    {
        private CertificateLocation certificate;
        public Form1()
        {
            InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            var certs = CertificateFinder.GetCertificateLocations();
            certificate = CertificateSelecter.ShowSelectionDialog(certs, out string password);
            if (certificate == null)
            {
                MessageBox.Show("선택되지 않음", "오류", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            try
            {
                certificate.PrivateKeyInfo = CertificateLoader.DecryptPrivateKey(certificate, password);
            }
            catch (LibNPKI.Exceptions.IncorretPasswordException)
            {
                MessageBox.Show("잘못된 비밀번호입니다.", "오류", MessageBoxButtons.OK, MessageBoxIcon.Error);
                certificate = null;
                return;
            }
            groupBox1.Visible = true;
            groupBox1.Enabled = true;
        }

        private void button2_Click(object sender, EventArgs e)
        {
            VIDVerifier verifier = new VIDVerifier();
            if (verifier.VerifyWithID(certificate.PublicKeyCertificate, certificate.PrivateKeyInfo, textBox1.Text))
            {
                MessageBox.Show("확인됐습니다.", "결과", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            else
            {
                MessageBox.Show("확인에 실패했습니다.", "결과", MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
            }
        }

        private void button3_Click(object sender, EventArgs e)
        {
            byte[] priKey = PKCS8.PrivateKeyInfo.Encode(CertificateLoader.ConvertPrivateKeyToRSA(certificate.PrivateKeyInfo.PrivateKey));
            if (File.Exists(textBox2.Text))
            {
                MessageBox.Show("파일이 이미 존재함", "오류", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            using (FileStream fs = new FileStream(textBox2.Text, FileMode.Create, FileAccess.Write))
            {
                fs.Write(priKey, 0, priKey.Length);
                fs.Flush();
            }
            MessageBox.Show("내보냈습니다.", "결과", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
    }
}
