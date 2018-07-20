using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace LibNPKI
{
    partial class CertificateSelectionDialog : Form
    {
        public CertificateSelectionDialog()
        {
            InitializeComponent();
        }
        public string certPassword { get { return textBox1.Text; } }
        public void addCertsToList(IEnumerable<CertificateLocation> certs)
        {
            foreach(CertificateLocation cert in certs)
            {
                ListViewItem item = new ListViewItem();
                item.Tag = cert;
                item.Text = cert.PublicKeyCertificate.Subject;
                item.SubItems.Add(cert.PublicKeyCertificate.NotAfter.ToString());
                item.SubItems.Add(cert.LocationDescription);
                listView1.Items.Add(item);
            }
        }
        public CertificateLocation selectedCert
        {
            get
            {
                return listView1.SelectedItems.Count == 0 ? null : (CertificateLocation)listView1.SelectedItems[0].Tag;
            }
        }

        private void button2_Click(object sender, EventArgs e)
        {
            this.DialogResult = DialogResult.OK;
            this.Close();
        }

        private void button3_Click(object sender, EventArgs e)
        {
            this.DialogResult = DialogResult.No;
            this.Close();
        }

        private void textBox1_KeyUp(object sender, KeyEventArgs e)
        {
            if (e.KeyCode == Keys.IMENonconvert)
                button2_Click(null, null);
        }
    }
}
