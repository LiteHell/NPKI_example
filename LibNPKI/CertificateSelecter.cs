using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LibNPKI
{
    public class CertificateSelecter
    {
        public static CertificateLocation ShowSelectionDialog(IEnumerable<CertificateLocation> certificates, out string password)
        {
            CertificateSelectionDialog dialog = new CertificateSelectionDialog();
            dialog.addCertsToList(certificates);
            dialog.ShowDialog();
            password = dialog.certPassword;
            if (dialog.DialogResult != System.Windows.Forms.DialogResult.OK)
                return null;
            return dialog.selectedCert;
        }
    }
}
