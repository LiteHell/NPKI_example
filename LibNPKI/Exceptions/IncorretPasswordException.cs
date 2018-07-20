using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LibNPKI.Exceptions
{
    public class IncorretPasswordException : Exception
    {
        internal IncorretPasswordException() : base("Incorrect password for decrypting private key")
        {

        }
    }
}
