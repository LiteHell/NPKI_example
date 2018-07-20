using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LibNPKI.Exceptions
{
    public class NotSupportedAlgorithmException : Exception
    {
        internal NotSupportedAlgorithmException(string message) : base(message)
        {

        }
    }
}
