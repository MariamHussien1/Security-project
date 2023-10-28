using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SecurityLibrary.DiffieHellman;
using SecurityLibrary.AES;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        AES.ExtendedEuclid extendedEuclid = new AES.ExtendedEuclid();
        public int Encrypt(int p, int q, int M, int e)
        {
            int n = p * q;
            int x = efficientPower(M, e, n);
            //(a*b)%n=(a%n*b%n)%n
            return x;
           
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            int n = p * q;
            int Qn = (p - 1) * (q - 1);
            //calculate key
            int d = extendedEuclid.GetMultiplicativeInverse(e, Qn);
            int x = efficientPower(C, d, n);
            return x;
           
        }
        public int efficientPower(int baseN, int power, int modulus)
        {
            int result = 1;
            for (int i = 0; i < power; i++)
            {
                result = (result * baseN) % modulus;
            }
            return result;
        }
    }
}