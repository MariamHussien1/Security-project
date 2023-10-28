using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SecurityLibrary.AES;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>
        public int efficientPower(int baseN, int power, int modulus)
        {
            int result = 1;
            for (int i = 0; i < power; i++)
            {
                result = (result * baseN) % modulus;
            }
            return result;
        }

        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            //throw new NotImplementedException();
            List<long> C = new List<long>();
            C.Add(efficientPower(alpha, k, q));
            int K = efficientPower(y, k, q);
            C.Add(efficientPower(K * m, 1, q));
            return C;
        }
        public int Decrypt(int c1, int c2, int x, int q)
        {
            //throw new NotImplementedException();
            ExtendedEuclid E = new ExtendedEuclid();
            int k = efficientPower(c1, x, q);
            int KK = E.GetMultiplicativeInverse(k, q);
         
            return efficientPower(KK * c2, 1, q);

        }
    }
}