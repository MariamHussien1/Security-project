using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{

    public class DiffieHellman
    {
        public int efficientPower(int baseN, int power, int modulus)
        {
            int result = 1;
            for (int i = 0; i < power; i++)
            {
                result = (result * baseN) % modulus;
            }
            return result;
        }

        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            //throw new NotImplementedException();
            List<int> keys = new List<int>();

            int ya = efficientPower(alpha, xa, q);
            keys.Add(efficientPower(ya, xb, q));
            keys.Add(efficientPower(ya, xb, q));
            return keys;
        }
    }
}