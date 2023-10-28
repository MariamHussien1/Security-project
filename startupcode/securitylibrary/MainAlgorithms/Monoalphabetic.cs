using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        static Dictionary<char, char> CreateEMap(string key)
        {
            Dictionary<char, char> map = new Dictionary<char, char>();
            for (int i = 0; i < 26; i++)
            {
                map.Add((char)('A' + i), key[i]);
            }
            return map;
        }
        static Dictionary<char, char> CreateDMap(string key)
        {
            Dictionary<char, char> map = new Dictionary<char, char>();
            for (int i = 0; i < 26; i++)
            {

                map.Add(key[i], (char)('a' + i));

            }
            return map;
        }
        static SortedDictionary<char, char> CreateAMap(string plainText, string cipherText)
        {
            char[] arr = new char[26]; //set of all char
            SortedDictionary<char, char> map = new SortedDictionary<char, char>();
            //create set of char and map of all char with flag value #
            for (int i = 0; i < 26; i++)
            {
                arr[i] = ((char)('a' + i));
                map.Add((char)('a' + i), '#');
            }

            //set for every plan char a cipher char and remove that cipher char  from array
            int l = plainText.Length;
            for (int i = 0; i < l; i++)
            {
                if (map[plainText[i]] != '#')
                {
                    continue;
                }
                map[plainText[i]] = cipherText[i];

                arr = arr.Except(new char[] { cipherText[i] }).ToArray();
            }
            // replace every flag with reminder char in array
            int top = 0;
            foreach (KeyValuePair<char, char> kvp in map.ToArray())
            {
                if (kvp.Value == '#')
                {
                    map[kvp.Key] = arr[top];
                    top++;
                }

            }
            return map;
        }
        static Dictionary<char, double> CreateFMap(string cipherText)
        {
            Dictionary<char, double> map = new Dictionary<char, double>();
            int l = cipherText.Length;
            for (int i = 0; i < l; i++)
            {
                if (map.ContainsKey(cipherText[i]))
                {
                    map[cipherText[i]]++;
                }
                else
                {
                    map[cipherText[i]] = 1;
                }

            }
            //calculate frequancy
            foreach (KeyValuePair<char, double> kvp in map.ToArray())
            {
                map[kvp.Key] = (kvp.Value / l * 100);
            }
            // sort map with value
            var sortedmap = map.OrderBy(x => x.Value).ToDictionary(x => x.Key, x => x.Value);
            return sortedmap;
        }

        public string Analyse(string plainText, string cipherText)
        {
            SortedDictionary<char, char> mapP = CreateAMap(plainText.ToLower(), cipherText.ToLower());
            string key = "";


            foreach (KeyValuePair<char, char> kvp in mapP)
            {
                key += kvp.Value;
            }


            return key.ToLower();
        }

        public string Decrypt(string cipherText, string key)
        {
            string plainText = "";
            Dictionary<char, char> map = CreateDMap(key);
            cipherText = cipherText.ToLower();
            foreach (char c in cipherText)
            {
                if (map.ContainsKey(c))
                {
                    plainText += map[c];
                }

            }



            return plainText;
        }


        public string Encrypt(string plainText, string key)
        {
            // throw new NotImplementedException();

            Dictionary<char, char> map = CreateEMap(key);
            string cipherText = "";
            plainText = plainText.ToUpper();
            foreach (char c in plainText)
            {
                if (map.ContainsKey(c))
                {
                    cipherText += map[c];
                }

            }
            return cipherText;
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            string plain = "";
            Dictionary<char, double> map = CreateFMap(cipher);
            int l = cipher.Length;
            int i = 25;
            char[] arr = { 'E', 'T', 'A', 'O', 'I', 'N', 'S', 'R', 'H', 'L', 'D', 'C', 'U', 'M', 'F', 'P', 'G', 'W', 'Y', 'B', 'V', 'K', 'X', 'J', 'Q', 'Z' };
            foreach (KeyValuePair<char, double> kvp in map.ToArray())
            {
                map[kvp.Key] = arr[i];
                i--;
            }
            for (int z = 0; z < l; z++)
            {
                plain += (char)map[cipher[z]];
            }



            return plain.ToLower();
        }
    }
}