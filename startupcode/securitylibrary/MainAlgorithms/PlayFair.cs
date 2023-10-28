using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographicTechnique<string, string>
    {
        /// <summary>
        /// The most common diagrams in english (sorted): TH, HE, AN, IN, ER, ON, RE, ED, ND, HA, AT, EN, ES, OF, NT, EA, TI, TO, IO, LE, IS, OU, AR, AS, DE, RT, VE
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="cipherText"></param>
        /// <returns></returns>
        public string Analyse(string plainText)
        {
            throw new NotImplementedException();
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }
        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            StringBuilder plainText = new StringBuilder(cipherText.ToUpper());
            int i1 = 0, i2 = 0, j1 = 0, j2 = 0, cntr2 = 0, cntr = 0, cntr1 = 0;
            string plain = "";
            char[,] matrix = new char[5, 5];
            string alpha = "ABCDEFGHIKLMNOPQRSTUVWXYZ";// no J
            List<char> Alphabet = new List<char>(alpha);
            List<char> tempAlphabet = new List<char>();
            key = key.ToUpper();


            //Remove Duplicated letters from Key
            List<char> distinctKey = key.Distinct().ToList();
            //Converting J to I
            int n = plainText.Length - 1;
            for (int i = 0; i < n; i++)
            {
                if (plainText[i] == 'J')
                {
                    plainText[i] = 'I';
                }
            }
            //Removing Alpabets which exists in Key
            foreach (var s in distinctKey)
            {
                foreach (var m in Alphabet)
                {
                    if (s == m)
                    {
                        tempAlphabet.Add(m);
                    }
                }
            }
            foreach (var s in tempAlphabet)
            {
                Alphabet.Remove(s);
            }
            //Building Matrix
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    if (cntr < distinctKey.Count)
                    {
                        matrix[i, j] = distinctKey[cntr];
                        cntr++;
                    }
                    else if (cntr1 < Alphabet.Count)
                    {
                        matrix[i, j] = Alphabet[cntr1];
                        cntr1++;
                    }
                }
            }
            //Decryption
            int newLen = plainText.Length;
            for (int i = 0; i < newLen; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    for (int k = 0; k < 5; k++)
                    {
                        if (plainText[i] != matrix[j, k])
                        {
                            continue;
                        }
                        if (cntr2 == 0)
                        {
                            i1 = j;
                            j1 = k;
                        }
                        else if (cntr2 == 1)
                        {
                            i2 = j;
                            j2 = k;
                        }
                        cntr2++;
                        if (cntr2 == 2)
                        {
                            cntr2 = 0;
                        }
                        if (cntr2 == 1)
                        {
                            continue;
                        }
                        if (i1 == i2)
                        {
                            plain += matrix[i1, (j1 + 4) % 5];
                            plain += matrix[i2, (j2 + 4) % 5];
                        }
                        else if (j1 == j2)
                        {
                            plain += matrix[(i1 + 4) % 5, j2];
                            plain += matrix[(i2 + 4) % 5, j1];
                        }
                        else
                        {
                            plain += matrix[i1, j2];
                            plain += matrix[i2, j1];
                        }
                    }
                }
            }
            //update the new plantext
            Console.WriteLine(plain.Length);
            string smallstr = plain.Substring(0, 1);

            for (int i = 1; i < plain.Length - 1; i++)
            {
                if (!(i % 2 != 0 && plain[i] == 'X' && plain[i + 1] == plain[i - 1]))
                {
                    Console.WriteLine("{0}{1}{2}", plain[i - 1], plain[i], plain[i + 1]);
                    smallstr += plain.Substring(i, 1);
                }
            }
            if (plain[plain.Length - 1] != 'X')
            {
                smallstr += plain.Substring(plain.Length - 1, 1);
            }
            plain = smallstr;

            return plain;
        }

        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();

            StringBuilder plaintext = new StringBuilder(plainText.ToUpper());

            int i1 = 0, i2 = 0, j1 = 0, j2 = 0, cntr2 = 0, cntr = 0, cntr1 = 0;
            string cipher = null, temp1 = null;

            char[,] matrix = new char[5, 5];

            string alpha = "ABCDEFGHIKLMNOPQRSTUVWXYZ";// remove j
            List<char> Alphabet = new List<char>(alpha);
            List<char> tempAlphabet = new List<char>();
            key = key.ToUpper();

            //Remove Duplicated letters from Key
            List<char> distinctKey = key.Distinct().ToList();

            //Converting J to I
            int n = plaintext.Length - 1;
            for (int i = 0; i < n; i++)
            {
                if (plaintext[i] == 'J')
                {
                    plaintext[i] = 'I';
                }
            }

            //Removing Alpabets which exists in Key
            foreach (var s in distinctKey)
            {
                foreach (var m in Alphabet)
                {
                    if (s == m)
                    {
                        tempAlphabet.Add(m);
                    }
                }
            }
            foreach (var s in tempAlphabet)
            {
                Alphabet.Remove(s);
            }

            //Building Matrix
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    if (cntr < distinctKey.Count)
                    {
                        matrix[i, j] = distinctKey[cntr];
                        cntr++;
                    }
                    else if (cntr1 < Alphabet.Count)
                    {
                        matrix[i, j] = Alphabet[cntr1];
                        cntr1++;
                    }
                }
            }

            //Adding X
            int c = plaintext.Length;
            for (int i = 0; i < c; i++)
            {
                temp1 += plaintext[i];
                if (temp1.Length == 2)
                {
                    if (temp1[0] == temp1[1])
                    {
                        plaintext.Insert(i, "X");
                        c++;
                    }
                    temp1 = null;
                }
                //if (plaintext[i] == plaintext[i + 1])
                //{
                //    plaintext.Insert(i, "X");
                //    c++;
                //    i++;
                //}
            }
            if (plaintext.Length % 2 != 0)
            {
                plaintext.Append('X');
            }

            //Encryption
            int plainLen = plaintext.Length;
            for (int i = 0; i < plainLen; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    for (int k = 0; k < 5; k++)
                    {
                        if (plaintext[i] != matrix[j, k])
                        {
                            continue;
                        }
                        if (cntr2 == 0)
                        {
                            i1 = j;
                            j1 = k;
                        }
                        else if (cntr2 == 1)
                        {
                            i2 = j;
                            j2 = k;
                        }
                        cntr2++;
                        if (cntr2 == 2)
                        {
                            cntr2 = 0;
                        }
                        if (cntr2 == 1)
                        {
                            continue;
                        }
                        if (i1 == i2)
                        {
                            cipher += matrix[i1, (j1 + 1) % 5];
                            cipher += matrix[i2, (j2 + 1) % 5];
                        }
                        else if (j1 == j2)
                        {
                            cipher += matrix[(i1 + 1) % 5, j2];
                            cipher += matrix[(i2 + 1) % 5, j1];
                        }
                        else
                        {
                            cipher += matrix[i1, j2];
                            cipher += matrix[i2, j1];
                        }
                    }
                }
            }
            return cipher;
        }
    }
}
