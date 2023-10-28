using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            plainText = plainText.Replace(" ", "");
            plainText = plainText.ToUpper();
            string plain;
            int key = 1;
            while (true)
            {
                plain = Decrypt(cipherText, key);
                if (plain == plainText)
                {
                    return key;
                }
                else
                {
                    key += 1;
                }
            }
        }

        public string Decrypt(string cipherText, int key)
        {
            //throw new NotImplementedException();
            cipherText = cipherText.Replace(" ", "");
            cipherText = cipherText.ToUpper();

            //Calculating number of columns
            double keylength = Convert.ToDouble(key);
            double cipherTextLength = Convert.ToDouble(cipherText.Length);
            double c = Math.Ceiling(cipherTextLength / keylength);
            int column = Convert.ToInt32(c);

            string plain = null;
            char[,] matrix = new char[key, column];

            int cntr = 0;

            c = c * 2 - 1;
            List<int> temp = new List<int>();

            //if ciphertext doesn't contain X
            //Add Whitespace
            if (cipherTextLength != key * column)
            {
                while (cipherTextLength != key * column)
                {
                    temp.Add(Convert.ToInt32(c));
                    cipherTextLength += 1;
                    c += column;
                }
                foreach (var t in temp)
                {
                    cipherText = cipherText.Insert(t, " ");
                }
            }
            //if ciphertext contains X
            else
            {
                if (c < cipherText.Length)
                {
                    while (true)
                    {
                        //storing index of X in temp list
                        if (cipherText[Convert.ToInt32(c)] == 'X')
                        {
                            Console.WriteLine(c);
                            temp.Add(Convert.ToInt32(c));
                            c += column;
                        }
                        else
                        {
                            break;
                        }
                        if (c > cipherText.Length)
                        {
                            break;
                        }
                    }
                    //Remove X
                    //Add whitespace
                    foreach (var t in temp)
                    {
                        cipherText = cipherText.Remove(t, 1);
                        cipherText = cipherText.Insert(t, " ");
                    }
                }
            }

            //Building matrix horizontally
            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < column; j++)
                {
                    matrix[i, j] = cipherText[cntr];
                    cntr += 1;
                }
            }

            //Reading ciphertext from matrix vertically
            for (int i = 0; i < column; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    plain += matrix[j, i];
                }
            }
            plain = plain.Replace(" ", "");

            return plain;
        }

        public string Encrypt(string plainText, int key)
        {
            //throw new NotImplementedException();
            plainText = plainText.Replace(" ", "");
            plainText = plainText.ToUpper();

            //Calculating number of columns
            double keylength = Convert.ToDouble(key);
            double plaintextLength = Convert.ToDouble(plainText.Length);
            double c = Math.Ceiling(plaintextLength / keylength);
            int column = Convert.ToInt32(c);

            string cipher = null;
            char[,] matrix = new char[key, column];

            int cntr = 0;

            //Adding whitespace to fill matrix
            if (plainText.Length != key * column)
            {
                while (plainText.Length != key * column)
                {
                    plainText += ' ';
                }
            }

            //Building matrix vertically
            for (int i = 0; i < column; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    matrix[j, i] = plainText[cntr];
                    cntr += 1;
                }
            }

            //Reading ciphertext from matrix horizontally
            foreach (var x in matrix)
            {
                cipher += x;
            }
            cipher = cipher.Replace(" ", "");

            return cipher;
        }
    }
}
