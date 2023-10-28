using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


namespace SecurityLibrary
{

    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public string Encrypt(string plainText, List<int> key)
        {

            int totalchars = plainText.Length;
            int col = key.Count;
            int row = (totalchars / col);
            string cipher = "";
            if (totalchars % col != 0)
            {
                row += 1;
            }
            char[,] matrix = new char[row, col];
            int k = 0;
            for (int i = 0; i < row; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    if (totalchars > k)
                    {
                        matrix[i, j] = plainText[k];
                        k++;
                    }
                    else
                        matrix[i, j] = 'x';
                }
            }
            for (int i = 0; i < col; i++)
            {
                int column = key.IndexOf(i + 1);
                for (int j = 0; j < row; j++)
                {
                    if (matrix[j, column] != 'x')
                        cipher += matrix[j, column];

                }
            }
            /*string cipher = new string(c);*/
            return cipher.ToUpper();


        }

        public List<int> Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            List<int> key = new List<int>();

            int Row = 4;
            // all possible keys
            while (true)
            {


                int Col = cipherText.Length / Row;
                int counter = 0;
                char[,] Arr1 = new char[Row, Col];
                char[,] Arr2 = new char[Row, Col];
                //fill the two matrixes
                for (int i = 0; i < Row; i++)
                {
                    for (int j = 0; j < Col; j++)
                    {
                        Arr1[i, j] = plainText[counter];
                        counter++;
                    }
                }
                counter = 0;
                for (int i = 0; i < Col; i++)
                {
                    for (int j = 0; j < Row; j++)
                    {

                        Arr2[j, i] = cipherText[counter];
                        counter++;
                    }
                }

                bool check = true;
                for (int i = 0; i < Col; i++)
                {

                    for (int j = 0; j < Col; j++)
                    {
                        check = true;

                        for (int k = 0; k < Row; k++)
                        {
                            if (Arr1[k, i] != Arr2[k, j])
                            {
                                check = false;
                                break;
                            }

                        }
                        if (check)
                        {
                            key.Add(j + 1);
                        }

                    }

                }

                if (check)
                {
                    break;
                }
                Row++;
            }
            while (key.Count < 10)
                key.Add(-1);
            return key;
        }


        public string Decrypt(string cipherText, List<int> key)
        {
            //throw new NotImplementedException();//
            int totalchars = cipherText.Length;
            int col = key.Count;
            int row = (totalchars / col);
            string plaintext = "";
            if (totalchars % col != 0)
            {
                row += 1;
            }
            char[,] matrix = new char[row, col];
            int k = 0;
            for (int i = 0; i < col; i++)
            {
                int column = key.IndexOf(i + 1);
                for (int j = 0; j < row; j++)
                {
                    if (totalchars > k)
                    {
                        matrix[j, column] = cipherText[k++];

                    }
                    else
                        matrix[j, column] = 'x';
                }
            }

            for (int i = 0; i < row; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    if (matrix[i, j] != 'x')
                        plaintext += matrix[i, j];
                }
            }

            return plaintext.ToUpper();

        }





    }
}