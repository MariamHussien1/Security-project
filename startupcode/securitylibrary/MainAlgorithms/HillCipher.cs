using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


namespace SecurityLibrary
{
    public class Vector
    {
        public List<int> data;
        public Vector(int[] data)
        {
            this.data = new List<int>(data);
        }
        public Vector(List<int> data)
        {
            this.data = data;
        }
    }
    public class Matrix
    {
        public int[,] data;
        public int cols;
        public int rows;
        public Matrix(int[,] data, int rows, int cols)
        {
            this.data = data;
            this.cols = cols;
            this.rows = rows;
        }
        public Matrix(List<int> data, int size)
        {
            this.data = new int[size, size];
            this.rows = size;
            this.cols = size;
            for (int i = 0; i < size; i++)
            {
                for (int j = 0; j < size; j++)
                {
                    this.data[i, j] = data[i * size + j];
                }
            }
        }
        public static Matrix operator %(Matrix a, int mod)
        {
            return new Matrix(ModInverse(a.data, mod), a.rows, a.cols);
        }
        public static int operator ~(Matrix a)
        {
            return Determinant(a.data, 26);
        }
        public static Vector operator *(Matrix a, Vector b)
        {
            int[] result = new int[b.data.Count];
            for (int i = 0; i < a.cols; i++)
            {
                for (int j = 0; j < b.data.Count; j++)
                {
                    result[i] += a.data[i, j] * b.data[j];
                }
                result[i] = result[i] % 26;
            }
            return new Vector(result);

        }
        private static int[,] ModInverse(int[,] matrix, int p)
        {
            int n = matrix.GetLength(0);
            int[,] adjoint = Adjoint(matrix, p);
            int det = Determinant(matrix, p);
            if (det == 0) throw new Exception();
            int detInverse = 0;
            for (int i = 1; i < p; i++)
            {
                if ((det * i) % p == 1)
                {
                    detInverse = i;
                    break;
                }
            }
            if (detInverse == 0) throw new Exception();
            int[,] result = new int[n, n];
            for (int i = 0; i < n; i++)
            {
                for (int j = 0; j < n; j++)
                {
                    result[i, j] = ((adjoint[i, j] * detInverse) % p + p) % p;
                }
            }
            return result;
        }

        private static int[,] Adjoint(int[,] matrix, int p)
        {
            int n = matrix.GetLength(0);
            int[,] result = new int[n, n];
            for (int i = 0; i < n; i++)
            {
                for (int j = 0; j < n; j++)
                {
                    int sign = ((i + j) % 2 == 0) ? 1 : -1;
                    int[,] minor = Minor(matrix, i, j);
                    result[j, i] = sign * Determinant(minor, p);
                }
            }
            return result;
        }

        private static int Determinant(int[,] matrix, int p)
        {
            int n = matrix.GetLength(0);
            if (n == 1) return matrix[0, 0];
            int result = 0;
            int sign = 1;
            for (int j = 0; j < n; j++)
            {
                int[,] minor = Minor(matrix, 0, j);
                int cofactor = Determinant(minor, p);
                result = (result + sign * matrix[0, j] * cofactor) % p;
                sign = -sign;
            }
            return (result + p) % p;
        }
        private static int[,] Minor(int[,] matrix, int row, int col)
        {
            int n = matrix.GetLength(0);
            int[,] result = new int[n - 1, n - 1];
            int ri = 0;
            for (int i = 0; i < n; i++)
            {
                if (i == row) continue;

                int cj = 0;
                for (int j = 0; j < n; j++)
                {
                    if (j == col) continue;

                    result[ri, cj] = matrix[i, j];
                    cj++;
                }
                ri++;
            }
            return result;
        }
    }
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            List<int> Key = new List<int>();

            for (int i = 0; i < 2; i++)
            {

                for (int j = 0; j < 26; j++)//try all of them
                {
                    if (Key.Count == 4)
                        break;
                    for (int k = 0; k < 26; k++)
                    {

                        if (((j * plainText[0]) + (k * plainText[1])) % 26 == cipherText[i] &&
                            ((j * plainText[2]) + (k * plainText[3])) % 26 == cipherText[i + 2])
                        {
                            Key.Add(j);
                            Key.Add(k);
                            break;
                        }
                    }

                }

            }
            if (Key.Count < 4)
                throw new InvalidAnlysisException();

            return Key;
        }





        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            //throw new NotImplementedException();
            int m = (int)Math.Sqrt(key.Count);
            //1- convert plaintextlist into matrix
            List<List<int>> plainTextMatrix = createMatrix(plainText, m, false, true); // its a plaintext matrix not key matrix 
            List<List<int>> keyMatrix = createMatrix(key, m, true, false); // its a plaintext matrix not key matrix 
                                                                           //2- list of the result
            List<int> resultMatrix = new List<int>();

            int lenOfrows = plainText.Count / m;//rows
            for (int i = 0; i < lenOfrows; i++)
            {
                //multiply each row *each column
                List<int> row = plainTextMatrix[i];
                List<int> result = new List<int>();
                foreach (List<int> keyRow in keyMatrix)
                {
                    int res = 0;
                    for (int k = 0; k < m; k++)
                    {
                        res += keyRow[k] * row[k];
                    }
                    res %= 26;

                    result.Add(res);
                }
                for (int j = 0; j < m; j++)
                {
                    resultMatrix.Add(result[j]);
                }

            }
            return resultMatrix;
        }
        public int[,] convertKeyListTo2dArray(List<int> input)
        {
            int[,] arr;
            //build 2d equal matrix
            if (input.Count % 3 == 0)
            {
                arr = new int[3, 3];
                for (int i = 0; i < 3; i++)
                {
                    for (int j = 0; j < 3; j++)
                    {
                        arr[i, j] = input[i];
                    }
                }
            }

            else
            {

                arr = new int[2, 2];
                for (int i = 0; i < 2; i++)
                {
                    for (int j = 0; j < 2; j++)
                    {
                        arr[i, j] = input[i];
                    }
                }
            }
            return arr;
        }

        public List<List<int>> createMatrix(List<int> input, int m, bool keyMatrix, bool plainMatrix)
        {
            //create the matrix 
            int rows = m, cols = m;
            if (keyMatrix && !plainMatrix)
                rows = m;
            else if (!keyMatrix && plainMatrix)
                rows = input.Count / m;

            List<List<int>> matrix = new List<List<int>>();
            int index = 0;
            for (int i = 0; i < rows; i++)
            {
                List<int> curruentElement = new List<int>();

                for (int j = 0; j < cols; j++)
                {
                    curruentElement.Add(input[index]);
                    index++;
                }

                matrix.Add(curruentElement);
            }
            return matrix;
        }


        public string Encrypt(string plainText, string key)
        {
            throw new NotImplementedException();
        }


        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            //throw new NotImplementedException();
            List<int> Key = new List<int>();

            for (int i = 0; i < 3; i++)
            {
                if (Key.Count == 9)
                    break;

                for (int j = 0; j < 26; j++)//try all of them
                {
                    for (int k = 0; k < 26; k++)
                    {
                        for (int l = 0; l < 26; l++)
                            if (((j * plain3[0]) + (k * plain3[1]) + (l * plain3[2])) % 26 == cipher3[i] &&
                                (((j * plain3[3]) + (k * plain3[4]) + (l * plain3[5])) % 26 == cipher3[i + 3]) && ((j * plain3[6]) + (k * plain3[7]) + (l * plain3[8])) % 26 == cipher3[i + 6])
                            {
                                Key.Add(j);
                                Key.Add(k);
                                Key.Add(l);
                                break;
                            }
                    }

                }

            }
            if (Key.Count < 9)
                throw new InvalidAnlysisException();

            return Key;
        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
            throw new NotImplementedException();
        }
        public string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            int size = (int)Math.Sqrt(key.Count);
            Matrix keyMatrix = new Matrix(key, size);
            Matrix keyMatrixInverse = keyMatrix % 26;
            List<int> plainText = new List<int>();
            int[] vector = new int[size];
            for (int i = 0; i < cipherText.Count; i++)
            {
                vector[i % size] = cipherText[i];
                if ((i + 1) % size == 0)
                {
                    Vector decryptedVector = keyMatrixInverse * new Vector(vector);
                    for (int j = 0; j < size; j++)
                    {
                        plainText.Add(decryptedVector.data[j]);
                    }
                }
            }
            return plainText;
        }
    }
}