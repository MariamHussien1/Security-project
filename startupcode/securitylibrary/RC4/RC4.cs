using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RC4
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class RC4 : CryptographicTechnique
    {
        public void S(ref int[] s)
        {
            s = new int[256];
            for (int i = 0; i < 256; i++)
            {
                s[i] = i;
            }
        }

        public void SByte(ref byte[] byteArray)
        {
            byteArray = new byte[256];

            for (int i = 0; i < 256; i++)
            {
                byteArray[i] = (byte)i;
            }
        }

        public void T(string key, ref int[] t)
        {
            t = new int[256];
            for (int i = 0; i < 256; i++)
            {
                t[i] = System.Convert.ToInt32(key[i % key.Length]);
            }
        }

        public void TByte(byte[] key, ref byte[] t)
        {
            t = new byte[256];
            for (int i = 0; i < 256; i++)
            {
                t[i] = key[(i % key.Length)];
            }
        }

        public void IntialPermutation(int[] T, ref int[] S)
        {
            int j = 0;
            for (int i = 0; i < 256; i++)
            {
                j = (j + S[i] + T[i]) % 256;
                int temp = S[i];
                S[i] = S[j];
                S[j] = temp;
            }
        }

        public void IntialPermutationByte(byte[] T, ref byte[] S)
        {
            int j = 0;
            for (int i = 0; i < 256; i++)
            {
                j = (j + S[i] + T[i]) % 256;
                byte temp = S[i];
                S[i] = S[j];
                S[j] = temp;
            }
        }

        public void StreamGeneration(int[] S, ref int[] K, string text)
        {
            int i = 0, j = 0;

            for (int k = 0; k < text.Length; k++)
            {
                i = (i + 1) % 256;
                j = (j + S[i]) % 256;
                int temp = S[i];
                S[i] = S[j];
                S[j] = temp;
                int t = (S[i] + S[j]) % 256;
                K[k] = S[t];
            }
        }

        public void StreamGenerationByte(byte[] S, ref byte[] K, byte[] text)
        {
            int i = 0, j = 0;

            for (int k = 0; k < text.Length; k++)
            {
                i = (i + 1) % 256;
                j = (j + S[i]) % 256;
                byte temp = S[i];
                S[i] = S[j];
                S[j] = temp;
                int t = (S[i] + S[j]) % 256;
                K[k] = S[t];
            }
        }

        public void XOR(int[] K, string text, ref string answer)
        {
            int length = text.Length;
            int[] arr = new int[length];
            int[] result = new int[length];
            char[] result2 = new char[length];

            for (int i = 0; i < length; i++)
            {
                arr[i] = System.Convert.ToInt32(text[i]);
            }
            for (int i = 0; i < length; i++)
            {
                result[i] = arr[i] ^ K[i];
            }
            for (int i = 0; i < length; i++)
            {
                result2[i] = Convert.ToChar(result[i]);
            }
            foreach (var s in result2)
            {
                answer += s;
            }
        }

        public void XORByte(byte[] K, byte[] text, ref string answer)
        {
            int length = text.Length;
            byte[] result = new byte[length];
            char[] result2 = new char[length];

            for (int i = 0; i < length; i++)
            {
                result[i] = (byte)(text[i] ^ K[i]);
            }
            answer = "0x" + BitConverter.ToString(result).Replace("-", "").ToLower();
        }

        public override string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            int[] s = new int[256];
            int[] t = new int[256];
            int[] K = new int[256];
            string plain = "";
            if (cipherText[0] == '0' && cipherText[1] == 'x' && key[0] == '0' && key[1] == 'x')
            {

                cipherText = cipherText.Substring(2);
                key = key.Substring(2);

                byte[] st = new byte[cipherText.Length - 2];
                int v = 0;
                for (int i = 0; i < cipherText.Length; i++)
                {
                    if (i % 2 == 0)
                    {
                        st[v] = Convert.ToByte(cipherText.Substring(i, 2), 16);
                        v += 1;
                    }
                }

                for (int i = 0; i < st.Length; i++)
                {
                    if (st[i] != 0)
                    {
                        v += 1;
                    }
                }
                byte[] newcipher = new byte[v / 2];
                for (int i = 0; i < newcipher.Length; i++)
                {
                    newcipher[i] = st[i];
                }

                byte[] st1 = new byte[key.Length - 2];
                v = 0;
                for (int i = 0; i < key.Length; i++)
                {
                    if (i % 2 == 0)
                    {
                        st1[v] = Convert.ToByte(key.Substring(i, 2), 16);
                        v += 1;
                    }
                }

                for (int i = 0; i < st.Length; i++)
                {
                    if (st1[i] != 0)
                    {
                        v += 1;
                    }
                }
                byte[] newkey = new byte[v / 2];
                v = 0;
                for (int i = 0; i < newkey.Length; i++)
                {
                    newkey[i] = st1[i];
                }

                byte[] T = new byte[256];
                byte[] S = new byte[256];
                byte[] k = new byte[256];

                SByte(ref S);
                TByte(newkey, ref T);
                IntialPermutationByte(T, ref S);
                StreamGenerationByte(S, ref k, newcipher);
                XORByte(k, newcipher, ref plain);
                return plain;
            }
            else
            {
                S(ref s);
                T(key, ref t);
                IntialPermutation(t, ref s);
                StreamGeneration(s, ref K, cipherText);
                XOR(K, cipherText, ref plain);
                return plain;
            }
        }

        public override string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            int[] s = new int[256];
            int[] t = new int[256];
            int[] K = new int[256];
            string cipher = "";
            if (plainText[0] == '0' && plainText[1] == 'x' && key[0] == '0' && key[1] == 'x')
            {

                plainText = plainText.Substring(2);
                key = key.Substring(2);
                byte[] st = new byte[plainText.Length - 2];
                int v = 0;
                for (int i = 0; i < plainText.Length; i++)
                {
                    if (i % 2 == 0)
                    {
                        st[v] = Convert.ToByte(plainText.Substring(i, 2), 16);
                        v += 1;
                    }
                }

                for (int i = 0; i < st.Length; i++)
                {
                    if (st[i] != 0)
                    {
                        v += 1;
                    }
                }
                byte[] newplain = new byte[v / 2];
                for (int i = 0; i < newplain.Length; i++)
                {
                    newplain[i] = st[i];
                }

                byte[] st1 = new byte[key.Length - 2];
                v = 0;
                for (int i = 0; i < key.Length; i++)
                {
                    if (i % 2 == 0)
                    {
                        st1[v] = Convert.ToByte(key.Substring(i, 2), 16);
                        v += 1;
                    }
                }

                for (int i = 0; i < st.Length; i++)
                {
                    if (st1[i] != 0)
                    {
                        v += 1;
                    }
                }
                byte[] newkey = new byte[v / 2];
                v = 0;
                for (int i = 0; i < newkey.Length; i++)
                {
                    newkey[i] = st1[i];
                }

                byte[] T = new byte[256];
                byte[] S = new byte[256];
                byte[] k = new byte[256];

                SByte(ref S);
                TByte(newkey, ref T);
                IntialPermutationByte(T, ref S);
                StreamGenerationByte(S, ref k, newplain);
                XORByte(k, newplain, ref cipher);
                return cipher;
            }
            else
            {
                S(ref s);
                T(key, ref t);
                IntialPermutation(t, ref s);
                StreamGeneration(s, ref K, plainText);
                XOR(K, plainText, ref cipher);
                return cipher;
            }
        }
    }
}
