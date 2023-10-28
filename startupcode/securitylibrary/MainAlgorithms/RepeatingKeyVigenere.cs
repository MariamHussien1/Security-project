using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{

    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {

        public string Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            int clength = cipherText.Length;
            string alphabet = "abcdefghijklmnopqrstuvwxyz";
            string key = "";
            string temp = "";
            for (int i = 0; i < clength; i++)
            {
                key = key + alphabet[((alphabet.IndexOf(cipherText[i]) - alphabet.IndexOf(plainText[i])) + 26) % 26];
            }
            temp = temp + key[0];
            int klength = key.Length;
            for (int i = 1; i < klength; i++)
            {
                if (cipherText.Equals(Encrypt(plainText, temp)))
                {
                    return temp;
                }
                temp = temp + key[i];
            }
            return key;

        }

        private string RepeatKey(string key, int length)
        {
            StringBuilder repeatedKey = new StringBuilder(length);

            for (int i = 0; i < length; i++)
            {
                char keyChar = key[i % key.Length];
                repeatedKey.Append(keyChar);
            }

            return repeatedKey.ToString();
        }


        private int Mod(int x, int m)
        {
            return (x % m + m) % m;
        }

        private char DecryptChar(char cipherChar, char keyChar)
        {
            if (!char.IsLetter(cipherChar))
            {
                return cipherChar;
            }

            int cipherOffset = char.IsUpper(cipherChar) ? 'A' : 'a';
            int keyOffset = char.IsUpper(keyChar) ? 'A' : 'a';
            int cipherIndex = cipherChar - cipherOffset;
            int keyIndex = keyChar - keyOffset;
            int plainIndex = Mod((cipherIndex - keyIndex), 26);
            int plainOffset = cipherOffset;
            char plainChar = (char)(plainIndex + plainOffset);
            return plainChar;
        }


        public string Decrypt(string cipherText, string key)
        {
            string repeatedKey = RepeatKey(key, cipherText.Length);
            StringBuilder plainText = new StringBuilder(cipherText.Length);

            for (int i = 0; i < cipherText.Length; i++)
            {
                char cipherChar = cipherText[i];
                char keyChar = repeatedKey[i];
                char plainChar = DecryptChar(cipherChar, keyChar);
                plainText.Append(plainChar);
            }

            return plainText.ToString();
        }

        public string Encrypt(string plainText, string key)
        {
            int temp = 0;
            int plength = plainText.Length;
            string ciphertext = "";
            string alphabet = "abcdefghijklmnopqrstuvwxyz";
            while (key.Length != plainText.Length)
            {
                key = key + key[temp];
                temp++;
            }
            for (int i = 0; i < plength; i++)
            {
                char plainChar = plainText[i];
                int plainIndex = alphabet.IndexOf(plainChar);

                char keyChar = key[i];
                int keyIndex = alphabet.IndexOf(keyChar);

                int cipherIndex = (plainIndex + keyIndex) % 26;

                char cipherChar = alphabet[cipherIndex];
                ciphertext = ciphertext + cipherChar;
            }
            return ciphertext;
        }



    }
}
