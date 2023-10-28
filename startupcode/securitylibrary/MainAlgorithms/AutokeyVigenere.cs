using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            string key = "";

            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            int len = cipherText.Length;
            for (int i = 0; i < len; i++)
            {
                if ((cipherText[i] - plainText[i] < 0))
                {
                    key += (Convert.ToChar((cipherText[i] - plainText[i] + 123)));
                }
                else
                {
                    key += (Convert.ToChar((cipherText[i] - plainText[i] + 97)));
                }

            }
            if (key.Contains(plainText[0]))
            {
                int index = key.LastIndexOf(plainText[0]);
                int end = index;
                int counter = 1;//start from second index in plaintext the first has been chiked
                bool flag = true;
                //loop from first elemt of plain text(index) unti end of key if(all is equal) that is added string 
                while (index < key.Length - 1)
                {
                    index++;
                    if ((key[index] != plainText[counter]))
                    {
                        flag = false;
                        break;
                    }
                    counter++;
                }
                if (flag == true)
                {
                    key = key.Remove(end, key.Length - end); // remove from first element of plain in key (end)until last char of key
                }
            }

            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            string plain = "";
            key = key.ToLower();
            cipherText = cipherText.ToLower();

            int len = cipherText.Length;
            for (int i = 0; i < len; i++)
            {
                if ((cipherText[i] - key[i] < 0))
                {
                    plain += (Convert.ToChar((cipherText[i] - key[i] + 123)));
                }
                else
                {
                    plain += (Convert.ToChar((cipherText[i] - key[i] + 97)));
                }
                if (key.Length < cipherText.Length)
                {
                    key += plain[i];

                }

            }

            return plain;
        }


        public string Encrypt(string plainText, string key)
        {
            // throw new NotImplementedException();
            string cipher = "";
            key = key.ToLower();
            plainText = plainText.ToLower();
            key += plainText.Substring(0, plainText.Length - key.Length);


            int len = key.Length;
            for (int i = 0; i < len; i++)
            {
                if ((key[i] + plainText[i] - 97) > 122)
                {
                    cipher += (Convert.ToChar((key[i] + plainText[i] - 123)));
                }
                else
                {
                    cipher += (Convert.ToChar((key[i] + plainText[i] - 97)));
                }

            }
            return cipher;


        }
    }
}
