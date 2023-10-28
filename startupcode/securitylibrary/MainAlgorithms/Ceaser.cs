using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Text.RegularExpressions;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {

        public string Encrypt(string plainText, int key)
        {


            //throw new NotImplementedException();

            int len = plainText.Length;


            string EncryptedStr = "";
            for (int i = 0; i < len; i++)
            {
                int asciiVal = 0;

                if (((int)plainText[i] + key) > 'z')// ascii number of z which is the last alpabet
                {
                    asciiVal = ((int)plainText[i] + key) - 26;

                }
                else
                {
                    asciiVal = (int)plainText[i] + key;
                }

                EncryptedStr += ((char)asciiVal);
            }


            return EncryptedStr;
        }

        public string Decrypt(string cipherText, int key)
        {

            //throw new NotImplementedException();


            int len = cipherText.Length;
            string originalStr = "";


            cipherText = cipherText.ToLower();
            for (int i = 0; i < len; i++)
            {
                int asciiVal = 0;
                //case of the char is not in boundries
                if (((int)cipherText[i] - key) < 'a')// ascii number of a which is the last alpabet
                {
                    asciiVal = ((int)cipherText[i] - key) + 26;

                }
                else
                {
                    asciiVal = (int)cipherText[i] - key;
                }

                originalStr += ((char)asciiVal);
                //originalStr.Append((char)(asciival))
            }


            return originalStr;

        }

        public int Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            cipherText = cipherText.ToLower();
            //we don’t need to check all chars we need just the first one
            int key = (int)plainText[0] - (int)cipherText[0];

            //a->97
            //c->99
            //key->99-97>2(ascii)->26-2>>key=24
            if (key >= 0)
            {
                return (26 - key) % 26;
            }
            else
            {
                return (-key);//-1*key 
            }


        }
    }
}
