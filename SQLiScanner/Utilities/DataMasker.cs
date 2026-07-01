using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SQLiScanner.Utilities
{
    public static class DataMasker
    {
        private static bool IsFormatChar(char c)
        {
            return c == ' ' ||
                   c == '@' ||
                   c == '.' ||
                   c == '-' ||
                   c == '_' ||
                   c == '(' ||
                   c == ')';
        }

        public static string Mask(string rawData, bool isVersionQuery = false)
        {
            if (string.IsNullOrEmpty(rawData))
            {
                return rawData;
            }

            int length = rawData.Length;

            if (length <= 256)
            {
                Span<char> resultSpan = stackalloc char[length];
                MaskInternal(rawData, resultSpan, isVersionQuery);
                return new string(resultSpan);
            }
            else
            {
                char[] resultArray = new char[length];
                MaskInternal(rawData, resultArray, isVersionQuery);
                return new string(resultArray);
            }

        }

        private static void MaskInternal(string rawData, Span<char> resultSpan, bool isVersionQuery)
        {
            int length = rawData.Length;
            for (int i = 0; i < length; i++)
            {
                char c = rawData[i];
                if (IsFormatChar(c))
                {
                    resultSpan[i] = c;
                    continue;
                }

                // Ngoại lệ cho dữ liệu Phiên bản (Giữ nguyên 18 ký tự đầu)
                if (isVersionQuery)
                {
                    if (i < 18)
                    {
                        resultSpan[i] = c;
                    }
                    else
                    {
                        resultSpan[i] = '*';
                    }
                }
                else
                {
                    if (length <= 3)
                    {
                        // Giữ duy nhất 1 ký tự đầu
                        if (i == 0)
                        {
                            resultSpan[i] = c;
                        }
                        else
                        {
                            resultSpan[i] = '*';
                        }
                    }
                    else if (length <= 10)
                    {
                        // Giữ 2 ký tự đầu và 1 ký tự cuối
                        if (i < 2 || i == length - 1)
                        {
                            resultSpan[i] = c;
                        }
                        else
                        {
                            resultSpan[i] = '*';
                        }
                    }
                    else
                    {
                        // Giữ 3 ký tự đầu và 2 ký tự cuối
                        if (i < 3 || i >= length - 2)
                        {
                            resultSpan[i] = c;
                        }
                        else
                        {
                            resultSpan[i] = '*';
                        }
                    }
                }
            }
        }
    }
}
