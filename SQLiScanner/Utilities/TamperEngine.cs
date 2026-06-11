using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SQLiScanner.Utilities
{
    public static class TamperEngine
    {
        private static readonly string[] KeywordArray =
        {
            "SELECT", "UNION", "AND", "OR", "WHERE", "ORDER", "BY", "LIMIT", "FROM",
            "INSERT", "UPDATE", "DELETE", "HAVING", "GROUP", "CONCAT", "SLEEP", "CHAR"
        };

        // Chuyển đổi khoảng trắng thành comment /**/ ngoại trừ các khoảng trắng nằm trong chuỗi nháy đơn hoặc nháy kép
        public static string SpaceToComment(string input)
        {
            if (string.IsNullOrEmpty(input)) return input;

            int spaceCount = 0;
            for (int idx = 0; idx < input.Length; idx++)
            {
                if (input[idx] == ' ') spaceCount++;
            }

            if (spaceCount == 0) return input;
            // Biến đổi từ ' '(1 kí tự) thành /**/ (4 kí tự) -> tăng thêm 3 kí tự
            var stringBuilder = new StringBuilder(input.Length + (spaceCount * 3));

            bool inSingleQuote = false;
            bool inDoubleQuote = false;

            for (int i = 0; i < input.Length; i++)
            {
                char c = input[i];

                if (c == '\'' && !inDoubleQuote)
                {
                    inSingleQuote = !inSingleQuote;
                }
                else if (c == '"' && !inSingleQuote)
                {
                    inDoubleQuote = !inDoubleQuote;
                }

                if (c == ' ' && !inSingleQuote && !inDoubleQuote)
                {
                    stringBuilder.Append("/**/");
                }
                else
                {
                    stringBuilder.Append(c);
                }
            }
            return stringBuilder.ToString();
        }

        public static string RandomCase(string input)
        {
            if (string.IsNullOrEmpty(input)) return input;

            var stringBuilder = new StringBuilder(input.Length);
            var rand = new Random();

            ReadOnlySpan<char> inputSpan = input.AsSpan();
            int i = 0;

            while (i < inputSpan.Length)
            {
                if (char.IsLetter(inputSpan[i]))
                {
                    int start = i;
                    while (i < inputSpan.Length && (char.IsLetterOrDigit(inputSpan[i]) || inputSpan[i] == '_'))
                    {
                        i++;
                    }
                    int length = i - start;
                    ReadOnlySpan<char> wordSpan = inputSpan.Slice(start, length);

                    if (IsSqlKeyword(wordSpan))
                    {
                        for (int j = 0; j < length; j++)
                        {
                            char c = wordSpan[j];
                            stringBuilder.Append(rand.Next(2) == 0 ? char.ToUpper(c) : char.ToLower(c));
                        }
                    }
                    else
                    {
                        stringBuilder.Append(wordSpan);
                    }
                }
                else
                {
                    stringBuilder.Append(inputSpan[i]);
                    i++;
                }
            }

            return stringBuilder.ToString();
        }

        public static string ApplyTamper(string payload)
        {
            if (string.IsNullOrEmpty(payload)) return payload;

            string step1 = SpaceToComment(payload);
            string step2 = RandomCase(step1);

            return step2;
        }

        private static bool IsSqlKeyword(ReadOnlySpan<char> wordSpan)
        {
            for (int k = 0; k < KeywordArray.Length; k++)
            {
                if (wordSpan.Equals(KeywordArray[k], StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
            return false;
        }
    }
}
