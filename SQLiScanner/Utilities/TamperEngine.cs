using System.Text;

namespace SQLiScanner.Utilities
{
    public static class TamperEngine
    {
        private static readonly string[] KeywordArray =
        {
            // 1. Core SQL Keywords (Mệnh đề cốt lõi - Bị WAF soi 100%)
            "SELECT", "UNION", "AND", "OR", "WHERE", "ORDER", "BY", "LIMIT", "FROM",
            "INSERT", "UPDATE", "DELETE", "HAVING", "GROUP", "INTO", "AS", "DISTINCT",
            "JOIN", "ON", "CASE", "WHEN", "THEN", "ELSE", "END",

            // 2. Toán tử & Logic thường dùng trong Boolean-Based
            "LIKE", "IN", "NOT", "BETWEEN", "IS", "NULL", "EXISTS",

            // 3. MySQL Specific (Hàm Error-Based, Time-Based & Trích xuất)
            "CONCAT", "SLEEP", "CHAR", "EXTRACTVALUE", "UPDATEXML", "DATABASE", "VERSION",
            "BENCHMARK", "USER", "SYSTEM_USER", "GROUP_CONCAT", "MID", "SUBSTR", "SUBSTRING",

            // 4. MSSQL Specific (Hàm Error-Based, Time-Based & Ép kiểu)
            "CONVERT", "CAST", "DB_NAME", "WAITFOR", "DELAY", "ISNULL", "COALESCE", "@@VERSION",

            // 5. PostgreSQL Specific 
            "CURRENT_DATABASE", "CURRENT_USER", "PG_SLEEP", "CHR", "MAKE_SET",

            // 6. Oracle Specific (Các package mạng thường bị lạm dụng để lấy Error)
            "UTL_INADDR", "CTXSYS", "DRITHSV", "DBMS_LOCK", "ASCIISTR", "TO_CHAR", "TO_NUMBER",

            // 7. Information Schema (Từ khóa dùng để trích xuất cấu trúc bảng/cột)
            "INFORMATION_SCHEMA", "TABLES", "COLUMNS", "SCHEMATA", "TABLE_NAME", "COLUMN_NAME"
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

            ReadOnlySpan<char> inputSpan = input.AsSpan();
            bool inSingleQuote = false;
            bool inDoubleQuote = false;
            int i = 0;

            while (i < inputSpan.Length)
            {
                char c = inputSpan[i];

                if (c == '\'' && !inDoubleQuote)
                {
                    inSingleQuote = !inSingleQuote;
                    stringBuilder.Append(c);
                    i++;
                    continue;
                }

                if (c == '"' && !inSingleQuote)
                {
                    inDoubleQuote = !inDoubleQuote;
                    stringBuilder.Append(c);
                    i++;
                    continue;
                }

                if (inSingleQuote || inDoubleQuote)
                {
                    stringBuilder.Append(c);
                    i++;
                    continue;
                }

                if (char.IsLetter(c))
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
                            char wc = wordSpan[j];
                            stringBuilder.Append(j % 2 == 0 ? char.ToUpper(wc) : char.ToLower(wc));
                        }
                    }
                    else
                    {
                        stringBuilder.Append(wordSpan);
                    }
                }
                else
                {
                    stringBuilder.Append(c);
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
