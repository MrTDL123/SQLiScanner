using AngleSharp.Html.Parser;
using SQLiScanner.Models;
using SQLiScanner.Models.Enums;
using SQLiScanner.Services;
using SQLiScanner.Utilities;
using SQLiScanner.Utility;
using System.Net;
using System.Net.Http.Headers;
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
            CrawlResult target, string paramName, PayloadState currentState, CancellationToken cancellationToken)
        {
            string originalValue = target.Params.TryGetValue(paramName, out var bodyVal)
                ? bodyVal
                : (System.Web.HttpUtility.ParseQueryString(target.RawQueryString)[paramName] ?? "");

            var result = new HeuristicResult();

            try
            {
                InjectionRoute route = InjectionRoute.CreateStandard(paramName, originalValue);
                
                currentState.UpdateStatus(ScanStatus.HeuristicScanning, "Đang tải cấu trúc trang gốc (Baseline)...");
                var (baseHtml, baseBytes, baseStatus, _,baseHeaders) = await _requestService.RequestAsync(target, originalValue, route, cancellationToken);
                if (baseBytes == null)
                {
                    result.Status = "FAILED";
                    Logger.Warning("Không lấy được Baseline. Target có thể đã sập hoặc WAF chặn.");
                    currentState.UpdateStatus(ScanStatus.Error, "Lỗi: Không lấy được Baseline (WAF/Drop)");
                    return result;
                }

                currentState.UpdateStatus(ScanStatus.HeuristicScanning, "Đang tự động đo đạc độ nhiễu nền trang (Calibration)...");
                var (baseHtml2, baseBytes2, baseStatus2, _, _) = await _requestService.RequestAsync(target, originalValue, route, cancellationToken);

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
                        Logger.Warning($"[!] Cảnh báo: Trang web rất hỗn loạn! Độ nhiễu nền đo được: {(backgroundNoise * 100):F1}%. Ngưỡng dung sai động được nâng lên: {(target.PageTolerance * 100):F1}%");
                    }
                    else
                    {
                        Logger.Info($"[*] Đo đạc độ nhiễu trang thành công: {(backgroundNoise * 100):F2}%. Ngưỡng dung sai động được thiết lập: {(target.PageTolerance * 100):F2}%");
                    }
                }
                else
                {
                    target.PageTolerance = 0.05;
                }

                currentState.UpdateStatus(ScanStatus.HeuristicScanning, "Đang dò cookie thụ động...");
                var passiveCookies = MinePassiveCookie(baseHtml, baseHeaders);

                currentState.UpdateStatus(ScanStatus.HeuristicScanning, "Đang dò cookie bằng Fuzzing...");
                var activeCookies = await MineActiveCookiesAsync(target, baseHtml, originalValue, baseStatus, baseBytes.Length, cancellationToken);

                // Gộp danh sách Cookie từ 2 lần dò trên
                var minedCookies = new HashSet<string>(passiveCookies, StringComparer.OrdinalIgnoreCase);
                minedCookies.UnionWith(activeCookies);

                if (minedCookies.Count > 0)
                {
                    currentState.UpdateStatus(ScanStatus.HeuristicScanning, $"Tìm thấy {minedCookies.Count} Cookies hoạt động: {string.Join(", ", minedCookies)}");
                }

                currentState.UpdateStatus(ScanStatus.HeuristicScanning, $"Đang chạy Cookie Aliasing cho [{paramName}]...");
                route = await CheckCookieAliasingAsync(target, paramName, minedCookies, cancellationToken);

                result.Route = route;

                string canary = ReflectionDetector.GenerateCanaryToken();

                currentState.UpdateStatus(ScanStatus.HeuristicScanning, $"Kiểm tra XSS: Gửi token {canary}");
                var (canaryHtml, canaryBytes, _, _, _) = await _requestService.RequestAsync(target, canary, route, cancellationToken);

                if (canaryBytes != null)
                {
                    if (ReflectionDetector.IsPayloadReflected(canaryHtml, canary))
                    {
                        result.IsReflected = true;
                        result.CanaryToken = canary;
                        Logger.Warning($"[!] Phát hiện tham số [{paramName}] bị rò rỉ dữ liệu (XSS/Reflected). Kích hoạt bộ lọc chống nhiễu DOM.");
                        currentState.UpdateStatus(ScanStatus.HeuristicScanning, "XSS/Reflected: Phát hiện rò rỉ đầu vào");
                    }
                }

                if (result.IsCookiePriority)
                {
                    Logger.Success($"ĐỊNH TUYẾN MỚI: Server ưu tiên Cookie cho [{paramName}]. Kích hoạt định tuyến Payload vào Header!");
                }
                else
                {
                    Logger.Info($"[-] Định tuyến bình thường: Sử dụng tham số URL/Form để truyền Payload.");
                }

                Logger.Phase($"XÁC ĐỊNH NGỮ CẢNH CỦA {target.BaseUrl} (Tham số: {paramName})");
                currentState.UpdateStatus(ScanStatus.HeuristicScanning, $"Đang phân tích bối cảnh: {paramName}");
                // PHASE 1: Kiểm tra ngữ cảnh là INTEGER
                Logger.Info("Kiểm tra ngữ cảnh integer...");
                currentState.UpdateStatus(ScanStatus.HeuristicScanning, "Heuristic: Kiểm tra bối cảnh số nguyên (Integer)...");
                await Phase1_DetectIntegerContextAsync(target, result, currentState, route, cancellationToken);

                if (result.DetectedType != "INTEGER")
                {
                    // PHASE 2: Kiểm tra liệu ngữ cảnh có phải là string-like
                    Logger.Phase("[PHASE 2] KIỂM TRA NGỮ CẢNH STRING THÔNG QUA ERROR-BASED");
                    currentState.UpdateStatus(ScanStatus.HeuristicScanning, "Heuristic: Kiểm tra bối cảnh chuỗi (String/LIKE)...");
                    await Phase2_DetectStringContextAsync(
                        target, baseStatus, baseBytes.Length, baseHtml, 
                        result, currentState,
                        route, cancellationToken
                    );
                }


                if (result.ApplicableBoundaries.Count > 0)
                {
                    // PHASE 3: Xác định ngữ cảnh
                    Logger.Phase("[PHASE 3] XÁC ĐỊNH CHÍNH XÁC BOUNDARY");
                    currentState.UpdateStatus(ScanStatus.HeuristicScanning, "Heuristic: Đang dò tìm và khóa Boundary...");
                    await Phase3_VerifyBoundaryAsync(
                        target, baseStatus, baseBytes.Length, baseHtml, 
                        result, currentState,
                        route, cancellationToken
                    );
                }

                if (!result.IsReadyForDetection)
                {
                    Logger.Warning($"Không tìm được boundary bằng Heuritic. Buộc load hết toàn bộ boundaries và Payload");
                    currentState.UpdateStatus(ScanStatus.HeuristicDone, $"Không tìm được ngữ cảnh thích hợp, load toàn bộ boundary và payload");
                    result.Status = "UNCERTAIN";
                    result.ApplicableBoundaries = await GetAllApplicableBoundaries();
                    await LoadApplicablePayloadsAsync(result);
                }

                return result;
            }
            catch (Exception ex)
            {
                // Nếu xảy ra lỗi thì load toàn bộ boundary và payload
                Logger.Error($"Lỗi nghiêm trọng tại ContextAnalyzer: {ex.Message}");
                result.Status = "FAILED";

                result.ApplicableBoundaries = await GetAllApplicableBoundaries();
                await LoadApplicablePayloadsAsync(result);
                return result;
            }
        }

        private async Task<List<Boundary>> GetBoundariesByPType(int ptype)
        {
            Logger.Process($"Load các boundary với ptype = {ptype}");

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

        public async Task<List<PayloadType>> LoadApplicablePayloads(int stype = 0)
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
        private async Task Phase1_DetectIntegerContextAsync(
            CrawlResult target, HeuristicResult result, PayloadState currentState,
            InjectionRoute route, CancellationToken cancellationToken = default)
        {
            Logger.Info("KỲ VỌNG: Các tham số với payload là các toán tử, nếu như tham số là INTEGER thì các phép toán này sẽ hoạt động.");
            // Lấy base response
            Logger.Process("Kiểm tra tham số với giá trị = 1");
            currentState.UpdateStatus(ScanStatus.HeuristicScanning, "Integer Check: Gửi request với tham số = 1...");
            var (baselineHtml, baselineBytes, baselineStatus, _, _) =
                await _requestService.RequestAsync(target, INT_PAYLOAD_1, route, cancellationToken);
            if (baselineBytes == null)
            {
                result.DetectedType = "UNKNOWN";
                result.ConfidenceScore = 0;
                return;
            }

            Logger.Response(baselineStatus, baselineBytes.Length);
            int baselineLength = baselineBytes.Length;

            // Test payloa False
            Logger.Process("Kiểm tra tham số với giá trị = 1-1");
            currentState.UpdateStatus(ScanStatus.HeuristicScanning, "Integer Check: Gửi biểu thức toán học [1-1]...");
            var (falseHtml, falseBytes, falseStatus, _, _) =
                await _requestService.RequestAsync(target, INT_PAYLOAD_2, route, cancellationToken);

            if (falseBytes == null)
            {
                result.DetectedType = "UNKNOWN";
                result.ConfidenceScore = 0;
                Logger.Warning("Không nhận được phản hồi từ đối tượng. Kiểm tra Phase 1 thất bại!");
                return;
            }
            Logger.Response(falseStatus, falseBytes.Length);


            // Test payload 3
            Logger.Process("Kiểm tra tham số với giá trị = 2-1");
            currentState.UpdateStatus(ScanStatus.HeuristicScanning, "Integer Check: Gửi biểu thức toán học [2-1]...");
            var (trueHtml, trueBytes, trueStatus, _, _) =
                await _requestService.RequestAsync(target, INT_PAYLOAD_3, route, cancellationToken);
            if (trueBytes == null)
            {
                result.DetectedType = "UNKNOWN";
                result.ConfidenceScore = 0;
                return;
            }

            Logger.Response(trueStatus, trueBytes.Length);

            Logger.Info("Đang mong chờ phản hồi có payload (2-1) sẽ giống (1) và ngược lại đối với (1-1) sẽ không giống (1)");
            // Nếu cả base và payload 2 và 3 đều giống nhau thì tham số là Integer
            double similarityPayloadFalse = CalculateSimilarity(
                baselineStatus, baselineLength, baselineHtml,
                falseStatus, falseBytes.Length, falseHtml,
                target.PageTolerance);
            Logger.Info($"Payload (1-1) giống {(similarityPayloadFalse * 100):F1}% so với Payload (1)");

            double similarityPayloadTrue = CalculateSimilarity(
                baselineStatus, baselineLength, baselineHtml,
                trueStatus, trueBytes.Length, trueHtml,
                target.PageTolerance
            );
            Logger.Info($"Payload (2-1) giống {similarityPayloadFalse * 100}% so với Payload (1)");

            result.Similarity = Math.Max(similarityPayloadFalse, similarityPayloadTrue);

            // Ngưỡng mức chấp nhận cho Integer (> 95% -> Integer)
            double INTEGER_THRESHOLD = 1.0 - target.PageTolerance;
            Logger.Process($"Đặt ngưỡng mức trùng nhau là {INTEGER_THRESHOLD * 100}%, sai số {((1.0 - INTEGER_THRESHOLD) * 100):F1}%");
            // Nếu payload 2 - 1 (giống base = 1) trả về như base thì chắc chắn server thực hiện phép trừ và có thể kết luận ngữ cảnh là Integer
            if (similarityPayloadTrue > INTEGER_THRESHOLD && similarityPayloadFalse < INTEGER_THRESHOLD)
            {
                Logger.Success("Phát hiện payload (2-1) trùng với payload (1) như dự đoán.");
                Logger.Success($"THÀNH CÔNG PHÁT HIỆN: INTEGER (ĐIỂM: {result.ConfidenceScore}%)");
                Logger.Info("Cần phải trải qua PHASE 3 để xác định BOUNDARY CHÍNH XÁC.");
                currentState.UpdateStatus(ScanStatus.HeuristicScanning, "Phát hiện mục tiêu nằm trong ngữ cảnh Integer");
                result.DetectedType = "INTEGER";
                result.ConfidenceScore = (int)Math.Min(100, (result.Similarity * 100));
                result.ApplicableBoundaries = await GetBoundariesByPType(1);
                return;
            }

            result.DetectedType = "UNCERTAIN";
            result.ConfidenceScore = 0;

            Logger.Warning($"Payload True (2-1) và Payload False (1-1) đều không ra như kết quả dự đoán.");
            Logger.Warning("Không thể là INTEGER - Chuyển sang kiểm tra ngữ cảnh STRING-LIKE ở Phase 2");
            currentState.UpdateStatus(ScanStatus.HeuristicScanning, "Mục tiêu không nằm trong ngữ cảnh Integer");
            return;
        }

        private async Task Phase2_DetectStringContextAsync(
            CrawlResult target,
            int baselineStatus, int baselineLength, string baselineHtml,
            HeuristicResult result, PayloadState currentState,
            InjectionRoute route, CancellationToken cancellationToken = default)
        {
            Logger.Info("KỲ VỌNG: Cố tình chèn các Prefix gây lỗi, nếu như đúng là ngữ cảnh STRING thì sẽ báo về lỗi");
            double STRING_LIKE_THRESHOLD = 1.0 - target.PageTolerance;
            Logger.Process($"Đặt ngưỡng mức trùng nhau là {STRING_LIKE_THRESHOLD * 100}%, sai số {((1.0 - STRING_LIKE_THRESHOLD) * 100):F1}%");
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
                Logger.Process($"Chèn payload [{payload}]");
                currentState.UpdateStatus(ScanStatus.HeuristicScanning, $"String Check: Gửi payload [{payload}] gây lỗi không...");
                var (testHtml, testBytes, testStatus, _, _) =
                    await _requestService.RequestAsync(target, payload, route, cancellationToken);

                if (testBytes == null)
                {
                    Logger.Skipped("Không nhận được phản hồi từ đối tượng. Chuyển sang Payload khác!");
                    continue;
                }
                Logger.Response(testStatus, testBytes.Length);


                double similarity = CalculateSimilarity(
                    baselineStatus, baselineLength, baselineHtml,
                    testStatus, testBytes.Length, testHtml,
                    target.PageTolerance
                );
                Logger.Info($"Payload [{payload}] giống {similarity * 100}% so request nguyên bản");

                if (similarity < STRING_LIKE_THRESHOLD)
                {
                    result.DetectedType = "STRING_LIKE";
                    result.ConfidenceScore = (int)((1.0 - similarity) * 100);
                    result.Similarity = similarity * 100;
                    result.ApplicableBoundaries = await GetAllStringLikeBoundaries();

                    Logger.Success($"PHÁT HIỆN PAYLOAD [{payload}] GÂY LỖI, CHẮC CHẮN LÀ STRING-LIKE - ĐIỂM: {result.ConfidenceScore}%");
                    currentState.UpdateStatus(ScanStatus.HeuristicScanning, $"Phát hiện payload [{payload}] gây lỗi. Mục tiêu nằm trong ngữ cảnh STRING");
                    return;
                }
            }

            result.DetectedType = "UNCERTAIN";
            result.ConfidenceScore = 0;
            result.Similarity = 100;
            result.ApplicableBoundaries = await GetAllApplicableBoundaries();

            Logger.Warning("Không tìm thấy dấu hiệu là string - Cần phải kiểm tra toàn bộ boundary ở Phase 3");
            currentState.UpdateStatus(ScanStatus.HeuristicScanning, "Mục tiêu không nằm trong ngữ cảnh STRING");
            return;
        }

        private async Task Phase3_VerifyBoundaryAsync(
            CrawlResult target,
            int baselineStatus, int baselineLength, string baselineHtml,
            HeuristicResult result, PayloadState currentState,
            InjectionRoute route, CancellationToken cancellationToken = default)
        {
            Logger.Info("KỲ VỌNG: Xác định chính xác boundary thông qua thử từng boundary bằng BOOLEAN LOGIC.");
            Logger.Info("Sử dụng 2 payload True (8341=8341) và False (8341=8342) để kiểm tra");
            currentState.UpdateStatus(ScanStatus.HeuristicScanning, $"Boundary Check: Kiểm tra từng Boundary bằng Boolean Logic...");

            double SIMILARITY_THRESHOLD = 1.0 - target.PageTolerance;

            foreach (var boundary in result.ApplicableBoundaries)
            {
                Logger.Process($"Sử dụng Boundary: {boundary}");
                string trueCondition = "8341=8341";
                string falseCondition = "8341=8342";

                Logger.Process($"Thiết lặp True Payload (Prefix: [{boundary.Prefix}] | Suffix: [{boundary.Suffix}])");
                string truePayload = $"{route.OriginalValue}{boundary.Prefix} AND {trueCondition} {boundary.Suffix} ";
                Logger.Process($"Thiết lặp False Payload (Prefix: [{boundary.Prefix}] | Suffix: [{boundary.Suffix}])");
                string falsePayload = $"{route.OriginalValue}{boundary.Prefix} AND {falseCondition} {boundary.Suffix} ";

                // TEST FALSE PAYLOAD (Kỳ vọng: Khác Base)
                Logger.Process("Gửi False Payload...");
                var (htmlFalse, bytesFalse, statusFalse, _, _) = await _requestService.RequestAsync(target, falsePayload, route, cancellationToken);
                if (bytesFalse == null)
                {
                    Logger.Warning("Không nhận được phản hồi từ đối tượng. Chuyển sang boundary tiếp theo!");
                    continue;
                }

                Logger.Response(statusFalse, bytesFalse.Length);

                double simFalse = CalculateSimilarity(
                    baselineStatus, baselineLength, baselineHtml,
                    statusFalse, bytesFalse.Length, htmlFalse,
                    target.PageTolerance);
                Logger.Info($"Payload False giống {(simFalse * 100):F1}% so request nguyên bản");

                // TEST TRUE PAYLOAD (Kỳ vọng: Giống Base)
                Logger.Process("Gửi True Payload...");
                var (htmlTrue, bytesTrue, statusTrue, _, _) = await _requestService.RequestAsync(target, truePayload, route, cancellationToken);
                if (bytesTrue == null)
                {
                    Logger.Warning("Không nhận được phản hồi từ đối tượng. Chuyển sang boundary tiếp theo!");
                    continue;
                }
                Logger.Response(statusTrue, bytesTrue.Length);


                double simTrue = CalculateSimilarity(
                    baselineStatus, baselineLength, baselineHtml,
                    statusTrue, bytesTrue.Length, htmlTrue,
                    target.PageTolerance);
                Logger.Info($"Payload True giống {simTrue * 100}% so request nguyên bản");

                // Kịch bản 1: True giống Base, False khác Base
                bool isRegularMatch = simTrue >= SIMILARITY_THRESHOLD && simFalse < SIMILARITY_THRESHOLD;
                if (isRegularMatch) Logger.Success("Phát hiện: True giống Base, False khác Base (Đúng như dự đoán)");

                // Kịch bản 2: False giống Base, True khác Base (Trường hợp Bypass / Original Value là sai)
                bool isInverseMatch = simFalse >= SIMILARITY_THRESHOLD && simTrue < SIMILARITY_THRESHOLD;
                if (isInverseMatch) Logger.Success("Phát hiện: False giống Base, True khác Base (Trường hợp Bypass / Original Value là sai)");

                // Bổ sung: Đảm bảo độ chênh lệch giữa True và False phải đủ lớn (ví dụ > 5%) để tránh nhiễu
                bool hasSignificantDifference = Math.Abs(simTrue - simFalse) >= 0.05;

                if ((isRegularMatch || isInverseMatch) && hasSignificantDifference)
                {
                    Logger.Success($"✓ Boundary Worked: {boundary.ContextName}");
                    currentState.UpdateStatus(ScanStatus.HeuristicDone, $"Phát hiện mục tiêu nằm trong boudanry {boundary.ContextName}");
                    result.LockedBoundary = boundary;
                    result.ApplicableBoundaries.Clear();
                    result.ApplicableBoundaries.Add(boundary);
                    result.Status = "SUCCESS";

                    // Load payloads
                    await LoadApplicablePayloadsAsync(result);
                    return;
                }

                Logger.Warning($"Boundary {boundary} không có tác dụng.");

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

                // Sort: Level (easy → hard) then Risk (low → high)
                result.ApplicablePayloads = allPayloads
                    .OrderBy(p => p.Level)
                    .ThenBy(p => p.Risk)
                    .ToList();

                Logger.Info($"Loaded {result.ApplicablePayloads.Count} payloads từ XML");
            }
            catch (Exception ex)
            {
                Logger.Warning($"Lỗi load payloads: {ex.Message}");
            }
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
                    Logger.Info($"[Active Miner] Phát hiện Hidden Cookie: [{word}] (Similarity: {similarity * 100:F1}%, Reflected: {isReflected})");
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
                Logger.Info($"[Cookie Aliasing] Tham số [{paramName}] không làm thay đổi trạng thái giao diện. Bỏ qua phân định.");
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
                    Logger.Success($"[WAF Bypass] Server ưu tiên đọc Cookie [{cookieName}] thay vì tham số [{paramName}]!");
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
