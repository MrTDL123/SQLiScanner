using SQLiScanner.Models;
using SQLiScanner.Models.Enums;
using SQLiScanner.Utility;
using System;
using System.Collections.Generic;
using System.Data;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Diagnostics;
using AngleSharp;
using AngleSharp.Dom;
using AngleSharp.Html.Parser;
using AngleSharp.Text;
using SQLiScanner.DTOs;
using System.Diagnostics.CodeAnalysis;
using SQLiScanner.Services;

namespace SQLiScanner.Modules
{
    public enum SimilarityResult
    {
        Similar,   // Giống nhau (> 95%) 
        Different, // Khác biệt rõ ràng (< 80%)
        GreyZone   // Vùng xám (80% - 95%) -> Cần AI thẩm định
    }

    public class DatabaseDetector
    {
        private readonly HttpClient _client;
        private readonly IAiApiClient _aiApiClient;
        private readonly ContextAnalyzer _contextAnalyzer;
        public DatabaseDetector(HttpClient client, ContextAnalyzer contextAnalyzer, IAiApiClient aiApiClient)
        {
            _client = client;
            _contextAnalyzer = contextAnalyzer;
            _aiApiClient = aiApiClient;
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
                Logger.Info($"THAM SỐ ĐƯỢC SỬ DỤNG ĐỂ TẤN CÔNG: {paramName}");
                // Kiểm tra ngữ cảnh
                HeuristicResult heuristicResult = await _contextAnalyzer.PerformHeuristicScanAsync(target, paramName);
                if (!heuristicResult.IsReadyForDetection) // Đảm bảo đã đầy đủ Boudary và Payload để test
                {
                    Logger.Warning($"Bỏ qua tham số [{paramName}] vì không khóa được Boundary hợp lệ.");
                    continue;
                }

                foreach (var boundary in heuristicResult.ApplicableBoundaries)
                {
                    string prefix = boundary.Prefix;
                    string suffix = boundary.Suffix;
                    Logger.Info($"\nXét Boundary: Prefix [{prefix}] | Suffix [{suffix}]");

                    var errorPayloads = heuristicResult.ApplicablePayloads.Where(p => p.SType == 2).ToList();
                    if (errorPayloads.Any()) // Error-Based
                    {
                        Logger.Phase($"TÌM KIẾM BẰNG ERROR-BASED VỚI PREFIX [{prefix}]");
                        foreach (var payload in errorPayloads)
                        {
                            var dbType = await TestErrorBasedPayload(
                                target, paramName, originalValue,
                                prefix, suffix, payload
                            );

                            if (dbType != DatabaseType.Unknow)
                            {
                                DetectionResult result = new DetectionResult
                                {
                                    VulnerableURL = target.FullUrl,
                                    FoundContext = "ERROR-BASED",
                                    DatabaseType = dbType,
                                    VulnerableParam = paramName,
                                    WorkingPrefix = prefix,
                                    WorkingSuffix = suffix
                                };

                                Logger.Success($"PHÁT HIỆN {dbType} THÔNG QUA THÔNG BÁO LỖI!");
                                Logger.Result(result);
                                return result;
                            }
                        }

                        Logger.Warning("Không thể sử dụng Error-Based để xác định Database!");
                    }

                    // --- GIAI ĐOẠN 2: TÌM KIẾM BOOLEAN-BASED (SType == 1) ---
                    var booleanPayloads = heuristicResult.ApplicablePayloads.Where(p => p.SType == 1).ToList();
                    if (booleanPayloads.Any()) //Boolean-Based
                    {
                        Logger.Phase($"TÌM KIẾM BẰNG BOOLEAN-BASED VỚI PREFIX [{prefix}]");

                        // Thử với từng loại DB để xem cái nào trả về True (Length không đổi)
                        foreach (var payload in booleanPayloads)
                        {
                            var dbType = await TestBooleanBasedPayload(
                                    target, paramName, originalValue,
                                    prefix, suffix, payload);

                            if (dbType != DatabaseType.Unknow)
                            {
                                DetectionResult result = new DetectionResult
                                {
                                    VulnerableURL = target.FullUrl,
                                    FoundContext = "BOOLEAN-BASED",
                                    DatabaseType = dbType,
                                    VulnerableParam = paramName,
                                    WorkingPrefix = prefix,
                                    WorkingSuffix = suffix
                                };

                                Logger.Success($"PHÁT HIỆN {dbType} THÔNG QUA Boolean-Based!");
                                Logger.Result(result);
                                return result;
                            }
                        }

                        Logger.Warning("Không thể sử dụng Boolean-Based để xác định Database!");
                    }

                    // --- GIAI ĐOẠN 3: TÌM KIẾM TIME-BASED (SType == 5) ---
                    var timePayloads = heuristicResult.ApplicablePayloads.Where(p => p.SType == 5).ToList();
                    if (timePayloads.Any())  // Time-based
                    {
                        Logger.Phase($"TÌM KIẾM TIME-BASED VỚI PREFIX [{prefix}]");
                        foreach (var payload in timePayloads)
                        {
                            var dbType = await TestTimeBasedPayloadAsync(
                                target, paramName, originalValue,
                                prefix, suffix, payload);
                            if (dbType != DatabaseType.Unknow)
                            {
                                DetectionResult result = new DetectionResult
                                {
                                    VulnerableURL = target.FullUrl,
                                    FoundContext = "TIME-BASED",
                                    DatabaseType = dbType,
                                    VulnerableParam = paramName,
                                    WorkingPrefix = prefix,
                                    WorkingSuffix = suffix
                                };
                                Logger.Success($"PHÁT HIỆN {dbType} THÔNG QUA TIME-BASED BLIND (Độ trễ thời gian)!");
                                Logger.Result(result);
                                return result; // Tìm thấy thì thoát luôn
                            }
                        }
                        Logger.Warning("Không thể sử dụng Time-Based để xác định Database!");
                    }
                }
            }

            Logger.Skipped("Không tìm thấy được lỗ hổng SQLi trong tất cả các Entry points!");
            return new DetectionResult { DatabaseType = DatabaseType.Unknow };
        }

        #region Các hàm phụ trợ
        private async Task<(bool isSuccess, long elapsedMs, int statusCode)> SendRequestWithTimingAsync(
            CrawlResult target, string paramName, string payloadValue)
        {
            var sw = new Stopwatch();
            try
            {
                sw.Start();
                var (_, _, statusCode) = await SendRequestAsync(target, paramName, payloadValue);
                sw.Stop();

                return (true, sw.ElapsedMilliseconds, statusCode);
            }
            catch (TaskCanceledException)
            {
                // LỖI TIMEOUT: Nếu HttpClient bị quá hạn thời gian chờ (Timeout)
                // Điều này THƯỜNG XẢY RA khi lệnh SLEEP() hoạt động tốt và giữ kết nối quá lâu
                sw.Stop();
                return (false, sw.ElapsedMilliseconds, 0);
            }
            catch (Exception)
            {
                sw.Stop();
                return (false, sw.ElapsedMilliseconds, 0);
            }
        }
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
                var encoding = charset is not null ? Encoding.GetEncoding(charset) : Encoding.UTF8;

                return (encoding.GetString(bytes), bytes, (int)response.StatusCode);
            }
            catch (Exception ex)
            {
                Logger.Error($"Gửi Request thất bại: {ex.Message}");
                return (null, null, 0);
            }
        }

        private async Task<DatabaseType> TestErrorBasedPayload(
            CrawlResult target,
            string paramName,
            string originalValue,
            string prefix,
            string suffix,
            PayloadTest payloads
        )
        {
            Logger.Info($"Kiểm tra Error-based với payload dành cho {payloads.DBMS}");
            foreach (string payload in payloads.Payloads)
            {
                string injectedPayload = $"{originalValue}{prefix} {payload} {suffix} ";
                var (html, _, _) = await SendRequestAsync(target, paramName, injectedPayload);

                if (string.IsNullOrEmpty(html))
                    return DatabaseType.Unknow;

                if (!string.IsNullOrEmpty(payloads.ErrorResponsePattern))
                {
                    try
                    {
                        Match match = Regex.Match(html, payloads.ErrorResponsePattern, RegexOptions.IgnoreCase | RegexOptions.Singleline);
                        if (match.Success)
                        {
                            string extractedData = match.Groups["result"].Value;
                            Logger.Success($"[+] Error-Based thành công! Đã trích xuất được: {extractedData}");

                            return GetDbTypeFromString(payloads.DBMS);
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.Warning($"Lỗi phân tích Regex Error-Based: {ex.Message}");
                    }
                }
            }
            return DatabaseType.Unknow;
        }

        private async Task<DatabaseType> TestBooleanBasedPayload(
            CrawlResult target,
            string paramName,
            string originalValue,
            string prefix,
            string suffix,
            PayloadTest payloads)
        {
            Logger.Info($"Testing Boolean-based: {payloads.DBMS}");

            foreach (var payload in payloads.Payloads)
            {
                // CHUẨN BỊ PAYLOAD
                string fullPayloadTrue = $"{originalValue}{prefix} {payload} {suffix} ";

                string falsePayload = payload.Replace("=", "!=").Replace(">", "<");
                string fullPayloadFalse = $"{originalValue}{prefix} {falsePayload} {suffix} ";

                Logger.Process($"[>] TRUE PayLoad {fullPayloadTrue}");
                (string? htmlTrue, byte[]? bytesTrue, int statusTrue) = await SendRequestAsync(target, paramName, fullPayloadTrue);
                if (bytesTrue == null)
                {
                    Logger.Warning("Mất kết nối hoặc bị WAF chặn. Bỏ qua.");
                    continue;
                }
                Logger.Response(statusTrue, bytesTrue.Length);

                Logger.Process($"[>] FALSE Payload {fullPayloadFalse}");
                (string? htmlFalse, byte[]? bytesFalse, int statusFalse) = await SendRequestAsync(target, paramName, fullPayloadFalse);

                if (bytesFalse == null)
                {
                    Logger.Warning("Mất kết nối hoặc bị WAF chặn. Bỏ qua.");
                    continue;
                }
                Logger.Response(statusFalse, bytesFalse.Length);

                // ĐẢM BẢO 2 PHẢN HỒI TỪ PAYLOAD KHÔNG GIỐNG NHAU          
                if (statusTrue != statusFalse)
                {
                    Logger.Success($"Phát hiện khác biệt Status Code: True({statusTrue}) != False({statusFalse})");
                    return GetDbTypeFromString(payloads.DBMS);
                }

                string textTrue = ExtractPlainText(htmlTrue!);
                string textFalse = ExtractPlainText(htmlFalse!);

                var similarityState = EvaluateSimilarity(textTrue, textFalse, bytesTrue.Length, bytesFalse.Length, 0.05, 0.20);
                if (similarityState == SimilarityResult.Similar)
                {
                    Logger.Warning($"Phát hiện sự trùng nhau ở dung lượng cả 2. True({bytesTrue.Length}) ~ False({bytesFalse.Length})");
                    continue;
                }

                //BÁO CÁO PHÁT HIỆN TRƯỜNG HỢP ĐẶC BIỆT KHI MÃ PHẢN HỒI CẢ 2 GIỐNG NHAU NHƯNG DUNG LƯỢNG CẢ 2 LẠI KHÁC.
                if (similarityState == SimilarityResult.GreyZone)
                {
                    Logger.Process("Phát hiện vùng xám. Đang kích hoạt AI để thẩm định ngữ cảnh");

                    string diffText = ExtractDiffText(textTrue, textFalse);
                    AiContextRequestPayload? conTextForAI = await GetContextForAI(htmlTrue!, htmlFalse!, diffText, target.FullUrl);
                    if (conTextForAI == null)
                    {
                        continue;
                    }

                    AiContextResponse response = await _aiApiClient.AnalyzeSqlInjectionAsync(conTextForAI);
                    if (!response.IsVulnerable)
                    {
                        Logger.Warning("AI thẩm định: Đây là dương tính giả (False Positive) do thay đổi nội dung động. Bỏ qua.");
                        continue;
                    }

                    Logger.Success("AI thẩm định: XÁC NHẬN đây là thay đổi do SQL Injection!");
                    Logger.Success($"Nguyên nhân: {response.Reason}");
                }

                Logger.Process("Đang xác định kịch bản phát hiện...");
                (string? htmlBase, byte[]? bytesBase, _) =
                    await SendRequestAsync(target, paramName, originalValue);

                if (bytesBase == null)
                {
                    Logger.Warning("Không lấy được Base Request. Vẫn ghi nhận lỗi SQLi.");
                    return GetDbTypeFromString(payloads.DBMS);

                }
                string textBase = ExtractPlainText(htmlBase!);

                // So sánh Base với True
                var baseVsTrue = EvaluateSimilarity(textBase, textTrue, bytesBase.Length, bytesTrue.Length, 0.05, 0.20);
                // So sánh Base với False
                var baseVsFalse = EvaluateSimilarity(textBase, textFalse, bytesBase.Length, bytesFalse.Length, 0.05, 0.20);

                // Vì đã qua phễu lọc mà vẫn chưa nhận định được vùng xám nên cứ mặc định là giống nhau
                if (baseVsTrue == SimilarityResult.Similar || baseVsTrue == SimilarityResult.GreyZone)
                {
                    Logger.Success("Kịch bản phát hiện: Base giống True, nhưng khác False.");
                }
                else if (baseVsFalse == SimilarityResult.Similar || baseVsFalse == SimilarityResult.GreyZone)
                {
                    Logger.Success("Kịch bản phát hiện (Bypass/Login): Base giống False, nhưng True lại ra kết quả mới.");
                }
                else
                {
                    Logger.Success("Kịch bản phát hiện: Cả True và False đều làm thay đổi trang web so với Base.");
                }
                return GetDbTypeFromString(payloads.DBMS);
            }

            return DatabaseType.Unknow;
        }

        private async Task<DatabaseType> TestTimeBasedPayloadAsync(
            CrawlResult target,
            string paramName,
            string originalValue,
            string prefix,
            string suffix,
            PayloadTest payloads)
        {
            int sleepSeconds = 5; // Mặc định thời gian ngủ là 5 giây
            long sleepMilliseconds = sleepSeconds * 1000;

            foreach (var payload in payloads.Payloads)
            {
                Logger.Info($"\nSử dụng Payload: {payload}");
                string payloadStr = payload.Replace("[SLEEPTIME]", sleepSeconds.ToString());
                string fullPayload = $"{originalValue}{prefix} AND {payloadStr} {suffix} ";
                Logger.Process($"[TIME-BASED] Kiểm tra thời gian phản hồi trung bình từ đối tượng...");

                // 1. LẤY BASELINE (3 MẪU ĐỂ LẤY TRUNG BÌNH & MAX)
                List<long> baselineDelays = new List<long>();
                for (int i = 0; i < 3; i++)
                {
                    Logger.Process($"Kiểm tra lần {i}");
                    var (success, ms, status) = await SendRequestWithTimingAsync(target, paramName, originalValue);
                    Logger.Response(status, null, $"Thời gian phản hồi: {ms}ms");
                    if (success) baselineDelays.Add(ms);
                }

                if (baselineDelays.Count == 0) return DatabaseType.Unknow; // Mất mạng
                long maxBaseline = baselineDelays.Max();
                Logger.Info($"Thời gian phản hồi chậm nhất trong 3 lần đo: {maxBaseline}ms");
                long avgBaseline = (long)baselineDelays.Average();
                Logger.Info($"Thời gian phản hồi trung bình trong 3 lần đo: {avgBaseline}ms");
                // Nếu mạng quá lag (Baseline bình thường mà mất tới > 3-4 giây), thì không thể test Time-based (rất dễ False Positive)
                if (avgBaseline > 4000)
                {
                    Logger.Warning($"Mạng quá chậm (Ping ~{avgBaseline}ms). Bỏ qua Time-Based để tránh False Positive.");
                    return DatabaseType.Unknow;
                }

                // TÍNH TOÁN NGƯỠNG (THRESHOLD): Thời gian delay tối đa của mạng + Thời gian Sleep (trừ hao 500ms sai số)
                long thresholdMs = maxBaseline + sleepMilliseconds - 500;
                Logger.Info($"Nếu thời gian request trả về lớn hơn {thresholdMs}ms ta mới nghi ngờ là có lỗi SQLi");

                Logger.Process($"[TIME-BASED] Baseline TB: {avgBaseline}ms | Ngưỡng xác nhận (Threshold): >= {thresholdMs}ms");

                // 2. GỬI PAYLOAD TRUE (CÓ LỆNH SLEEP)
                Logger.Process($"Gửi Payload chứa hàm SLEEP: [{fullPayload}]");
                var sleepResponse = await SendRequestWithTimingAsync(target, paramName, fullPayload);
                Logger.Response(sleepResponse.statusCode, null, $"Thời gian phản hồi: {sleepResponse.elapsedMs}");
                if (sleepResponse.elapsedMs >= thresholdMs || (!sleepResponse.isSuccess && sleepResponse.elapsedMs >= sleepMilliseconds))
                {
                    Logger.Success($"[!] Phát hiện độ trễ bất thường: {sleepResponse.elapsedMs}ms. Đang Double-Check...");
                    // Gửi lại Baseline gốc một lần nữa. Nếu nó trả về NHANH, chứng tỏ lệnh Sleep vừa nãy là thật chứ không phải do Server Lag.

                    Logger.Process("Kiểm tra lại thời gian phản hồi khi không có payload");
                    var doubleCheck = await SendRequestWithTimingAsync(target, paramName, originalValue);
                    Logger.Response(doubleCheck.statusCode, null, $"Thời gian phản hồi: {doubleCheck.elapsedMs}");

                    if (doubleCheck.isSuccess && doubleCheck.elapsedMs <= maxBaseline + 1000) // Cho phép xê dịch 1s
                    {

                        Logger.Success($"Hàm SLEEP có tác dụng với thời gian phản hồi Payload độc ({sleepResponse.elapsedMs}) > {thresholdMs}");
                        DatabaseType dbType = GetDbTypeFromString(payloads.DBMS);
                        Logger.Success($"Server sử dụng {payloads.DBMS} làm cơ sở dữ liệu!");
                        return dbType;
                    }
                    else
                    {
                        Logger.Warning("Double-Check thất bại (Server đang bị Lag thực sự). Hủy báo động giả.");
                    }
                }

                Logger.Warning($"Payload [{payload}] chứa hàm SLEEP không hoạt động");
            }
            return DatabaseType.Unknow;
        }

        private SimilarityResult EvaluateSimilarity(string html1, string html2, int length1,
                               int length2, double acceptableDiffThreshold = 0.05, double greyZoneThreshold = 0.20)
        {
            if (length1 == length2 && html1 == html2)
                return SimilarityResult.Similar;

            int maxLength = Math.Max(length1, length2);
            // Kiểm tra dung lượng từ 2 response
            double diffRatio = (double)Math.Abs(length1 - length2) / maxLength;

            if (diffRatio <= acceptableDiffThreshold)
            {
                return SimilarityResult.Similar;
            }

            if (diffRatio >= greyZoneThreshold)
            {
                return SimilarityResult.Different;
            }

            // Độ lệch ít, nghi ngờ là do dynamic content nên cần kiểm tra nội dung text thô từ html
            // Kiểm tra nội dung từ 2 response
            double similarity = GetContentSimilarity(html1, html2);

            if (similarity >= (1.0 - acceptableDiffThreshold))
            {
                return SimilarityResult.Similar;
            }

            if (similarity <= (1.0 - greyZoneThreshold))
            {
                return SimilarityResult.Different;
            }

            //Cần được AI xác nhận
            return SimilarityResult.GreyZone;
        }


        // Sử dụng thuật toán Jaccard Index: Chỉ quan tâm đến số lượng dòng string trùng, không quan tâm đến ngữ nghĩa
        private double GetContentSimilarity(string html1, string html2)
        {
            if (string.IsNullOrEmpty(html1) && string.IsNullOrEmpty(html2)) return 1.0;
            if (string.IsNullOrEmpty(html1) || string.IsNullOrEmpty(html2)) return 0.0;
            if (html1 == html2) return 1.0;

            // tách toàn bộ nội dung thành từng từ để đem vào HashSet
            var separators = new[] { ' ' };

            // Dùng HashSet để loại bỏ các dòng trùng lặp
            var set1 = new HashSet<string>(
                html1.Split(separators, StringSplitOptions.RemoveEmptyEntries)
                    .Select(line => line.Trim())
                    .Where(line => line.Length > 0)
            );

            var set2 = new HashSet<string>(
                html2.Split(separators, StringSplitOptions.RemoveEmptyEntries)
                    .Select(line => line.Trim())
                    .Where(line => line.Length > 0)
            );

            int intersectionCount = set1.Intersect(set2).Count();
            int unionCount = set1.Union(set2).Count();

            if (unionCount == 0) return 0.0;

            return (double)intersectionCount / unionCount;
        }

        private async Task<AiContextRequestPayload?> GetContextForAI(string baseHtml, string errorHtml, string diffText, string targetUrl)
        {
            var parser = new HtmlParser();

            var documentBaseTask = parser.ParseDocumentAsync(baseHtml);
            var documentFalseTask = parser.ParseDocumentAsync(errorHtml);

            await Task.WhenAll(documentBaseTask, documentFalseTask);
            var documentBase = documentBaseTask.Result;
            var documentFalse = documentFalseTask.Result;

            var changedElementFalse = documentFalse.All.FirstOrDefault(m => m.TextContent.Contains(diffText));
            // Tránh trường hợp lấy Full DOM. Vì thẻ duy nhất không có cha là thẻ <html>
            if (changedElementFalse?.ParentElement == null) return null;

            // Lấy nội dung của thẻ cha sau khi chèn Payload
            string cssPath = BuildCssPath(changedElementFalse);
            // Lấy thông tin Title
            string pageTitle = documentFalse.Title ?? "Không có Title";

            // Tìm context chứa DiffText ở html trước khi chèn payload dựa vào thông tin có được từ cssPath
            IElement? matchedBaseElement = null;
            var currentSearchNode = changedElementFalse.ParentElement;
            while (currentSearchNode != null && currentSearchNode.LocalName != "html")
            {
                string currentPath = BuildCssPath(currentSearchNode);
                matchedBaseElement = documentBase.QuerySelector(currentPath);
                if (matchedBaseElement != null)
                {
                    // Tìm thấy "điểm neo" thành công
                    break;
                }
                currentSearchNode = currentSearchNode.ParentElement;
            }

            string htmlBefore = matchedBaseElement != null
                ? matchedBaseElement.OuterHtml
                : "Không tìm thấy bối cảnh đối xứng ở Request gốc";
            string htmlAfter = (matchedBaseElement != null && currentSearchNode != null)
                ? currentSearchNode.OuterHtml
                : changedElementFalse.ParentElement.OuterHtml;

            return new AiContextRequestPayload(
                Url: targetUrl,
                PageTitle: pageTitle,
                CssPath: matchedBaseElement != null ? BuildCssPath(currentSearchNode!) : cssPath,
                HtmlBefore: htmlBefore,
                HtmlAfter: htmlAfter
            );
        }

        private string BuildCssPath(IElement element)
        {
            StringBuilder path = new StringBuilder();
            var current = element;

            while (current != null && current.LocalName != "html")
            {
                string identifier = current.LocalName;
                // ID luôn tồn tại ở cả 2 request nên ta tạo "điểm neo" ở đây để chút có thể lấy path này làm query selector
                if (!string.IsNullOrEmpty(current.Id))
                {
                    identifier += $"#{current.Id}";
                    path.Insert(0, identifier + (path.Length > 0 ? ">" : ""));
                    break;
                }

                var anchorAttribute = current.Attributes.FirstOrDefault(a =>
                    a.Name.StartsWith("data-") ||
                    a.Name == "name");

                if (anchorAttribute != null)
                {
                    identifier += $"[{anchorAttribute.Name}=\"{anchorAttribute.Value}\"]";
                    path.Insert(0, identifier + (path.Length > 0 ? " > " : ""));
                    break;
                }

                if (current.ClassList.Length > 0)
                {
                    identifier += $".{string.Join(".", current.ClassList)}";
                }

                path.Insert(0, identifier + (path.Length > 0 ? " > " : ""));
                current = current.ParentElement;
            }
            return path.ToString();
        }
        // Loại bỏ toàn bộ thẻ HTML, script và chỉ giữa lại văn bản thuần
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

        private string ExtractDiffText(string originalText, string errorText)
        {
            if (string.IsNullOrEmpty(originalText) || string.IsNullOrEmpty(errorText) || originalText == errorText)
                return string.Empty;

            int start = 0;
            int endOriginal = originalText.Length - 1;
            int endError = errorText.Length - 1;

            // Cắt tiền tố (từ trên xuống)
            while (start <= endOriginal && start <= endError && originalText[start] == errorText[start])
            {
                start++;
            }

            // Cắt hậu tố (từ dưới lên)
            while (endOriginal >= start && endError >= start && originalText[endOriginal] == errorText[endError])
            {
                endOriginal--;
                endError--;
            }

            if (endError >= start)
            {
                return errorText.Substring(start, endError - start + 1).Trim();
            }

            return string.Empty;
        }

        private DatabaseType GetDbTypeFromString(string dbmsName)
        {
            string name = dbmsName?.ToLower() ?? "";
            if (name.Contains("mysql")) return DatabaseType.MySQL;
            if (name.Contains("mssql") || name.Contains("sql server")) return DatabaseType.MSSQL;
            if (name.Contains("postgresql")) return DatabaseType.PostgreSQL;
            if (name.Contains("oracle")) return DatabaseType.Oracle;
            if (name.Contains("sqlite")) return DatabaseType.SQLite;

            return DatabaseType.Unknow;
        }
        #endregion
    }
}