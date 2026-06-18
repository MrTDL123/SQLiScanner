using AngleSharp;
using AngleSharp.Dom;
using AngleSharp.Html.Parser;
using AngleSharp.Io;
using DataSchema;
using SQLiScanner.Models;
using SQLiScanner.Models.Enums;
using SQLiScanner.Utility;
using System.Data;
using System.Diagnostics;
using System.Net;
using System.Text;
using System.Net.Http;
using System.Text.RegularExpressions;
using SQLiScanner.Utilities;
using AngleSharp.Html.Forms;
namespace SQLiScanner.Modules
{

    public enum SimilarityResult
    {
        Similar,   // Giống nhau (> 95%) 
        Different, // Khác biệt rõ ràng (< 80%)
        GreyZone   // Vùng xám (80% - 95%) -> Cần AI thẩm định
    }
    // Mảng phục vụ duy nhất hàm GetContextForAI
    public class DatabaseDetector
    {
        private readonly HttpClient _client;
        private readonly AiConcurrencyEngine _aiConcurrencyEngine;
        private readonly ContextAnalyzer _contextAnalyzer;
        private static readonly string[] CriticalKeywords = { "error", "exception", "syntax", "sql", "500", "warning", "denied", "invalid", "server" };

        private bool IsTesting = true;
        public DatabaseDetector(
            HttpClient client,
            ContextAnalyzer contextAnalyzer,
            AiConcurrencyEngine aiConcurrencyEngine)
        {
            _client = client;
            _contextAnalyzer = contextAnalyzer;
            _aiConcurrencyEngine = aiConcurrencyEngine;
        }

        public async Task DetectAsync(
            CrawlResult target,
            List<PayloadState> trackingList,
            ScanConfig config)
        {
            var allParamNames = new List<string>(target.Params.Keys);
            if (!string.IsNullOrEmpty(target.RawQueryString))
            {
                var queryQueryParams = System.Web.HttpUtility.ParseQueryString(target.RawQueryString);
                foreach (string? key in queryQueryParams.AllKeys)
                {
                    if (key != null && !allParamNames.Contains(key))
                    {
                        allParamNames.Add(key);
                    }
                }
            }

            Logger.Url(
                target.BaseUrl,
                target.HttpMethod,
                string.Join(", ", allParamNames)
            );

            List<Task> pendingAiTasks = new();

            bool ShouldStopCurrentTarget()
            {
                if (config.Token.IsCancellationRequested) return true;

                if (config.ExitOnFirstHit && config.DetectionResults.Any(r => r.VulnerableURL == target.FullUrl && r.HttpMethod == target.HttpMethod))
                    return true;

                return false;
            }

            if (ShouldStopCurrentTarget())
                return;

            foreach (string paramName in allParamNames)
            {
                if (ShouldStopCurrentTarget()) break;

                // Lấy giá trị gốc an toàn: Ưu tiên trong Params, nếu không có thì bóc từ RawQueryString
                string originalValue = target.Params.TryGetValue(paramName, out var bodyVal)
                    ? bodyVal
                    : (System.Web.HttpUtility.ParseQueryString(target.RawQueryString)[paramName] ?? "");

                Logger.Info($"THAM SỐ ĐƯỢC SỬ DỤNG ĐỂ TẤN CÔNG: {paramName}");
                // Kiểm tra ngữ cảnh
                PayloadState heuristicState = new PayloadState(target.FullUrl, paramName, "[Đang lấy payload dựa vào ngữ cảnh]");
                trackingList.Add(heuristicState);

                heuristicState.UpdateStatus(ScanStatus.HeuristicScanning, "Bắt đầu phân tích bối cảnh đầu vào...");
                HeuristicResult heuristicResult = await _contextAnalyzer.PerformHeuristicScanAsync(target, paramName, heuristicState, config.Token);

                // Kiểm tra XSS
                if (heuristicResult.IsReflected)
                {
                    Logger.Warning($"[+] DANGEROUS: Phát hiện lỗ hổng Reflected XSS tại tham số [{paramName}]!");
                    heuristicState.UpdateStatus(ScanStatus.Vulnerable, $"Phát hiện rò rĩ dữ liệu (XSS) tại tham số [{paramName}]");
                    DetectionResult xssResult = new DetectionResult
                    {
                        HttpMethod = target.HttpMethod,
                        VulnerableURL = target.FullUrl,
                        FoundContext = "XSS",
                        DatabaseType = DatabaseType.Unknow,
                        VulnerableParam = paramName,
                        WorkingPrefix = string.Empty,
                        WorkingSuffix = string.Empty,
                        IsCookieBypass = heuristicResult.IsCookiePriority,
                        IsReflected = heuristicResult.IsReflected
                    };

                    config.DetectionResults.Add(xssResult);
                }

                if (!heuristicResult.IsReadyForDetection) // Đảm bảo đã đầy đủ Boudary và Payload để test
                {
                    heuristicState.UpdateStatus(ScanStatus.Safe, "Bỏ qua: Không tìm thấy Boundary hoặc ngữ cảnh lỗi.");
                    Logger.Warning($"Bỏ qua tham số [{paramName}] vì không khóa được Boundary hợp lệ.");
                    continue;
                }

                foreach (var boundary in heuristicResult.ApplicableBoundaries)
                {
                    if (ShouldStopCurrentTarget()) break;
                    string prefix = boundary.Prefix;
                    string suffix = boundary.Suffix;
                    Logger.Info($"\nXét Boundary: Prefix [{prefix}] | Suffix [{suffix}]");

                    // CỜ KIỂM SOÁT NGẮT SỚM CHO THAM SỐ HIỆN TẠI
                    bool isCurrentParamVulnerable = false;
                    // --- GIAI ĐOẠN 1: TÌM KIẾM ERROR-BASED ---
                    var errorType = heuristicResult.ApplicablePayloads.Where(p => p.SType == 2).ToList();
                    if (errorType.Any())
                    {
                        Logger.Phase($"TÌM KIẾM BẰNG ERROR-BASED VỚI PREFIX [{prefix}]");

                        PayloadState[] localStates = new PayloadState[errorType.Sum(payload => payload.Payloads.Count)];
                        int stateIndex = 0;
                        foreach (PayloadType payloads in errorType)
                        {
                            foreach (string payload in payloads.Payloads)
                            {
                                localStates[stateIndex++] = new PayloadState(target.FullUrl, paramName, payload);
                            }
                        }
                        foreach (var state in localStates) trackingList.Add(state);

                        stateIndex = 0;
                        foreach (PayloadType payloads in errorType)
                        {
                            if (ShouldStopCurrentTarget() || isCurrentParamVulnerable) break;
                            foreach (string payload in payloads.Payloads)
                            {
                                if (ShouldStopCurrentTarget() || isCurrentParamVulnerable) break;

                                PayloadState currentState = localStates[stateIndex];
                                currentState.UpdateStatus(ScanStatus.HeuristicScanning, "Testing Error-Based...");

                                bool isErrorBasedSuccess = await CheckErrorBasedPayload(
                                    target, prefix, suffix, payload, payloads.ErrorResponsePattern,
                                    currentState, heuristicResult.IsReflected,
                                    heuristicResult.Route,
                                    expectedResult: "19998",
                                    config.Token
                                );

                                if (isErrorBasedSuccess)
                                {
                                    isCurrentParamVulnerable = true;
                                    currentState.UpdateStatus(ScanStatus.Vulnerable, $"Phát hiện {payloads.DBMS} (Error-based)");
                                    DetectionResult result = new DetectionResult
                                    {
                                        HttpMethod = target.HttpMethod,
                                        VulnerableURL = target.FullUrl,
                                        FoundContext = "ERROR-BASED",
                                        DatabaseType = GetDbTypeFromString(payloads.DBMS),
                                        VulnerableParam = paramName,
                                        WorkingPrefix = prefix,
                                        WorkingSuffix = suffix,
                                        IsCookieBypass = heuristicResult.IsCookiePriority,
                                        IsReflected = heuristicResult.IsReflected
                                    };

                                    Logger.Success($"PHÁT HIỆN {result.DatabaseType} THÔNG QUA THÔNG BÁO LỖI!");
                                    config.DetectionResults.Add(result);

                                    if (config.ExitOnFirstHit) break;
                                }
                                if (currentState.Status != ScanStatus.Safe)
                                    if (currentState.Status != ScanStatus.Error)
                                        currentState.UpdateStatus(ScanStatus.Safe, "Phản hồi từ đối tượng không chứa các từ khóa cần tìm");
                                stateIndex++;
                            }
                        }
                        ClearUnusedStates(localStates);
                    }

                    // --- GIAI ĐOẠN 2: TÌM KIẾM BOOLEAN-BASED (SType == 1) ---
                    if (isCurrentParamVulnerable) continue;

                    List<PayloadType> booleanType = heuristicResult.ApplicablePayloads.Where(p => p.SType == 1).ToList();
                    if (booleanType.Any())
                    {
                        Logger.Phase($"TÌM KIẾM BẰNG BOOLEAN-BASED VỚI PREFIX [{prefix}]");
                        PayloadState[] localStates = new PayloadState[booleanType.Sum(payload =>
                            payload.Payloads.Count
                        )];
                        int stateIndex = 0;

                        foreach (PayloadType payloads in booleanType)
                        {
                            foreach (string payload in payloads.Payloads)
                            {
                                localStates[stateIndex++] = new PayloadState(target.FullUrl, paramName, payload);
                            }
                        }

                        foreach (PayloadState state in localStates) trackingList.Add(state);

                        stateIndex = 0;
                        foreach (PayloadType payloads in booleanType)
                        {
                            if (ShouldStopCurrentTarget() || isCurrentParamVulnerable) break;
                            foreach (string payload in payloads.Payloads)
                            {
                                if (ShouldStopCurrentTarget() || isCurrentParamVulnerable) break;

                                PayloadState currentState = localStates[stateIndex];
                                currentState.UpdateStatus(ScanStatus.HeuristicScanning, "Testing Boolean...");

                                bool isBooleanSuccess = await CheckBooleanBasedPayload(
                                    target, payloads.DBMS, prefix, suffix, payload,
                                    currentState, config, pendingAiTasks,
                                    heuristicResult.IsReflected, heuristicResult.Route,
                                    config.Token);

                                if (isBooleanSuccess)
                                {
                                    isCurrentParamVulnerable = true;
                                    currentState.UpdateStatus(ScanStatus.Vulnerable, $"Phát hiện {payloads.DBMS} (Boolean-based)");

                                    DetectionResult result = new DetectionResult
                                    {
                                        HttpMethod = target.HttpMethod,
                                        VulnerableURL = target.FullUrl,
                                        FoundContext = "BOOLEAN-BASED",
                                        DatabaseType = GetDbTypeFromString(payloads.DBMS),
                                        VulnerableParam = paramName,
                                        WorkingPrefix = prefix,
                                        WorkingSuffix = suffix,
                                        IsCookieBypass = heuristicResult.IsCookiePriority,
                                        IsReflected = heuristicResult.IsReflected
                                    };
                                    Logger.Success($"PHÁT HIỆN {result.DatabaseType} THÔNG QUA Boolean-Based!");
                                    config.DetectionResults.Add(result);

                                    if (config.ExitOnFirstHit) break;
                                }
                                if (currentState.Status != ScanStatus.Safe) 
                                    if (currentState.Status != ScanStatus.Error)
                                        currentState.UpdateStatus(ScanStatus.Safe, "Payload không có tác dụng");
                                stateIndex++;
                            }
                        }
                        ClearUnusedStates(localStates);
                    }

                    // --- GIAI ĐOẠN 3: TÌM KIẾM TIME-BASED (SType == 5) ---
                    if (isCurrentParamVulnerable) continue;
                    var timeType = heuristicResult.ApplicablePayloads.Where(p => p.SType == 5).ToList();
                    if (timeType.Any())
                    {
                        Logger.Phase($"TÌM KIẾM TIME-BASED VỚI PREFIX [{prefix}]");

                        PayloadState[] localStates = new PayloadState[timeType.Sum(payloads => payloads.Payloads.Count)];

                        int stateIndex = 0;
                        foreach (PayloadType payloads in timeType)
                        {
                            foreach (string payload in payloads.Payloads)
                            {
                                localStates[stateIndex++] = new PayloadState(target.FullUrl, paramName, payload);
                            }
                        }

                        foreach (var state in localStates) trackingList.Add(state);

                        stateIndex = 0;
                        foreach (PayloadType payloads in timeType)
                        {
                            if (ShouldStopCurrentTarget() || isCurrentParamVulnerable) break;
                            foreach (string payload in payloads.Payloads)
                            {
                                if (ShouldStopCurrentTarget() || isCurrentParamVulnerable) break;
                                PayloadState currentState = localStates[stateIndex];
                                currentState.UpdateStatus(ScanStatus.HeuristicScanning, "Testing Time-Based...");

                                bool isTimeBasedSuccess = await CheckTimeBasedPayloadAsync(
                                target, prefix, suffix, payload, currentState, heuristicResult.Route,
                                config.Token);

                                if (isTimeBasedSuccess)
                                {
                                    isCurrentParamVulnerable = true;
                                    currentState.UpdateStatus(ScanStatus.Vulnerable, $"Phát hiện {payloads.DBMS} (Time-based)");
                                    DetectionResult result = new DetectionResult
                                    {
                                        HttpMethod = target.HttpMethod,
                                        VulnerableURL = target.FullUrl,
                                        FoundContext = "TIME-BASED",
                                        DatabaseType = GetDbTypeFromString(payloads.DBMS),
                                        VulnerableParam = paramName,
                                        WorkingPrefix = prefix,
                                        WorkingSuffix = suffix,
                                        IsCookieBypass = heuristicResult.IsCookiePriority,
                                        IsReflected = heuristicResult.IsReflected
                                    };
                                    Logger.Success($"PHÁT HIỆN {result.DatabaseType} THÔNG QUA TIME-BASED!");
                                    config.DetectionResults.Add(result);

                                    if (config.ExitOnFirstHit) break;
                                }
                                if (currentState.Status != ScanStatus.Safe) 
                                    if (currentState.Status != ScanStatus.Error)
                                        currentState.UpdateStatus(ScanStatus.Safe, "Payload Time-based không hoạt động");
                                stateIndex++;
                            }
                        }
                        ClearUnusedStates(localStates);
                    }
                }
            }

            if (!config.Token.IsCancellationRequested && pendingAiTasks.Any())
            {
                if (!config.ExitOnFirstHit || !config.DetectionResults.Any(r => r.VulnerableURL == target.FullUrl))
                {
                    Logger.Process($"Đang chờ {pendingAiTasks.Count} payload vùng xám được AI xử lý nốt...");
                    await Task.WhenAll(pendingAiTasks);
                }
            }

            return;
        }

        #region Các hàm phụ trợ
        private async Task<(bool isSuccess, long elapsedMs, int statusCode)> SendRequestWithTimingAsync(
            CrawlResult target, string payload, InjectionRoute route, CancellationToken cancellationToken = default)
        {
            var sw = new Stopwatch();
            try
            {
                sw.Start();
                var (_, _, statusCode, _) = await SendRequestAsync(target, payload, route, cancellationToken);
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
        private async Task<(string? html, byte[]? bytes, int statusCode, string finalUrl)> SendRequestAsync(
            CrawlResult target, string payload, InjectionRoute route, CancellationToken cancellationToken = default)
        {
            try
            {
                var method = new System.Net.Http.HttpMethod(target.HttpMethod.ToUpper());
                HttpRequestMessage request;

                var queryParams = System.Web.HttpUtility.ParseQueryString(target.RawQueryString);
                var bodyParams = new Dictionary<string, string>(target.Params);

                // Kiểm tra liệu có phải đang chèn payload vào tham số query hay đang chèn vào Form
                bool isQueryParam = target.RawQueryString.Contains($"{route.TargetKey}=") || !target.Params.ContainsKey(route.TargetKey);

                string valueToInject = route.Type switch
                {
                    RouteType.Cookie => route.OriginalValue, // Sử dụng Cookie là nơi chứa payload nên giữ nguyên giá trị các tham số query/inputs
                    _ => payload                             // Ngược lại: Gửi payload trực tiếp qua URL/Body
                };

                if (isQueryParam)
                {
                    queryParams[route.TargetKey] = valueToInject;
                    bodyParams.Remove(route.TargetKey);
                }
                else
                {
                    bodyParams[route.TargetKey] = valueToInject;
                }

                var uriBuilder = new UriBuilder(target.BaseUrl)
                {
                    Query = queryParams.ToString()
                };

                request = new HttpRequestMessage(method, uriBuilder.ToString());

                if (method == System.Net.Http.HttpMethod.Post)
                {
                    request.Content = new FormUrlEncodedContent(bodyParams);
                    Logger.Request(method.ToString(), $"URL Query: {uriBuilder.Query} | Body: {string.Join(", ", bodyParams.Select(kv => $"{kv.Key}=[{kv.Value}]"))}");
                }
                else
                {
                    Logger.Request(method.ToString(), uriBuilder.ToString());
                }

                if (!request.Headers.Contains("User-Agent"))
                {
                    request.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
                }

                string baseSessionCookie = target.OriginalCookie;

                if (route.Type == RouteType.Cookie)
                {
                    var cookieBuilder = new StringBuilder();
                    cookieBuilder.Append(route.TargetKey).Append('=').Append(payload);

                    if (!string.IsNullOrEmpty(baseSessionCookie))
                    {
                        cookieBuilder.Append("; ").Append(baseSessionCookie);
                    }

                    request.Headers.Add("Cookie", cookieBuilder.ToString());
                }
                else
                {
                    if (!string.IsNullOrEmpty(baseSessionCookie))
                    {
                        request.Headers.Add("Cookie", baseSessionCookie);
                    }
                }
                using var response = await _client.SendAsync(request, HttpCompletionOption.ResponseContentRead, cancellationToken);
                var bytes = await response.Content.ReadAsByteArrayAsync(cancellationToken);
                var charset = response.Content.Headers.ContentType?.CharSet;
                var encoding = charset is not null ? Encoding.GetEncoding(charset) : Encoding.UTF8;
                string? finalUrl = response.RequestMessage.RequestUri.ToString();

                return (encoding.GetString(bytes), bytes, (int)response.StatusCode, finalUrl);
            }
            catch (OperationCanceledException)
            {
                Logger.Warning("Yêu cầu mạng bị hủy bỏ theo yêu cầu của hệ thống/người dùng.");
                return (null!, null!, 0, null!);
            }
            catch (Exception ex)
            {
                Logger.Error($"Gửi Request thất bại: {ex.Message}");
                return (null!, null!, 0, null!);
            }
        }

        private async Task<bool> CheckErrorBasedPayload(
            CrawlResult target,
            string prefix,
            string suffix,
            string payload,
            string errorResponseRegex,
            PayloadState currentState,
            bool isReflected,
            InjectionRoute route,
            string expectedResult = null,
            CancellationToken cancellationToken = default
        )
        {
            string rawFullPayload = $"{route.OriginalValue}{prefix} {payload} {suffix} ";
            string fullPayload = route.Type == RouteType.Standard
                ? TamperEngine.ApplyTamper(rawFullPayload)
                : rawFullPayload;
            var (html, _, _, _) = await SendRequestAsync(target, fullPayload, route, cancellationToken);

            if (string.IsNullOrEmpty(html))
            {
                currentState.UpdateStatus(ScanStatus.Error, "Bị WAF chặn / Timeout");
                return false;
            }

            if (!string.IsNullOrEmpty(errorResponseRegex))
            {
                try
                {
                    Match match = Regex.Match(html, errorResponseRegex, RegexOptions.IgnoreCase | RegexOptions.Singleline);
                    if (match.Success)
                    {
                        string extractedData = match.Groups["result"].Value;
                        extractedData = WebUtility.UrlDecode(extractedData).Trim();

                        // Nếu nội dung thấy được chứa các câu query thì payload không hoạt động mà chỉ bị trả về
                        if (expectedResult != null)
                        {
                            if (extractedData == expectedResult)
                            {
                                Logger.Success($"Xác thực thành công bằng toán học! Kỳ vọng: {expectedResult} | Thực tế nhận được: {extractedData}");
                                return true;
                            }
                            else
                            {
                                Logger.Warning($"Cảnh báo nhiễu Reflected: Nhận được '{extractedData}' nhưng kỳ vọng kết quả phép tính '{expectedResult}'.");
                                currentState.UpdateStatus(ScanStatus.Safe, "Bị nhiểu Reflected, đối tượng có khả năng bị XSS");
                                return false;
                            }
                        }
                        else
                        {
                            if (extractedData.Contains("SELECT", StringComparison.OrdinalIgnoreCase) ||
                                extractedData.Contains("qXXq", StringComparison.OrdinalIgnoreCase) ||
                                extractedData.Contains("EXTRACTVALUE", StringComparison.OrdinalIgnoreCase))
                            {
                                Logger.Warning("Regex tóm nhầm dữ liệu Reflected (Do chứa nguyên văn từ khóa chưa biên dịch).");
                                currentState.UpdateStatus(ScanStatus.Safe, "Bị nhiểu Reflected, đối tượng có khả năng bị XSS");
                                return false;
                            }
                            else
                            {
                                Logger.Success($"Trích xuất dữ liệu thành công! Data: {extractedData}");
                                return true;
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    Logger.Warning($"Lỗi phân tích Regex Error-Based: {ex.Message}");
                }
            }
            return false;
        }

        private async Task<bool> CheckBooleanBasedPayload(
            CrawlResult target, string dbms,
            string prefix, string suffix, string payload, PayloadState currentState,
            ScanConfig config, List<Task> pendingAiTasks, bool isReflected,
            InjectionRoute route,
            CancellationToken cancellationToken = default)
        {
            // CHUẨN BỊ PAYLOAD
            string rawPayloadTrue = $"{route.OriginalValue}{prefix} {payload} {suffix} ";
            string fullPayloadTrue = route.Type == RouteType.Standard
                ? TamperEngine.ApplyTamper(rawPayloadTrue)
                : rawPayloadTrue;

            string falsePayload = payload.Replace("=", "!=").Replace(">", "<");
            string rawPayloadFalse = $"{route.OriginalValue}{prefix} {falsePayload} {suffix} ";
            string fullPayloadFalse = route.Type == RouteType.Standard
                ? TamperEngine.ApplyTamper(rawPayloadFalse)
                : rawPayloadFalse;

            Logger.Process($"[>] TRUE PayLoad {fullPayloadTrue}");
            (string? htmlTrue, byte[]? bytesTrue, int statusTrue, string trueFinalUrl) =
                await SendRequestAsync(target, fullPayloadTrue, route, cancellationToken);
            if (bytesTrue == null)
            {
                Logger.Warning("Mất kết nối hoặc bị WAF chặn. Bỏ qua.");
                currentState.UpdateStatus(ScanStatus.Error, "Bị WAF chặn / Timeout");
                return false;
            }
            Logger.Response(statusTrue, bytesTrue.Length);

            Logger.Process($"[>] FALSE Payload {fullPayloadFalse}");
            (string? htmlFalse, byte[]? bytesFalse, int statusFalse, string falseFinalUrl) =
                await SendRequestAsync(target, fullPayloadFalse, route, cancellationToken);

            if (bytesFalse == null)
            {
                Logger.Warning("Mất kết nối hoặc bị WAF chặn. Bỏ qua.");
                currentState.UpdateStatus(ScanStatus.Error, "Bị WAF chặn / Timeout");
                return false;
            }
            Logger.Response(statusFalse, bytesFalse.Length);

            //ĐẢM BẢO 2 PHẢN HỒI TỪ PAYLOAD KHÔNG GIỐNG NHAU
            if (statusTrue != statusFalse)
            {
                Logger.Success($"Phát hiện khác biệt Status Code: True({statusTrue}) != False({statusFalse})");
                return true;
            }

            string textTrue = ExtractPlainText(htmlTrue!);
            string textFalse = ExtractPlainText(htmlFalse!);
            var similarityState = EvaluateSimilarity(textTrue, textFalse, bytesTrue.Length, bytesFalse.Length, 0.05, 0.20);

            if (similarityState == SimilarityResult.Similar)
            {
                Logger.Warning($"Phát hiện sự trùng nhau ở dung lượng cả 2. True({bytesTrue.Length}) ~ False({bytesFalse.Length})");
                return false;
            }

            //BÁO CÁO PHÁT HIỆN TRƯỜNG HỢP ĐẶC BIỆT KHI MÃ PHẢN HỒI CẢ 2 GIỐNG NHAU NHƯNG DUNG LƯỢNG CẢ 2 LẠI KHÁC.
            if (/*IsTesting || */similarityState == SimilarityResult.GreyZone)
            {
                Logger.Process("Phát hiện vùng xám. Đang kích hoạt AI để thẩm định ngữ cảnh");

                var uriBuilder = new UriBuilder(target.BaseUrl);
                if (!string.IsNullOrEmpty(target.RawQueryString))
                {
                    uriBuilder.Query = target.RawQueryString;
                }
                string fullOriginalUrl = uriBuilder.ToString();

                AiContextRequestPayload? conTextForAI = await GetContextForAI(
                    htmlTrue!, trueFinalUrl!,
                    htmlFalse!, falseFinalUrl,
                    fullOriginalUrl);

                if (conTextForAI != null)
                {
                    Task aiTask = _aiConcurrencyEngine.EnqueueAnalysisAsync(
                        conTextForAI, currentState, response =>
                        {
                            // Đoạn code dưới chạy trên luồng phân tích bằng AI
                            if (response.IsVulnerable)
                            {
                                currentState.UpdateStatus(ScanStatus.Vulnerable, $"AI: {response.Reason}");
                                DetectionResult result = new DetectionResult
                                {
                                    HttpMethod = target.HttpMethod,
                                    VulnerableURL = target.FullUrl,
                                    FoundContext = "BOOLEAN-BASED",
                                    DatabaseType = GetDbTypeFromString(dbms),
                                    VulnerableParam = route.TargetKey,
                                    WorkingPrefix = prefix,
                                    WorkingSuffix = suffix,
                                    IsCookieBypass = (route.Type == RouteType.Cookie),
                                    IsReflected = isReflected
                                };
                                config.DetectionResults.Add(result);
                            }
                            else
                            {
                                currentState.UpdateStatus(ScanStatus.Safe, $"AI: {response.Reason}");
                            }
                        }
                    );
                    pendingAiTasks.Add(aiTask);
                }
                if (conTextForAI is null)
                    currentState.UpdateStatus(ScanStatus.Safe, $"Không tìm thấy dữ liệu để gửi AI");

                // Ngay lập tức trả về false để luồng chính phân tích Heuristic
                return false;
            }

            Logger.Process("Đang xác định kịch bản phát hiện...");
            var baselineRoute = InjectionRoute.CreateStandard(route.TargetKey, route.OriginalValue);
            (string? htmlBase, byte[]? bytesBase, _, _) =
                await SendRequestAsync(target, route.OriginalValue, baselineRoute, cancellationToken);

            if (bytesBase == null)
            {
                Logger.Warning("Không lấy được Base Request. Vẫn ghi nhận lỗi SQLi.");
                return true;
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
                currentState.UpdateStatus(ScanStatus.HeuristicScanning, "Bypass: Base = True");
            }
            else if (baseVsFalse == SimilarityResult.Similar || baseVsFalse == SimilarityResult.GreyZone)
            {
                Logger.Success("Kịch bản phát hiện (Bypass/Login): Base giống False, nhưng True lại ra kết quả mới.");
                currentState.UpdateStatus(ScanStatus.HeuristicScanning, "Bypass: Base = False");
            }
            else
            {
                Logger.Success("Kịch bản phát hiện: Cả True và False đều làm thay đổi trang web so với Base.");
                currentState.UpdateStatus(ScanStatus.HeuristicScanning, "Bypass: True != False != Base");
            }
            return true;
        }


        private async Task<bool> CheckTimeBasedPayloadAsync(
            CrawlResult target,
            string prefix,
            string suffix,
            string payload,
            PayloadState currentState,
            InjectionRoute route, // Thay thế hoàn toàn các biến rời rạc
            CancellationToken cancellationToken = default)
        {
            int sleepSeconds = 5;
            long sleepMilliseconds = sleepSeconds * 1000;

            Logger.Info($"\nSử dụng Payload: {payload}");
            string payloadStr = payload.Replace("[SLEEPTIME]", sleepSeconds.ToString());

            // YÊU CẦU 2: Định tuyến và xáo trộn Tamper nếu đi qua ngả Standard (Bypass WAF)
            string rawFullPayload = $"{route.OriginalValue}{prefix} AND {payloadStr} {suffix} ";
            string fullPayload = route.Type == RouteType.Standard
                ? TamperEngine.ApplyTamper(rawFullPayload)
                : rawFullPayload;

            Logger.Process($"[TIME-BASED] Kiểm tra thời gian phản hồi trung bình...");

            // Khởi tạo một Route Standard sạch cho các request đo Baseline đo đạc không mang payload
            var baselineRoute = InjectionRoute.CreateStandard(route.TargetKey, route.OriginalValue);

            // 1. LẤY BASELINE
            List<long> baselineDelays = new List<long>();
            for (int i = 0; i < 3; i++)
            {
                Logger.Process($"Kiểm tra lần {i}");
                var (success, ms, status) = await SendRequestWithTimingAsync(target, route.OriginalValue, baselineRoute, cancellationToken);
                Logger.Response(status, null, $"Thời gian phản hồi: {ms}ms");
                if (success) baselineDelays.Add(ms);
            }

            if (baselineDelays.Count == 0)
            {
                currentState.UpdateStatus(ScanStatus.Error, "Bị WAF chặn / Timeout");
                return false;
            }
            long maxBaseline = baselineDelays.Max();
            long avgBaseline = (long)baselineDelays.Average();

            if (avgBaseline > 4000)
            {
                Logger.Warning($"Mạng quá chậm (Ping ~{avgBaseline}ms). Bỏ qua Time-Based để tránh False Positive.");
                currentState.UpdateStatus(ScanStatus.Error, "Mạng quá chậm để sử dụng Time-Based");
                return false;
            }

            long thresholdMs = maxBaseline + sleepMilliseconds - 500;
            Logger.Process($"[TIME-BASED] Baseline TB: {avgBaseline}ms | Ngưỡng xác nhận (Threshold): >= {thresholdMs}ms");

            // 2. GỬI PAYLOAD TRUE (Áp dụng định tuyến theo InjectionRoute cấu hình sẵn)
            Logger.Process($"Gửi Payload chứa hàm SLEEP: [{fullPayload}]");
            var sleepResponse = await SendRequestWithTimingAsync(target, fullPayload, route, cancellationToken);
            Logger.Response(sleepResponse.statusCode, null, $"Thời gian phản hồi: {sleepResponse.elapsedMs}");

            if (sleepResponse.elapsedMs >= thresholdMs || (!sleepResponse.isSuccess && sleepResponse.elapsedMs >= sleepMilliseconds))
            {
                Logger.Success($"[!] Phát hiện độ trễ bất thường: {sleepResponse.elapsedMs}ms. Đang Double-Check...");

                Logger.Process("Kiểm tra lại thời gian phản hồi khi không có payload");
                var doubleCheck = await SendRequestWithTimingAsync(target, route.OriginalValue, baselineRoute, cancellationToken);
                Logger.Response(doubleCheck.statusCode, null, $"Thời gian phản hồi: {doubleCheck.elapsedMs}");

                if (doubleCheck.isSuccess && doubleCheck.elapsedMs <= maxBaseline + 1000)
                {
                    Logger.Success($"Hàm SLEEP có tác dụng với thời gian phản hồi Payload độc ({sleepResponse.elapsedMs}) > {thresholdMs}");
                    return true;
                }
                else
                {
                    Logger.Warning("Double-Check thất bại (Server đang bị Lag thực sự). Hủy báo động giả.");
                }
            }

            Logger.Warning($"Payload [{payload}] chứa hàm SLEEP không hoạt động");
            currentState.UpdateStatus(ScanStatus.Safe, "Payload Time-based không hoạt động");
            return false;
        }

        private SimilarityResult EvaluateSimilarity(
            string html1, string html2, int length1, int length2,
            double acceptableDiffThreshold = 0.05, double greyZoneThreshold = 0.20)
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


        private async Task<AiContextRequestPayload?> GetContextForAI(
            string trueHtml, string trueFinalUrl,
            string falseHtml, string falseFinalUrl,
            string targetUrl)
        {
            var parser = new HtmlParser();

            var documentTrueTask = parser.ParseDocumentAsync(trueHtml);
            var documentFalseTask = parser.ParseDocumentAsync(falseHtml);

            await Task.WhenAll(documentTrueTask, documentFalseTask);
            var documentTrue = documentTrueTask.Result;
            var documentFalse = documentFalseTask.Result;

            string trueFullText = documentTrue.DocumentElement?.TextContent ?? "";

            var diffElements = documentFalse.All
                .Where(e => e.LocalName != "script"
                         && e.LocalName != "style"
                         && !string.IsNullOrWhiteSpace(e.TextContent))
                .Where(e => !trueFullText.Contains(e.TextContent.Trim()))
                .ToList();



            // Vì thẻ cha cũng được tính là chứa được nội dung diffText 
            // nên ta đi tìm thẻ chứa nội dung diffText ít thẻ con nhất
            var changedElementFalse = diffElements
                .OrderBy(e => e.QuerySelectorAll("*").Length)
                .ThenByDescending(e => CriticalKeywords.Count(k => e.TextContent.Contains(k, StringComparison.OrdinalIgnoreCase)))
                .FirstOrDefault();

            // Tránh trường hợp lấy Full DOM. Vì thẻ duy nhất không có cha là thẻ <html>
            if (changedElementFalse == null || changedElementFalse.ParentElement == null)
                return null;

            string cssPath = BuildCssPath(changedElementFalse);
            string pageTitle = documentFalse.Title ?? "Không có Title";

            // Tìm context chứa DiffText ở html chèn payload True dựa vào thông tin có được từ cssPath
            IElement? matchedBaseElement = null;
            var currentSearchNode = changedElementFalse.ParentElement;
            while (currentSearchNode != null && currentSearchNode.LocalName != "html")
            {
                string currentPath = BuildCssPath(currentSearchNode);
                matchedBaseElement = documentTrue.QuerySelector(currentPath);

                // Tìm thấy "điểm neo" thành công
                if (matchedBaseElement != null) break;
                currentSearchNode = currentSearchNode.ParentElement;
            }

            string htmlBefore = matchedBaseElement != null
                ? matchedBaseElement.OuterHtml
                : "Không tìm thấy bối cảnh đối xứng ở Request gốc";
            string htmlAfter = (matchedBaseElement != null && currentSearchNode != null)
                ? currentSearchNode.OuterHtml
                : changedElementFalse.ParentElement.OuterHtml;

            return new AiContextRequestPayload(
                TargetUrl: targetUrl,
                PageTitle: pageTitle,
                CssPath: matchedBaseElement != null ? BuildCssPath(currentSearchNode!) : cssPath,
                TrueUrl: trueFinalUrl,
                TrueHtml: htmlBefore,
                FalseUrl: falseFinalUrl,
                FalseHtml: htmlAfter
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

        private void ClearUnusedStates(PayloadState[] states)
        {
            // Bắt đầu từ payload tiếp theo chưa được chạy, ép tất cả về Safe
            foreach (var state in states)
            {
                if (state.Status == ScanStatus.Pending)
                {
                    state.UpdateStatus(ScanStatus.Safe, "Bỏ qua (Đã tìm thấy lỗ hổng trang đang xét)");
                }
            }
        }
        #endregion
    }
}