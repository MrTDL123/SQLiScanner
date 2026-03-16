using SQLiScanner.Models;
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
namespace SQLiScanner.Modules
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
            Logger.Url(
                target.FullUrl,
                target.HttpMethod,
                string.Join(", ", target.Params.Keys)
            );
            // Kiểm tra ngữ cảnh
            var contextAnalyzer = new ContextAnalyzer(_client);

            foreach (var param in target.Params)
            {
                string paramName = param.Key;
                string originalValue = param.Value;
                Logger.Info($"ĐỐI TƯỢNG THAM SỐ ĐỂ CHÈN PAYLOAD: {paramName}");
                HeuristicResult heuristicResult = await contextAnalyzer.PerformHeuristicScanAsync(target, paramName);
                if (!heuristicResult.IsReadyForDetection) // Đảm bảo đã đầy đủ Boudary và Payload để test
                {
                    Logger.Warning($"Bỏ qua tham số [{paramName}] vì không khóa được Boundary hợp lệ.");
                    continue;
                }

                foreach (var boundary in heuristicResult.ApplicableBoundaries)
                {
                    string prefix = boundary.Prefix;
                    string suffix = boundary.Suffix;
                    Logger.Success($"Đã nhận Boundary chuẩn từ ContextAnalyzer: Prefix [{prefix}] | Suffix [{suffix}]");

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

                            if (dbType != DbType.Unknow)
                            {
                                DetectionResult result = new DetectionResult
                                {
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

                            if (dbType != DbType.Unknow)
                            {
                                DetectionResult result = new DetectionResult
                                {
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
                            if (dbType != DbType.Unknow)
                            {
                                DetectionResult result = new DetectionResult
                                {
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
                    }
                }
            }

            Logger.Skipped("Không tìm thấy được lỗ hổng SQLi trong tất cả các Entry points!");
            return new DetectionResult { DatabaseType = DbType.Unknow };
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

        private async Task<DbType> TestErrorBasedPayload(
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
                string injectedPayload = $"{originalValue}{prefix}{payload} {suffix} ";
                var (html, _, _) = await SendRequestAsync(target, paramName, injectedPayload);

                if (string.IsNullOrEmpty(html))
                    return DbType.Unknow;

                if (!string.IsNullOrEmpty(payloads.ErrorResponsePattern))
                {
                    var regex = new Regex(payloads.ErrorResponsePattern, RegexOptions.IgnoreCase);
                    if (regex.IsMatch(html))
                    {
                        Logger.Success($"✓ Error-based detected: {payloads.DBMS}");
                        return GetDbTypeFromString(payloads.DBMS);
                    }
                }
            }

            return DbType.Unknow;
        }

        private async Task<DbType> TestBooleanBasedPayload(
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
                string fullPayloadTrue = $"{originalValue}{prefix} AND {payload} {suffix} ";

                string falsePayload = payload.Replace("=", "!=").Replace(">", "<");
                string fullPayloadFalse = $"{originalValue}{prefix} AND {falsePayload} {suffix} ";

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
                if (IsSimilar(textTrue, textFalse, bytesTrue.Length, bytesFalse.Length, 0.05))
                {
                    Logger.Warning($"Phát hiện sự trùng nhau ở dung lượng cả 2. True({bytesTrue.Length}) ~ False({bytesFalse.Length})");
                    continue;
                }

                //BÁO CÁO PHÁT HIỆN TRƯỜNG HỢP ĐẶC BIỆT KHI MÃ PHẢN HỒI CẢ 2 GIỐNG NHAU NHƯNG DUNG LƯỢNG CẢ 2 LẠI KHÁC.
                Logger.Process("Đang xác định kịch bản phát hiện...");
                (string? htmlBase, byte[]? bytesBase, _) =
                    await SendRequestAsync(target, paramName, originalValue);

                if (bytesBase == null)
                {
                    Logger.Warning("Không lấy được Base Request. Vẫn ghi nhận lỗi SQLi.");
                    return GetDbTypeFromString(payloads.DBMS);

                }
                string textBase = ExtractPlainText(htmlBase!);

                if (IsSimilar(textBase!, textTrue, bytesBase.Length, bytesTrue.Length, 0.05))
                {
                    Logger.Success("Kịch bản phát hiện: Base giống True, nhưng khác False.");
                }
                else if (IsSimilar(textBase!, textFalse, bytesBase.Length, bytesFalse.Length, 0.05))
                {
                    Logger.Success("Kịch bản phát hiện (Bypass/Login): Base giống False, nhưng True lại ra kết quả mới.");
                }
                else
                {
                    Logger.Success("Kịch bản phát hiện: Cả True và False đều làm thay đổi trang web so với Base.");
                }

                return GetDbTypeFromString(payloads.DBMS);
            }

            //Để đây để không bị lỗi cú pháp
            return DbType.Unknow;
        }

        private async Task<DbType> TestTimeBasedPayloadAsync(
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
                string payloadStr = payload.Replace("[SLEEPTIME]", sleepSeconds.ToString());
                string fullPayload = $"{originalValue}{prefix} AND {payloadStr} {suffix} ";
                Logger.Process($"[TIME-BASED] Đang đo Baseline Ping cho tham số '{paramName}'...");

                // 1. LẤY BASELINE (3 MẪU ĐỂ LẤY TRUNG BÌNH & MAX)
                List<long> baselineDelays = new List<long>();
                for (int i = 0; i < 3; i++)
                {
                    var (success, ms, _) = await SendRequestWithTimingAsync(target, paramName, originalValue);
                    if (success) baselineDelays.Add(ms);
                }

                if (baselineDelays.Count == 0) return DbType.Unknow; // Mất mạng
                long maxBaseline = baselineDelays.Max();
                long avgBaseline = (long)baselineDelays.Average();

                // Nếu mạng quá lag (Baseline bình thường mà mất tới > 3-4 giây), thì không thể test Time-based (rất dễ False Positive)
                if (avgBaseline > 4000)
                {
                    Logger.Warning($"Mạng quá chậm (Ping ~{avgBaseline}ms). Bỏ qua Time-Based để tránh False Positive.");
                    return DbType.Unknow;
                }

                // TÍNH TOÁN NGƯỠNG (THRESHOLD): Thời gian delay tối đa của mạng + Thời gian Sleep (trừ hao 500ms sai số)
                long thresholdMs = maxBaseline + sleepMilliseconds - 500;

                Logger.Process($"[TIME-BASED] Baseline TB: {avgBaseline}ms | Ngưỡng xác nhận (Threshold): >= {thresholdMs}ms");

                // 2. GỬI PAYLOAD TRUE (CÓ LỆNH SLEEP)
                Logger.Process($"[>] Gửi Payload Sleep: {fullPayload}");
                var sleepResponse = await SendRequestWithTimingAsync(target, paramName, fullPayload);

                if (sleepResponse.elapsedMs >= thresholdMs || (!sleepResponse.isSuccess && sleepResponse.elapsedMs >= sleepMilliseconds))
                {
                    Logger.Warning($"[!] Phát hiện độ trễ bất thường: {sleepResponse.elapsedMs}ms. Đang Double-Check...");
                    // Gửi lại Baseline gốc một lần nữa. Nếu nó trả về NHANH, chứng tỏ lệnh Sleep vừa nãy là thật chứ không phải do Server Lag.
                    var doubleCheck = await SendRequestWithTimingAsync(target, paramName, originalValue);

                    if (doubleCheck.isSuccess && doubleCheck.elapsedMs <= maxBaseline + 1000) // Cho phép xê dịch 1s
                    {
                        DbType dbType = GetDbTypeFromString(payloads.DBMS);
                        return dbType;
                    }
                    else
                    {
                        Logger.Warning("Double-Check thất bại (Server đang bị Lag thực sự). Hủy báo động giả.");
                    }
                }
            }
            return DbType.Unknow;
        }

        private bool IsSimilar(string html1, string html2, int length1,
                               int length2, double tolerancePercent)
        {
            if (length1 == length2 && html1 == html2)
                return true;

            int maxLength = Math.Max(length1, length2);
            if (maxLength == 0)
                return true;

            // Kiểm tra dung lượng từ 2 response
            double diffRatio = (double)Math.Abs(length1 - length2) / maxLength;

            if (diffRatio > tolerancePercent)
            {
                return false;
            }

            // Độ lệch ít, nghi ngờ là do dynamic content nên cần kiểm tra nội dung text thô từ html
            // Kiểm tra nội dung từ 2 response
            double similarity = GetContentSimilarity(html1, html2);
            return similarity >= (1.0 - tolerancePercent);
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

        private DbType GetDbTypeFromString(string dbmsName)
        {
            string name = dbmsName?.ToLower() ?? "";
            if (name.Contains("mysql")) return DbType.MySQL;
            if (name.Contains("mssql") || name.Contains("sql server")) return DbType.MSSQL;
            if (name.Contains("postgresql")) return DbType.PostgreSQL;
            if (name.Contains("oracle")) return DbType.Oracle;
            if (name.Contains("sqlite")) return DbType.SQLite;

            return DbType.Unknow;
        }
        #endregion
    }
}