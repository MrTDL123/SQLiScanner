using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using SQLiScanner.Models;
using SQLiScanner.Modules;
using SQLiScanner.Utility;

namespace SQLiScanner
{

    public class ScannerApp
    {
        private readonly Crawler _crawler;
        private readonly DatabaseDetector _dbDetector;
        private readonly UnionDetector _unionDetector;
        public ScannerApp(
            Crawler crawler,
            DatabaseDetector dbDetector,
            UnionDetector unionDetector)
        {
            _crawler = crawler;
            _dbDetector = dbDetector;
            _unionDetector = unionDetector;
        }

        public async Task RunAsync()
        {
            Console.WriteLine("==SQLi SCANNER DEMO v1.2==");
            var (url, maxDepth) = GetUserInput();
            if (string.IsNullOrEmpty(url)) return;

            Console.WriteLine($"[+] Đang bắt đầu quét tại: {url} (Độ sâu: {maxDepth})");

            // Crawler tìm mục tiêu
            List<CrawlResult> targets = await _crawler.CrawlAsync(url, maxDepth);
            if (targets.Count == 0)
            {
                Console.WriteLine("[-] Không tìm thấy URL tiềm năng.");
                return;
            }

            List<CrawlResult> targetsDemo = new()
            {
                new()
                {
                    FullUrl = "http://testasp.vulnweb.com/Login.asp?RetURL=%2FDefault%2Easp%3F",
                    HttpMethod = "POST",
                    IsForm = true,
                    Params = new()
                    {
                        { "tfUName", "admin" },
                        { "tfUPass", "Admin@123"}
                    }
                },

                new()
                {
                    FullUrl = "http://testasp.vulnweb.com/showforum.asp?id=0",
                    HttpMethod = "GET",
                    IsForm = false,
                    Params = new()
                    {
                        { "id", "0" }
                    }
                }

            };
            // DatabaseDetecotr xác định database và UnionDetector khai thác
            List<DetectionResult> results = new();
            foreach (var target in targetsDemo)
            {
                DetectionResult result = await _dbDetector.DetectAsync(target);

                if (result.IsVulnerable)
                {
                    int colCount = await _unionDetector.GetColumnCountAsync(target, result);
                    if (colCount > 0)
                    {
                        var visibleCols = await _unionDetector.GetVisibleColumnsAsync(target, result, colCount);
                        if (visibleCols.Count > 0)
                        {
                            result.IsExpointable = true;
                            results.Add(result);
                            Console.WriteLine("[***] EXPLOIT THÀNH CÔNG!");
                        }
                    }
                }
            }
            if (results.Count > 0)
            {
                Logger.SummaryResults(results);
            }
        }

        private (string? url, int depth) GetUserInput()
        {
            Console.Write("Nhập địa chỉ URL: ");
            string? url = Console.ReadLine();
            Console.Write("Nhập độ sâu (0=vô hạn, default=1): ");
            string? depthStr = Console.ReadLine();

            int depth = depthStr switch
            {
                "0" or "all" or "full" => int.MaxValue,
                _ => int.TryParse(depthStr, out int d) ? d : 1
            };

            return (url, depth);
        }
    }
}