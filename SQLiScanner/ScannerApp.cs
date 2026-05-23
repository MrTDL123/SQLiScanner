using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using SQLiScanner.Models;
using SQLiScanner.Modules;
using SQLiScanner.Utility;
using Spectre.Console;
using SQLiScanner.Models.Enums;

namespace SQLiScanner
{

    public class ScannerApp
    {
        private readonly Crawler _crawler;
        private readonly DatabaseDetector _dbDetector;
        private readonly UnionDetector _unionDetector;
        private readonly AiConcurrencyEngine _aiEngine;
        public ScannerApp(
            Crawler crawler,
            DatabaseDetector dbDetector,
            UnionDetector unionDetector,
            AiConcurrencyEngine aiEngine)
        {
            _crawler = crawler;
            _dbDetector = dbDetector;
            _unionDetector = unionDetector;
            _aiEngine = aiEngine;
        }

        public async Task RunAsync()
        {
            Logger.IsMuted = true;

            AnsiConsole.MarkupLine("[bold green]==SQLi SCANNER DEMO v1.2==[/]");
            var (url, maxDepth) = GetUserInput();
            if (string.IsNullOrEmpty(url)) return;

            bool isEarlyExit = AnsiConsole.Confirm("Bạn có muốn dừng ngay khi tìm thấy lỗi đầu tiên (Early Exit)?", defaultValue: true);
            var scanConfig = new ScanConfig(isEarlyExit);
            Console.CancelKeyPress += (sender, e) =>
            {
                AnsiConsole.MarkupLine("\n[bold red][!] Nhận lệnh hủy từ người dùng. Đang dừng các luồng an toàn...[/]");
                scanConfig.Cts.Cancel(); // Bóp cò CancellationToken
                e.Cancel = true;
            };
            AnsiConsole.MarkupLine($"[bold blue][/] Đang bắt đầu quét tại: [underline]{url}[/] (Độ sâu: {maxDepth})");

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
                    BaseUrl = "http://testasp.vulnweb.com/Login.asp",
                    HttpMethod = "POST",
                    IsForm = true,
                    Params = new()
                    {
                        { "tfUName", "admin" },
                        { "tfUPass", "Admin@123"}
                    },
                    RawQueryString = "RetURL=%2FDefault.asp%3F"
                },

                new()
                {
                    BaseUrl = "http://testasp.vulnweb.com/showforum.asp",
                    HttpMethod = "GET",
                    IsForm = false,
                    Params = new()
                    {
                        { "id", "0" }
                    },
                    RawQueryString = "id=0"
                },
            };

            // Bắt đầu cho chạy chờ đọc request từ luồng chính nếu cần AI phân tích
            _aiEngine.StartWorkers();

            var sharedTrackingStates = new List<PayloadState>();

            await RenderLiveScanTableAsync(sharedTrackingStates, async () =>
            {
                foreach (var target in targets)
                {
                    if (scanConfig.Token.IsCancellationRequested) break;
                    await _dbDetector.DetectAsync(target, sharedTrackingStates, scanConfig);

                    List<DetectionResult> targetResults = scanConfig.DetectionResults
                        .Where(r => r.VulnerableURL == target.BaseUrl
                                    && r.HttpMethod == target.HttpMethod
                                    && !r.IsExpointable).ToList();
                    foreach (var result in targetResults)
                    {
                        if (scanConfig.Token.IsCancellationRequested) break;
                        PayloadState? vulnerableState = sharedTrackingStates.FirstOrDefault(t =>
                            t.TargetUrl == result.VulnerableURL &&
                            t.ParamName == result.VulnerableParam &&
                            t.Status == ScanStatus.Vulnerable);

                        if (vulnerableState == null) continue;

                        int colCount = await _unionDetector.GetColumnCountAsync(target, result, vulnerableState);
                        if (colCount > 0)
                        {
                            var visibleCols = await _unionDetector.GetVisibleColumnsAsync(target, result, colCount, vulnerableState);
                            if (visibleCols.Count > 0)
                            {
                                string colInfo = string.Join(", ", visibleCols);
                                vulnerableState.UpdateStatus(ScanStatus.Dangerous, $"[Khai thác thành công] Cột text: {colInfo} / Tổng: {colCount}");
                                result.IsExpointable = true;
                            }
                            else
                            {
                                vulnerableState.UpdateStatus(ScanStatus.Vulnerable, $"Có {colCount} cột nhưng không cột nào chứa Text");
                            }
                        }
                        else
                        {
                            vulnerableState.UpdateStatus(ScanStatus.Vulnerable, "Lỗi WAF/Logic: Không đếm được số cột");
                        }
                    }
                }

                // Dừng việc chờ đọc request phân tích bằng AI
                await _aiEngine.StopAndWaitAsync();
            });

            Logger.IsMuted = false;

            var finalResults = scanConfig.DetectionResults.ToList();

            if (scanConfig.Token.IsCancellationRequested)
            {
                AnsiConsole.MarkupLine("[bold yellow] Quá trình quét đã bị hủy giữa chừng![/]");
            }

            if (finalResults.Count > 0)
            {
                AnsiConsole.MarkupLine("\n[bold green] QUÁ TRÌNH QUÉT KẾT THÚC. PHÁT HIỆN LỖ HỔNG![/]");
                Logger.SummaryResults(finalResults);
            }
            else
            {
                AnsiConsole.MarkupLine("\n[bold grey]Hoàn thành quét. Không phát hiện lỗ hổng có thể khai thác.[/]");
            }

            Console.ReadLine();
        }

        private async Task RenderLiveScanTableAsync(List<PayloadState> trackingList, Func<Task> scanLogic)
        {
            var table = new Table().Border(TableBorder.Rounded).Expand();
            table.AddColumn("[cyan bold]Target[/]");
            table.AddColumn("[magenta bold]Payload[/]");
            table.AddColumn(new TableColumn("[yellow bold]Status[/]").Centered());
            table.AddColumn("[white bold]Reason[/]");

            table.ShowRowSeparators();
            // Frame của loading animation
            string[] spinnerFrames = { "/", "-", "\\", "|" };
            int frameIndex = 0;

            await AnsiConsole.Live(table)
                .AutoClear(false)
                .Overflow(VerticalOverflow.Ellipsis)
                .StartAsync(async tableLive =>
                {
                    Task scanTask = scanLogic();
                    while (!scanTask.IsCompleted)
                    {
                        UpdateTableContent(table, trackingList, spinnerFrames[frameIndex]);
                        tableLive.Refresh();

                        // Xoay animaiton loading
                        frameIndex = (frameIndex + 1) % spinnerFrames.Length;
                        // Update mỗi 100ms
                        await Task.Delay(100);
                    }

                    UpdateTableContent(table, trackingList, " ");
                    tableLive.Refresh();

                    if (scanTask.IsFaulted && scanTask.Exception != null)
                    {
                        throw scanTask.Exception;
                    }
                });
        }

        private void UpdateTableContent(Table table, List<PayloadState> trackingList, string spinner)
        {
            table.Rows.Clear();
            var activeState = trackingList.Where(s => s.Status != ScanStatus.Pending).TakeLast(50);

            foreach (var state in activeState)
            {
                string statusMarkup = state.Status switch
                {
                    ScanStatus.HeuristicScanning => $"[yellow]{spinner} Scanning[/]",
                    ScanStatus.AiAnalyzing => $"[blue]{spinner} AI Analyzing[/]",
                    ScanStatus.Vulnerable => "[red blink bold]VULNERABLE[/]",
                    ScanStatus.Safe => "[green]Safe[/]",
                    ScanStatus.Error => "[grey]Error[/]",
                    ScanStatus.CheckingColumnCount => $"[magenta]{spinner} Counting Columns[/]",
                    ScanStatus.ExploitingData => $"[darkorange]{spinner} Extracting Data[/]",
                    ScanStatus.Dangerous => "[red on yellow blink bold] DANGEROUS EXPLOIT [/]",
                    _ => $"[grey]{state.Status}[/]"
                };

                table.AddRow(
                    // Vì các URL và Payload có rất nhiều kì tự đặc biệt khiến cho việc phân tích văn bản gây nhiễu
                    // nên ta cần thêm Markup.Escape để mã hóa thành dạng an toàn
                    $"[dim]{Markup.Escape(state.TargetUrl)}[/]",
                    $"[bold]{Markup.Escape(state.Payload)}[/]",
                    statusMarkup,
                    Markup.Escape(state.ResultReason)
                );
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