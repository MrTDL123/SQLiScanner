using DataSchema;
using SQLiScanner.Models;
using SQLiScanner.Models.Enums;
using SQLiScanner.Services;
using System.Threading.Channels;

namespace SQLiScanner.Utility
{
    public readonly struct AiWorkItem
    {
        public AiContextRequestPayload PayloadData { get; }
        public TaskCompletionSource<bool> CompletionSource { get; }
        // Action dùng để trả kết quả về DatabaseDetector nếu việc phân tích hoàn thành
        public Action<AiContextResponse> OnCompleted { get; }

        public AiWorkItem(
            AiContextRequestPayload data, 
            TaskCompletionSource<bool> tcs,
            Action<AiContextResponse> onCompleted)
        {
            PayloadData = data;
            CompletionSource = tcs;
            OnCompleted = onCompleted;
        }
    }

    public class AiConcurrencyEngine
    {
        private readonly Channel<AiWorkItem> _channel = Channel.CreateBounded<AiWorkItem>(
            new BoundedChannelOptions(50)
            {
                // Nếu đầy, người gửi (luồng Heuristic) sẽ bị chặn lại (Wait) cho đến khi có slot trống
                FullMode = BoundedChannelFullMode.Wait
            });

        private readonly IAiApiClient _aiApiClient;
        private readonly int _maxWorkers;
        private readonly List<Task> _workers = new();

        public AiConcurrencyEngine(IAiApiClient aiApiClient, int maxWorkers = 3)
        {
            _aiApiClient = aiApiClient;
            _maxWorkers = maxWorkers;
        }

        public void StartWorkers()
        {
            for (int i = 0; i < _maxWorkers; i++)
            {
                _workers.Add(Task.Run(ProcessQueueAsync));
            }
        }

        public Task EnqueueAnalysisAsync(
            AiContextRequestPayload data,
            Action<AiContextResponse> onCompleted)
        {   
            // tcs dùng để báo hiệu task đã hoàn thành
            var tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            var workItem = new AiWorkItem(data, tcs, onCompleted);

            // Ghi vào Channel (Nếu đầy 50, nó sẽ tự động await đợi ở đây)
            _ = _channel.Writer.WriteAsync(workItem);

            // Cần phải đợi flag từ TaskCompletionSource được gán vào item 
            return tcs.Task;
        }

        private async Task ProcessQueueAsync()
        {
            // Vòng lặp vĩnh cửu: Chờ và đọc liên tục từ Channel
            await foreach (var item in _channel.Reader.ReadAllAsync())
            {
                try
                {
                    var response = await _aiApiClient.AnalyzeSqlInjectionAsync(item.PayloadData);

                    // Kích hoạt flag đẻ producer có thể kết thúc luồng
                    item.OnCompleted?.Invoke(response);
                    item.CompletionSource.TrySetResult(true);
                }
                catch (Exception ex)
                {
                    item.CompletionSource.TrySetException(ex);
                }
            }
        }

        // Khi quét xong toàn bộ app, gọi hàm này để dọn dẹp an toàn
        public async Task StopAndWaitAsync()
        {
            _channel.Writer.Complete();
            await Task.WhenAll(_workers);
        }
    }
}