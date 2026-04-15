using System.Threading.Tasks;
using SQLiScanner.DTOs;

namespace SQLiScanner.Services
{
    public interface IAiApiClient
    {
        Task<AiContextResponse> AnalyzeSqlInjectionAsync(AiContextRequestPayload payload);
    }
}