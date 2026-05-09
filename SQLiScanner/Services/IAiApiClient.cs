using DataSchema;
using System.Threading.Tasks;

namespace SQLiScanner.Services
{
    public interface IAiApiClient
    {
        Task<AiContextResponse> AnalyzeSqlInjectionAsync(AiContextRequestPayload payload);
    }
}