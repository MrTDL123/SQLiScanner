using SQLiScanner.API.Models;

namespace SQLiScanner.API.Services
{
    public interface IResponseSimilarityService
    {
        Task<SimilarityResponse> AnalyzeAsync(SimilarityRequest request);
    }
}
