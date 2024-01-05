using Microsoft.EntityFrameworkCore.Metadata.Conventions;
using System.Text.Json.Serialization;

namespace JwtRefreshTokenTemplate.Model
{
    public class AuthModel
    {
        public  String UserName { get; set; }
        public   string Email { get; set; }
        public List<string> Roles { get; set; }
        public string Message { get; set; }
        public bool IsAuthenticated { get; set; }
        public string Token{ get; set; }
        public DateTime TokenExpiration { get; set; }

        [JsonIgnore]
        public  string? RefreshToken { get; set; }
        public DateTime RefreshTokenExpiration { get; set; }

    }
}
