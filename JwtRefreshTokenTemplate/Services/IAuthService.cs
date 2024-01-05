using JwtRefreshTokenTemplate.Model;

namespace JwtRefreshTokenTemplate.Services
{
    public interface IAuthService
    {
        Task<AuthModel> Register(RegistrationModel user);
        Task<AuthModel> Login(LoginUSerModel user);
        Task<AuthModel> RefreshToken(string refreshToken);
        Task<bool> RevokeToken(string refreshToken);
    }
}
