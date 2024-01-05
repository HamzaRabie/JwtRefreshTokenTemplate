using JwtRefreshTokenTemplate.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualBasic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using JwtRefreshTokenTemplate.Settings;
using JwtRefreshTokenTemplate.Controllers;

namespace JwtRefreshTokenTemplate.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> userManager;
        private readonly JwtOptions jwt;

        public AuthService(UserManager<ApplicationUser> userManager, IOptions<JwtOptions> jwt  )
        {
            this.userManager = userManager;
            this.jwt = jwt.Value;
        }

        public async Task<AuthModel> Login(LoginUSerModel model)
        {
            var authModel = new AuthModel();
            var user = await userManager.FindByEmailAsync(model.Email);

            if ( user is null || !await userManager.CheckPasswordAsync(user, model.Password))
            {
                return new AuthModel()
                {
                    Message = "Invalid Email Or Password"
                };
            }

            var JwtToken = await GenerateJWTtoken(user);
            var roles = await userManager.GetRolesAsync(user);

            authModel.Email = user.Email;
            authModel.UserName = user.UserName;
            authModel.IsAuthenticated = true;
            authModel.Token = new JwtSecurityTokenHandler().WriteToken(JwtToken);
            authModel.TokenExpiration = JwtToken.ValidTo;
            authModel.Roles = roles.ToList();

            if( user.refreshTokens.Any(t=>t.IsActive) )
            {
                var refreshToken = user.refreshTokens.FirstOrDefault(t=>t.IsActive);    
                authModel.RefreshToken = refreshToken.Token;
                authModel.RefreshTokenExpiration = refreshToken.ExpireOn;
            }
            else
            {
                var refreshToken =  GenerateRefreshToken();
                authModel.RefreshToken = refreshToken.Token;
                authModel.RefreshTokenExpiration = refreshToken.ExpireOn;
                user.refreshTokens.Add(refreshToken);
                await userManager.UpdateAsync(user);

            }

            return authModel;
        }

        public async Task<AuthModel> Register(RegistrationModel newUser)
        {
            var authModel = new AuthModel();
            if( await userManager.FindByEmailAsync(newUser.Email) != null )
            {
                return new AuthModel()
                {
                    Message = "Email Already Registered"
                };
            };

            if(await userManager.FindByNameAsync(newUser.UserName) != null )
            {
                return new AuthModel()
                {
                    Message = "UserName Is Already Registered"
                };
            };

            ApplicationUser user = new ApplicationUser()
            {

                UserName = newUser.UserName,
                Email = newUser.Email,
                FirstName = newUser.FirstName,
                LastName = newUser.LastName
            };


            var res = await userManager.CreateAsync(user , newUser.Password);
            if (!res.Succeeded)
            {
                var errors = string.Empty;
                foreach (var error in res.Errors)
                    errors += error.Description + " , ";
                return new AuthModel()
                {
                    Message = errors
                };
            }

            await userManager.AddToRoleAsync(user, "User");

            var JwtToken = await GenerateJWTtoken(user);

            var refreshToken =  GenerateRefreshToken();

            authModel.IsAuthenticated = true;
            authModel.Token = new JwtSecurityTokenHandler().WriteToken(JwtToken);
            authModel.Email= newUser.Email;
            authModel.UserName= newUser.UserName;
            //authModel.TokenExpiration = JwtToken.ValidTo;
            authModel.Roles = new List<string>() { "User" };
            authModel.RefreshToken = refreshToken.Token;
            authModel.RefreshTokenExpiration = refreshToken.ExpireOn;
            return authModel;
        }

        private async Task<JwtSecurityToken> GenerateJWTtoken(ApplicationUser user)
        {

            var userClaims = await userManager.GetClaimsAsync(user);
            var roles = await userManager.GetRolesAsync(user);
            List<Claim> roleList = new List<Claim>();

            var s = jwt.Key;

            foreach (var item in roles)
            {
                roleList.Add(new Claim( ClaimTypes.Role , item ));
            }

            var claims = new[]
            {
                new Claim( ClaimTypes.NameIdentifier, user.Id ),
                new Claim( ClaimTypes.Name , user.UserName ),
                new Claim( JwtRegisteredClaimNames.Jti , Guid.NewGuid().ToString()  ),
            }.Union(roleList)
            .Union(userClaims);

            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwt.Key));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

            var min = jwt.DurationInMinutes;

            var jwtToken = new JwtSecurityToken(
                issuer: jwt.Issuer,
                audience : jwt.Audience,
                expires : DateTime.UtcNow.AddMinutes(jwt.DurationInMinutes),
                claims:claims,
                signingCredentials : signingCredentials

                );

            return jwtToken;
        }

        private  RefreshToken GenerateRefreshToken()
        {
            var token = Guid.NewGuid().ToString();
            return new RefreshToken() {
                Token = token,
                CreatedOn = DateTime.UtcNow,
                ExpireOn = DateTime.UtcNow.AddDays(10)
            };

        }

        public async Task<AuthModel> RefreshToken(string userToken)
        {
            var user = await userManager.Users.SingleOrDefaultAsync(u => u.refreshTokens.Any(t => t.Token == userToken));
            if(user == null)
            {
                return new AuthModel()
                {
                    Message="Ivalid Token"
                };
            }

            var token = user.refreshTokens.Single(t=>t.Token== userToken);
            if( !token.IsActive )
            {
                return new AuthModel()
                {
                    Message = "Expired Token"
                };
            }

            token.RevokedOn = DateTime.UtcNow;

            var refreshToken =  GenerateRefreshToken();
            user.refreshTokens.Add(refreshToken);
            await userManager.UpdateAsync(user);

            var jwtToken = await GenerateJWTtoken(user);

            var roles = await userManager.GetRolesAsync(user);

            return new AuthModel()
            {
                Email = user.Email,
                IsAuthenticated = true,
                RefreshToken = refreshToken.Token,
                RefreshTokenExpiration = refreshToken.ExpireOn,
                Token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                UserName = user.UserName,
                Roles = roles.ToList(),
            };
        }

        public async Task<bool> RevokeToken(string refreshToken)
        {
            var user = await userManager.Users.SingleOrDefaultAsync( u=>u.refreshTokens.Any(u=>u.Token== refreshToken));
            if (user == null)
               return false;

            var token = user.refreshTokens.Single(t=>t.Token== refreshToken);
            if( !token.IsActive )
                return false;

           token.RevokedOn = DateTime.UtcNow;
            
            await userManager.UpdateAsync(user);
            
            return true;
           
        }

    }
}
