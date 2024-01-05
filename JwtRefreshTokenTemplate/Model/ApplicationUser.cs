using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace JwtRefreshTokenTemplate.Model
{
    public class ApplicationUser : IdentityUser 
    {
        [Required, MaxLength(60)]
        public string FirstName { get; set; }

        [Required, MaxLength(60)]
        public string LastName { get; set; }
        public  List<RefreshToken>? refreshTokens { get; set; }

    }
}
