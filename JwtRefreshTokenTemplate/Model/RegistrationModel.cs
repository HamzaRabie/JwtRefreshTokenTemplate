using System.ComponentModel.DataAnnotations;

namespace JwtRefreshTokenTemplate.Model
{
    public class RegistrationModel
    {
        [Required, StringLength(100)]
        public string FirstName { get; set; }
        [Required, StringLength(100)]
        public string LastName { get; set; }
        [Required, StringLength(100)]
        public string UserName { get; set; }
        [Required, StringLength(30)]
        public string Password { get; set; }
        [Required, StringLength(50)]
        public string Email { get; set; }

    }
}
