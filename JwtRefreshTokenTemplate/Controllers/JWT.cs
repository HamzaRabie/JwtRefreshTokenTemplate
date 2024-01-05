using JwtRefreshTokenTemplate.Model;
using JwtRefreshTokenTemplate.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace JwtRefreshTokenTemplate.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class JWT : ControllerBase
    {
        private readonly IAuthService service;

        public JWT(IAuthService service)
        {
            this.service = service;
        }



        [HttpPost("register")]
        public async Task<IActionResult> register(RegistrationModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var res = await service.Register(model);

            if (!res.IsAuthenticated)
                return BadRequest(res.Message);

            return Ok(res);

            SetRefreshToCookie(res.RefreshToken, res.RefreshTokenExpiration);
            return Ok();
        }

        [HttpPost("Login")]
        public async Task<IActionResult> Login(LoginUSerModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var res = await service.Login(model);
            if (!res.IsAuthenticated)
                return BadRequest(res.Message);

            if(!string.IsNullOrEmpty(res.RefreshToken))
                SetRefreshToCookie(res.RefreshToken, res.RefreshTokenExpiration);
            return Ok(res);

        }

        [Authorize]
        [HttpGet("testing")]
        public IActionResult test()
        {
            return Ok("hello Authorized User");
        }

        [HttpGet("refreshToken")]
        public async Task<IActionResult> RefreshToken()
        {
            var refreshToken = Request.Cookies["refreshToken"];
            var res = await service.RefreshToken(refreshToken);
            if(!res.IsAuthenticated )
                return BadRequest(res.Message);

            SetRefreshToCookie(res.RefreshToken, res.RefreshTokenExpiration);

            return Ok(res);
        }

        [HttpPost("revokeToken")]
        public async Task<IActionResult> RevokeToken(RefreshTokenModel model)
        {
            var token = model.token ?? Request.Cookies["refreshToken"];

            if (string.IsNullOrEmpty(token))
                return BadRequest("Send Refresh Token");

            var res = await service.RevokeToken(token);
            
            if(res==false)
                return BadRequest("Invalid TOken");

            return Ok("Token Is Revoked Successfully");

        }
        private void SetRefreshToCookie( string refreshToken , DateTime Expiration)
        {
            var cookieOptions = new CookieOptions()
            {
                HttpOnly = true,
                Expires = Expiration.ToLocalTime(),
            };
            Response.Cookies.Append("refreshToken", refreshToken, cookieOptions);
        }
    }
}
/*
 * {
  "firstName": "hamza",
  "lastName": "rabie",
  "userName": "Sp1",
  "password": "mmMM123@!",
  "email": "hamza@gmail.com"
}
 */ 