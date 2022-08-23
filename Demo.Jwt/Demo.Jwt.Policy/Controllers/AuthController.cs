using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Demo.Jwt.Policy.Controllers
{
    public class AuthController : Controller
    {
        [AllowAnonymous]
        [HttpGet]
        [Route("api/nopermission")]
        public IActionResult NoPermission()
        {
            return Forbid("No Permission!");
        }

        [AllowAnonymous]
        [HttpGet("GetToken")]
        public IActionResult Get(string userName, string pwd)
        {
            if (CheckAccount(userName, pwd, out string role))
            {
                //获取在配置文件中获取Jwt属性设置
                string secretKey = Appsettings.app(new string[] { "JwtSettings", "SecurityKey" });
                string issuer = Appsettings.app(new string[] { "JwtSettings", "Issuer" });
                string audience = Appsettings.app(new string[] { "JwtSettings", "Audience" });
                // 这里可以随意加入自定义的参数，key可以自己随便起
                var claims = new[]
                {
                    new Claim(JwtRegisteredClaimNames.Nbf,$"{new DateTimeOffset(DateTime.Now).ToUnixTimeSeconds()}") ,
                    new Claim (JwtRegisteredClaimNames.Exp,$"{new DateTimeOffset(DateTime.Now.AddMinutes(30)).ToUnixTimeSeconds()}"),
                    new Claim(ClaimTypes.Name, userName),
                    new Claim(ClaimTypes.Role, role)
                };
                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
                var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
                var token = new JwtSecurityToken(
                    issuer: issuer,//颁发者
                    audience: audience,//接收者
                    claims: claims,//自定义参数
                    expires: DateTime.Now.AddMinutes(30),//过期时间
                    signingCredentials: creds//签名证书
                    );

                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(token)
                });
            }
            else
            {
                return BadRequest(new { message = "username or password is incorrect." });
            }
        }

        /// <summary>
        /// 模拟登陆校验，因为是模拟，所以逻辑很‘模拟’
        /// </summary>
        /// <param name="userName"></param>
        /// <param name="pwd"></param>
        /// <param name="role"></param>
        /// <returns></returns>
        private bool CheckAccount(string userName, string pwd, out string role)
        {
            role = "user";

            if (string.IsNullOrEmpty(userName) || string.IsNullOrEmpty(pwd))
                return false;

            if (userName.Equals("admin"))
                role = "admin";

            return true;
        }
    }
}
