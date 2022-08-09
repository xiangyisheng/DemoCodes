namespace Demo.Jwt
{
    public class JWTSettings
    {
        public const string Position = "JWTSettings";
        public string SecretKey { get; set; }
        public string Issuer { get; set; }
        public string Audience { get; set; }
    }
}
