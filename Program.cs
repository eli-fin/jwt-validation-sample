using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

// accept token from the following tenant with the following subject (i.e., managed identity's object ID) only
const string TOKEN_TENANT = "<TENANT_ID>";
const string TOKEN_SUBJECT = "<SUBJECT_ID>";

var openIdConfig = await OpenIdConnectConfigurationRetriever.GetAsync(
        $"https://sts.windows.net/{TOKEN_TENANT}/.well-known/openid-configuration",
        CancellationToken.None);

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultSignInScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(o =>
{
    // validate issuer (tenant), signature and subject
    o.TokenValidationParameters = new TokenValidationParameters
    {
        ValidIssuer = openIdConfig.Issuer,
        ValidateIssuer = true,
        ValidateAudience = false,
        ValidateLifetime = true,
        IssuerSigningKeys = openIdConfig.SigningKeys,
        SignatureValidator = (token, validationParameters) =>
        {
            var jwt = new JsonWebToken(token);
            if (jwt.Subject != TOKEN_SUBJECT)
            {
                throw new SecurityTokenValidationException("unauthorized_subject");
            }
            return jwt;
        }
    };
});
builder.Services.AddAuthorization();

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/hi", (HttpContext context) => "Success").RequireAuthorization();

app.Run();
