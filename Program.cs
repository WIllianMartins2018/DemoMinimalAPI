using DemoMinimalAPI.Data;
using DemoMinimalAPI.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.OpenApi.Models;
using MiniValidation;
using NetDevPack.Identity.Jwt;
using NetDevPack.Identity.Model;

var builder = WebApplication.CreateBuilder(args);


builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "Minimal API Sample",
        Description = "Developed by Willian",
        Contact = new OpenApiContact { Name = "Willian Martins"}
    });

    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "Insira o token JWT desta maneira: Bearer {seu token}",
        Name = "Authorization",
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            new string[] {}
        }
    });
});

builder.Services.AddDbContext<MinimalContextDb>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddIdentityEntityFrameworkContextConfiguration(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"),
        b => b.MigrationsAssembly("DemoMinimalAPI")));

builder.Services.AddIdentityConfiguration();
builder.Services.AddJwtConfiguration(builder.Configuration, "AppSettings");

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("DeleteFornecedor",
        policy => policy.RequireClaim("DeleteFornecedor"));

});


var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseAuthConfiguration();
app.UseHttpsRedirection();

app.MapPost("/registro", [AllowAnonymous] async (
    SignInManager<IdentityUser> signInManager,
    UserManager<IdentityUser> userManager,
    IOptions<AppJwtSettings> appJwtSettings,
    RegisterUser registerUser
    ) =>
{
    if (registerUser is null)
        return Results.BadRequest("Usuário Não Informado");

    if (!MiniValidator.TryValidate(registerUser, out var erros))
        return Results.ValidationProblem(erros);

    var user = new IdentityUser
    {
        UserName = registerUser.Email,
        Email = registerUser.Email,
        EmailConfirmed = true,
    };

    var result = await userManager.CreateAsync(user, registerUser.Password);

    if (!result.Succeeded)
        return Results.BadRequest(result.Errors);

    var jwt = new JwtBuilder()
                    .WithUserManager(userManager)
                    .WithJwtSettings(appJwtSettings.Value)
                    .WithEmail(user.Email)
                    .WithJwtClaims()
                    .WithUserClaims()
                    .WithUserRoles()
                    .BuildUserResponse();

    return Results.Ok(jwt);
})      
    .ProducesValidationProblem()
    .Produces(StatusCodes.Status200OK)
    .Produces(StatusCodes.Status400BadRequest)
    .WithName("RegistroUsuario")
    .WithTags("Usuario");

app.MapPost("/login", [AllowAnonymous] async
    (
    SignInManager<IdentityUser> signInManager,
    UserManager<IdentityUser> userManager,
    IOptions<AppJwtSettings> appJwtSettings,
    LoginUser loginUser
    ) =>
{
    if (loginUser is null)
        return Results.BadRequest("Usuário Não Informado");

    if (!MiniValidator.TryValidate(loginUser, out var erros))
        return Results.ValidationProblem(erros);

    var result = await signInManager.PasswordSignInAsync(loginUser.Email, loginUser.Password, false, true);

    if (result.IsLockedOut)
        return Results.BadRequest("Usuário Bloqueado");

    if (!result.Succeeded)
        return Results.BadRequest("Usuário ou Senha inválido");

    var jwt = new JwtBuilder()
                   .WithUserManager(userManager)
                    .WithJwtSettings(appJwtSettings.Value)
                    .WithEmail(loginUser.Email)
                    .WithJwtClaims()
                    .WithUserClaims()
                    .WithUserRoles()
                    .BuildUserResponse();

    return Results.Ok(jwt);
})
    .ProducesValidationProblem()
    .Produces(StatusCodes.Status200OK)
    .Produces(StatusCodes.Status400BadRequest)
    .WithName("LoginUsuario")
    .WithTags("Usuario");



app.MapGet("/fornecedor", [AllowAnonymous] async
    (
    MinimalContextDb context
    ) =>
    await context.Fornecedors.ToListAsync())
    .WithName("GetFornecedor")
    .WithTags("Fornecedor");

app.MapGet("/fornecedor/{id}", [Authorize] async
    (
    MinimalContextDb context,
    Guid id
    ) =>
    await context.Fornecedors.FindAsync(id)
        is Fornecedor fornecedor
            ? Results.Ok(fornecedor)
            : Results.NotFound())
    .Produces<Fornecedor>(StatusCodes.Status200OK)
    .Produces(StatusCodes.Status404NotFound)
    .WithName("GetFornecedorPorId")
    .WithTags("Fornecedor");


app.MapPost("/fornecedor", [Authorize] async
    (
    MinimalContextDb context,
    Fornecedor fornecedor
    ) =>
{
    if (!MiniValidator.TryValidate(fornecedor, out var erros))
        return Results.ValidationProblem(erros);

    context.Fornecedors.Add(fornecedor);
    var result = await context.SaveChangesAsync();

    return result > 0 ?
        //Results.Created($"/fornecedor/{fornecedor.Id}", fornecedor) 
        Results.CreatedAtRoute("GetFornecedorPorId", new { id = fornecedor.Id }, fornecedor) :
        Results.BadRequest("Houve um problema ao salvar o registro");
})
    .ProducesValidationProblem()
    .Produces<Fornecedor>(StatusCodes.Status201Created)
    .Produces(StatusCodes.Status404NotFound)
    .WithName("PostFornecedor")
    .WithTags("Fornecedor");

app.MapPut("/fornecedor/{id}", [Authorize]  async
    (
    Guid id,
    MinimalContextDb context,
    Fornecedor fornecedor
    ) =>
{
    var forncedorBanco = await context.Fornecedors.AsNoTracking<Fornecedor>()
                                                .FirstOrDefaultAsync(f => f.Id == id);
    if (forncedorBanco == null) return Results.NotFound();

    if (!MiniValidator.TryValidate(fornecedor, out var erros))
        return Results.ValidationProblem(erros);

    context.Fornecedors.Update(fornecedor);
    var result = await context.SaveChangesAsync();

    return result > 0
        ? Results.NoContent()
        : Results.BadRequest("Houve um problema ao alterar o registro");
})
    .ProducesValidationProblem()
    .Produces(StatusCodes.Status204NoContent)
    .Produces(StatusCodes.Status400BadRequest)
    .WithName("PutFornecedor")
    .WithTags("Fornecedor");

app.MapDelete("/fornecedor/{id}", [Authorize] async
    (
    Guid id,
    MinimalContextDb context
    ) =>
{
    var fornecedor = await context.Fornecedors.FindAsync(id);
    if (fornecedor == null) return Results.NotFound();

    context.Fornecedors.Remove(fornecedor);
    var result = await context.SaveChangesAsync();

    return result > 0
        ? Results.NoContent()
        : Results.BadRequest("Houve um problema ao remover o registro");
})
    .Produces(StatusCodes.Status204NoContent)
    .Produces(StatusCodes.Status400BadRequest)
    .Produces(StatusCodes.Status404NotFound)
    .RequireAuthorization("DeleteFornecedor")
    .WithName("DeleteFornecedor")
    .WithTags("Fornecedor");


app.Run();

