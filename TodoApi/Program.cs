using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.OpenApi.Models;
using MiniValidation;
using NetDevPack.Identity.Jwt;
using NetDevPack.Identity.Model;
using TodoApi.Data;
using TodoApi.Models;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<MinimalContextDb>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddIdentityEntityFrameworkContextConfiguration(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection"),
    b => b.MigrationsAssembly("TodoApi")));

builder.Services.AddIdentityConfiguration();
builder.Services.AddJwtConfiguration(builder.Configuration, "AppSettings");
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("ExcluirFornecedor",
        policy => policy.RequireClaim("ExcluirFornecedor"));
});

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
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
        {   new OpenApiSecurityScheme
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
    RegisterUser registeruser) =>
{
    if (registeruser == null)
        return Results.BadRequest("Usuário não informado");

    if (!MiniValidator.TryValidate(registeruser, out var errors))
        return Results.ValidationProblem(errors);

    var user = new IdentityUser
    {
        UserName = registeruser.Email,
        Email = registeruser.Email,
        EmailConfirmed = true
    };

    var result = await userManager.CreateAsync(user, registeruser.Password);

    if (!result.Succeeded)
        return Results.BadRequest(result.Errors);


    var jwt = new JwtBuilder()
        .WithUserManager(userManager)
        .WithEmail(user.Email)
        .WithJwtSettings(appJwtSettings.Value)
        .WithJwtClaims()
        .WithUserClaims()
        .WithUserRoles()
        .BuildUserResponse();

    return Results.Ok(jwt);
})
.ProducesValidationProblem()
.Produces<Fornecedor>(StatusCodes.Status200OK)
.Produces(StatusCodes.Status400BadRequest)
.WithName("RegistroUsuario")
.WithTags("Usuario");


app.MapPost("/login", [AllowAnonymous] async (
    SignInManager<IdentityUser> signInManager,
    UserManager<IdentityUser> userManager,
    IOptions<AppJwtSettings> appJwtSettings,
    LoginUser loginUser) =>
{
    if (loginUser == null)
        return Results.BadRequest("Usuario não informado");

    if (!MiniValidator.TryValidate(loginUser, out var errors))
        return Results.ValidationProblem(errors);

    var result = await signInManager.PasswordSignInAsync(loginUser.Email, loginUser.Password, false, false);

    if (result.IsLockedOut)
        return Results.BadRequest("Usuário bloqueados");

    if (!result.Succeeded)
        return Results.BadRequest("Usuário ou senha inválidos");

    var jwt = new JwtBuilder()
    .WithUserManager(userManager)
    .WithEmail(loginUser.Email)
    .WithJwtSettings(appJwtSettings.Value)
    .WithJwtClaims()
    .WithUserClaims()
    .WithUserRoles()
    .BuildUserResponse();

    return Results.Ok(jwt);
})
.ProducesValidationProblem()
.Produces<Fornecedor>(StatusCodes.Status200OK)
.Produces(StatusCodes.Status400BadRequest)
.WithName("LoginUsuario")
.WithTags("Usuario");


app.MapGet("/fornecedor", [AllowAnonymous] async (MinimalContextDb context) =>
    await context.Fornecedores.ToArrayAsync())
    .WithName("GetFornecedor")
    .WithTags("Fornecedor");

app.MapGet("/fornecedor/{id}", async (int id, MinimalContextDb context) =>
       await context.Fornecedores.FindAsync(id)
       is Fornecedor fornecedor
           ? Results.Ok(fornecedor)
           : Results.NotFound()
    )
    .Produces<Fornecedor>(StatusCodes.Status200OK)
    .Produces(StatusCodes.Status404NotFound)
    .WithName("GetFornecedorPorId")
    .WithTags("Fornecedor");

// Uma boa pratica é criar um modelo de entrada de daddos e outro de saida
// E não expor da maneira que estamos fazendo. 
app.MapPost("/fornecedor", [Authorize] async (Fornecedor fornecedor, MinimalContextDb context) =>
{
    if (!MiniValidator.TryValidate(fornecedor, out var errors))
        return Results.ValidationProblem(errors);

    context.Fornecedores.Add(fornecedor);
    var result = await context.SaveChangesAsync();

    return result > 0
        //? Results.Created($"/fornecedor/{fornecedor.Id}", fornecedor)
        ? Results.CreatedAtRoute("GetFornecedorPorId", new { id = fornecedor.Id }, fornecedor)
        : Results.BadRequest("Erro ao salvar o registro");
})
.ProducesValidationProblem()
.Produces<Fornecedor>(StatusCodes.Status201Created) //metadado => Produces serve para documentação da api
.Produces(StatusCodes.Status400BadRequest)
.WithName("PostFornecedorPorId")
.WithTags("Fornecedor");

app.MapPut("/fornecedor/{id}", [Authorize] async (int id, Fornecedor fornecedor, MinimalContextDb context) =>
{
    var fornecedorBanco = await context.Fornecedores.AsNoTracking<Fornecedor>().FirstOrDefaultAsync(f => f.Id == id);
    if (fornecedorBanco == null) return Results.NotFound();

    if (!MiniValidator.TryValidate(fornecedor, out var errors))
        return Results.ValidationProblem(errors);

    context.Fornecedores.Update(fornecedor);
    var result = await context.SaveChangesAsync();

    return result > 0
        ? Results.NoContent()
        : Results.BadRequest("Ocorreu um problema ao alterar o registro");
})
.ProducesValidationProblem()
.Produces<Fornecedor>(StatusCodes.Status201Created)
.Produces(StatusCodes.Status400BadRequest)
.WithName("PutFornecedorPorId")
.WithTags("Fornecedor");

app.MapDelete("/fornecedor/{id}", [Authorize] async (int id, MinimalContextDb context) =>
{
    var fornecedor = await context.Fornecedores.FindAsync(id);
    if (fornecedor == null) return Results.NotFound();

    context.Fornecedores.Remove(fornecedor);
    var result = await context.SaveChangesAsync();

    return result > 0
        ? Results.NoContent()
        : Results.BadRequest("Ocorreu um problema ao deletar o registro");
})
.Produces<Fornecedor>(StatusCodes.Status400BadRequest)
.Produces<Fornecedor>(StatusCodes.Status204NoContent)
.Produces(StatusCodes.Status404NotFound)
.RequireAuthorization("ExcluirFornecedor")
.WithName("DeleteFornecedorPorId")
.WithTags("Fornecedor");

app.Run();
