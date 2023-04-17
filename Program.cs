using DemoMinimalAPI.Data;
using DemoMinimalAPI.Models;
using Microsoft.EntityFrameworkCore;
using MiniValidation;

var builder = WebApplication.CreateBuilder(args);


builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddDbContext<MinimalContextDb>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.MapGet("/fornecedor", async
    (
    MinimalContextDb context
    ) =>
    await context.Fornecedors.ToListAsync())
    .WithName("GetFornecedor")
    .WithTags("Fornecedor");

app.MapGet("/fornecedor/{id}", async
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


app.MapPost("/fornecedor", async
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

app.MapPut("/fornecedor/{id}", async
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

app.MapDelete("/fornecedor/{id}", async
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
    .WithName("DeleteFornecedor")
    .WithTags("Fornecedor");


app.Run();

