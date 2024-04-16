using Exo.WebApi.Models;
using Exo.WebApi.Repositories;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace Exo.WebApi.Controllers
{
    [Produces("application/json")]
    [Route("api/[controller]")]
    [ApiController]

    public class UsuariosController : ControllerBase
    {
        private readonly UsuarioRepository _usuarioRepository;

        public UsuariosController(UsuarioRepository usuarioRepository)
        {
            _usuarioRepository = usuarioRepository;
        }


        //GET - CRUD de Usuários - /api/usuarios
        [HttpGet]
        public IActionResult Listar()
        {
            return Ok(_usuarioRepository.Listar());
        }


        //POST - CRUD de Usuários - /api/usuarios
        // [HttpPost]
        // public IActionResult Cadastrar(Usuario usuario)
        // {
        //     _usuarioRepository.Cadastrar(usuario);
        //     return StatusCode(201);
        // }


        // Código POST para o método Login.
        public IActionResult Post(Usuario usuario)
        {
            Usuario usuarioBuscado = _usuarioRepository.Login(usuario.Email, usuario.Senha);
            if (usuarioBuscado == null)
            {
                return NotFound("E-mail ou senha inválidos!");
            }
            // No caso do usuário encontrado, o token é criado.
            // Dados que serão fornecidos no token - Payload.
            var claims = new[]
            {
                // Armazena o e-mail usuário autenticado na claim.
                new Claim(JwtRegisteredClaimNames.Email, usuarioBuscado.Email),
                // Armazena o id do usuário autenticado na claim.
                new Claim(JwtRegisteredClaimNames.Jti, usuarioBuscado.Id.ToString()),
            };
            // Chave de acesso ao token.
            var key = new
            SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes("exoapi-chaveautenticacao"));
            // Define as credenciais do token.
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            // Gera o token.
            var token = new JwtSecurityToken(
            issuer: "exoapi.webapi", // Emissor 
            audience: "exoapi.webapi", // Destinatário
            claims: claims, // Dados definidos
            expires: DateTime.Now.AddMinutes(30), // Tempo de expiração
            signingCredentials: creds // Credenciais do token
            );
            // Retorna ok com o token.
            return Ok(
            new { token = new JwtSecurityTokenHandler().WriteToken(token) }
            );
        }


        //GET - CRUD de Usuários - /api/usuarios{id}
        [HttpGet("{id}")]
        public IActionResult BuscarPorId(int id)
        {
            Usuario usuario = _usuarioRepository.BuscaPorId(id);
            if (usuario == null)
            {
                return NotFound();
            }
            return Ok(usuario);
        }

        //PUT- CRUD de Usuários - /api/usuarios{id}
        [Authorize]
        [HttpPut("{id}")]
        public IActionResult Atualizar(int id, Usuario usuario)
        {
            _usuarioRepository.Atualizar(id, usuario);
            return StatusCode(284);
        }


        //DELETE -CRUD de Usuários - /api/usuarios{id}
        [Authorize]
        [HttpDelete("{id}")]
        public IActionResult Deletar(int id)
        {
            try
            {
                _usuarioRepository.Deletar(id);
                return StatusCode(284);
            }
            catch (Exception e)
            {
                return BadRequest();
            }
        }
    }
}
