using System;
using System.Threading.Tasks;
using DatingApp.API.Models;
using Microsoft.EntityFrameworkCore;

namespace DatingApp.API.Data
{
    public class AuthRepository : IAuthRepository
    {
        /* DATA FIELDS */
        private readonly DataContext _context;

        /* METHODS */
        public AuthRepository(DataContext context)
        {
            _context = context;   
        }

        public async Task<User> Login(string username, string password)
        {
            // 
            var user = await _context.Users.FirstOrDefaultAsync(x => x.Username == username);
            // if no user return null
            if(user == null) return null;
            // if user is a valid user then check password
            if(!VerifyPasswordHash(password, user.PasswordHash, user.PasswordSalt)) return null;
            // if user is not null and password is verified return the user object
            return user;
        }
        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using (var hmac = new System.Security.Cryptography.HMACSHA512(passwordSalt))
            {
                //compute Hash using password
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                //iterate through byte arrays and compare each element
                for(int i=0; i<computedHash.Length; i++)
                {
                    // if bits do not match at index i then incorrect password and return false
                    if(computedHash[i] != passwordHash[i]) return false;
                }
            }
            // loop completes on match, return true
            return true;
        }

        public async Task<User> Register(User user, string password)
        {
            byte[] passwordHash, passwordSalt; //local variables to store our derived hash and salt
            CreatePasswordHash(password, out passwordHash, out passwordSalt); //hash and salt passedByReference 

            user.PasswordHash = passwordHash; //assign derived hash to user
            user.PasswordSalt = passwordSalt; //assign derived 

            await _context.Users.AddAsync(user);
            await _context.SaveChangesAsync();

            return user;
        }
        // PRIVATE HELPER METHOD : derives passwordHash and passwordSalt -- CALLED BY: Register method
        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using (var hmac = new System.Security.Cryptography.HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        public async Task<bool> UserExists(string username)
        {
            if (await _context.Users.AnyAsync(x => x.Username == username))
                return true;
            return false;
        }
    }
}