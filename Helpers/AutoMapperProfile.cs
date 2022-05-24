using AuthenticationAPI.Entities;
using AuthenticationAPI.Models;
using AutoMapper;

namespace AuthenticationAPI.Helpers
{
    public class AutoMapperProfile: Profile
    {
        // mappings between model and entity objects
        public AutoMapperProfile()
        {
            CreateMap<Account, AccountResponse>();

        }
    }
}
