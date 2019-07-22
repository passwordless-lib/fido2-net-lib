using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Fido2Demo.Pages
{
    public class dashboardModel : PageModel
    {
        public void OnGet(string username)
        {
            this.Username = username;
        }

        public string Username { get; set; }
    }
}
