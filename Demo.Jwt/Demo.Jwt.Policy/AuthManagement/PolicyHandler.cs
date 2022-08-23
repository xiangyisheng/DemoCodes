using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace Demo.Jwt.Policy.AuthManagement
{
    public class PolicyHandler : AuthorizationHandler<PolicyRequirement>
    {
        /// <summary>
        /// 通过IHttpContextAccessor可以获取HttpContext相关信息，但一定要注册服务
        /// </summary>
        private readonly IHttpContextAccessor _accessor;
        /// <summary>
        ///  构造函数注入
        /// </summary>
        public PolicyHandler(IHttpContextAccessor accessor)
        {
            this._accessor = accessor;
        }

        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, PolicyRequirement requirement)
        {
            //赋值用户权限
            var userPermissions = requirement.UserPermissions;
            //从AuthorizationHandlerContext转成HttpContext，以便取出表求信息
            //拿到HttpContext就无所不能啦
            var httpContext = _accessor.HttpContext;
            //var httpContext = (context.Resource as Microsoft.AspNetCore.Mvc.Filters.AuthorizationFilterContext).HttpContext;
            //请求Url
            var questUrl = httpContext.Request.Path.Value.ToUpperInvariant(); 
            //是否经过验证
            var isAuthenticated = context.User.Identity.IsAuthenticated;
            if (isAuthenticated)
            {
                if (userPermissions.GroupBy(g => g.Url).Any(w => w.Key.ToUpperInvariant() == questUrl))
                {
                    //用户名
                    var userName = context.User.Claims.SingleOrDefault(s => s.Type == ClaimTypes.Name).Value;
                    if (userPermissions.Any(w => w.UserName == userName && w.Url.ToUpperInvariant() == questUrl))
                    {
                        context.Succeed(requirement);
                    }
                    else
                    {
                        //无权限跳转到拒绝页面
                        httpContext.Response.Redirect(requirement.DeniedAction);
                    }
                }
                else
                {
                    context.Succeed(requirement);
                }
            }
            return Task.CompletedTask;
        }
    }
}
