package org.jeecg.config.shiro.filters;

import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter;
import org.jeecg.common.constant.CommonConstant;
import org.jeecg.common.system.util.JwtUtil;
import org.jeecg.common.util.oConvertUtils;
import org.jeecg.config.mybatis.TenantContext;
import org.jeecg.config.shiro.JwtToken;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @Description: 鉴权登录拦截器
 * @Author: Scott
 * @Date: 2018/10/7
 **/
@Slf4j
public class JwtFilter extends BasicHttpAuthenticationFilter {

    /**
     * 执行登录认证
     *
     * @param request
     * @param response
     * @param mappedValue
     * @return
     */
    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
        try {
            executeLogin(request, response);
            return true;
        } catch (Exception e) {
            JwtUtil.responseError(response,401,CommonConstant.TOKEN_IS_INVALID_MSG);
            return false;
            //throw new AuthenticationException("Token失效，请重新登录", e);
        }
    }

    /**
     *
     */
    @Override
    protected boolean executeLogin(ServletRequest request, ServletResponse response) throws Exception {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        String token = httpServletRequest.getHeader(CommonConstant.X_ACCESS_TOKEN);
        // update-begin--Author:lvdandan Date:20210105 for：JT-355 OA聊天添加token验证，获取token参数
        if (oConvertUtils.isEmpty(token)) {
            token = httpServletRequest.getParameter("token");
        }
        // update-end--Author:lvdandan Date:20210105 for：JT-355 OA聊天添加token验证，获取token参数

        JwtToken jwtToken = new JwtToken(token);
        // 提交给realm进行登入，如果错误他会抛出异常并被捕获
        getSubject(request, response).login(jwtToken);
        // 如果没有抛出异常则代表登入成功，返回true
        return true;
    }

    /**
     * 对跨域提供支持
     */
    @Override
    protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        HttpServletResponse httpServletResponse = (HttpServletResponse) response;
        //update-begin-author:taoyan date:20200708 for:多租户用到
        String tenant_id = httpServletRequest.getHeader(CommonConstant.TENANT_ID);
        TenantContext.setTenant(tenant_id);
        //update-end-author:taoyan date:20200708 for:多租户用到
        return super.preHandle(request, response);
    }
}
