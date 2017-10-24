package com.sso.login.client.shiro.filter;

import com.alibaba.fastjson.JSONObject;
import com.github.pagehelper.util.StringUtil;
import com.sso.common.util.RedisUtil;
import com.sso.login.client.util.RequestParameterUtil;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DecompressingHttpClient;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.StringUtils;
import org.apache.shiro.web.filter.authc.AuthenticationFilter;
import org.apache.shiro.web.util.WebUtils;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by zhaokai on 2017/10/17.
 */
public class UpmsAuthenticationFilter extends AuthenticationFilter {

    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
        Subject subject = SecurityUtils.getSubject();
        return validateClient(request,response);
    }

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        StringBuffer loginUrl = new StringBuffer("http://localhost:8888/sso-login-web/sso/login");
        HttpServletRequest httpServletRequest = (HttpServletRequest)request;
        StringBuffer backUrl = httpServletRequest.getRequestURL();
        String queryString = httpServletRequest.getQueryString();
        if (StringUtil.isNotEmpty(queryString)){
            backUrl.append("?").append(queryString);
        }
        loginUrl.append("?").append("backurl=").append(URLEncoder.encode(backUrl.toString(),"utf-8"));
        HttpServletResponse httpServletResponse = (HttpServletResponse)response;
        httpServletResponse.sendRedirect(loginUrl.toString());
        return false;
    }

    private boolean validateClient(ServletRequest request,ServletResponse response){
        Subject subject = getSubject(request,response);
        Session session = subject.getSession();
        String currentSessionId = RedisUtil.get("sso_client_session_id"+"_"+session.getId().toString());
        if (StringUtils.hasText(currentSessionId)) {
            if (null != request.getParameter("code")) {
                if (StringUtils.hasText(currentSessionId)) {//已经保存对应session，移除url中code，转发目标url
                    String backurl = RequestParameterUtil.getParameterWithOutCode(WebUtils.toHttp(request));
                    HttpServletResponse response1 = WebUtils.toHttp(response);
                    try {
                        response1.sendRedirect(backurl);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            } else {
                return true;
            }
        }

        //判断是否有登录中心的code
        String code = request.getParameter("code");
        if (StringUtils.hasText(code)){
            try{
                HttpClient httpClient = new DefaultHttpClient();
                HttpPost httpPost = new HttpPost("http://localhost:8888/sso-login-web/sso/login/code");

                List<NameValuePair> nameValuePairList = new ArrayList<NameValuePair>();
                nameValuePairList.add(new BasicNameValuePair("code",code));
                httpPost.setEntity(new UrlEncodedFormEntity(nameValuePairList));

                HttpResponse httpResponse = httpClient.execute(httpPost);
                if (httpResponse.getStatusLine().getStatusCode() == 200){
                    HttpEntity httpEntity = httpResponse.getEntity();
                    JSONObject result = JSONObject.parseObject(EntityUtils.toString(httpEntity));
                    if (1==result.getIntValue("code") && result.getString("result").equals(code)){
                        //保存局部sessionid
                        RedisUtil.set("sso_client_session_id"+"_"+currentSessionId,code);
                        //保存全局sessionids方便退出登录
                        RedisUtil.set("sso_client_session_ids"+"_"+code,currentSessionId);
                        // 移除url中的token参数
                        String backUrl = RequestParameterUtil.getParameterWithOutCode(WebUtils.toHttp(request));
                        // 返回请求资源
                        try {
                            // client无密认证
                            String username = request.getParameter("username");
                            subject.login(new UsernamePasswordToken(username, ""));
                            HttpServletResponse httpServletResponse = WebUtils.toHttp(response);
                            httpServletResponse.sendRedirect(backUrl.toString());
                            return true;
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                }
            }catch (Exception e){
                e.printStackTrace();
            }
        }
        return false;
    }
}
