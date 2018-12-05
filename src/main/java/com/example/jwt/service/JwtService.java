package com.example.jwt.service;

import com.example.jwt.entity.Token;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.*;
import lombok.Data;
import org.springframework.stereotype.Service;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.Charset;
import java.security.Key;
import java.util.*;

/**
 * @author: tomcmd
 * @create: 2018/11/27 10:40 AM
 */
@Service
public class JwtService {
    List<TokenData> tokenDataList = new ArrayList<>();

    @Data
    static class TokenData {
        Token token;
        String appId;
        String appKey;

    }

    //jwt令牌的有效时间
    private static final long ACCESS_TOKEN_EXPIRE = 1000 * 60 * 60 * 2L;

    /**
     * 生成密钥
     *
     * @return
     */
    private static Key getKey(String clientSecret) {
        //HS256加密
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
        //密钥
        byte[] apiKeySecretBytes = clientSecret.getBytes(Charset.forName("utf-8"));
        Key sigingKey = new SecretKeySpec(apiKeySecretBytes, signatureAlgorithm.getJcaName());
        return sigingKey;
    }

    public static void main(String[] args){
        String token = createToken("xxx");
        System.out.println("token:"+token);
        boolean vaild = vaild(token);
        System.out.println("valid:"+vaild);
    }
    /**
     * 生成用户令牌
     *
     * @return
     */
    public static String createToken(String clientSecret) {
        Long now = System.currentTimeMillis();
        Date nowDate = new Date(now);
        Long expMills = now + ACCESS_TOKEN_EXPIRE;
        Date expDate = new Date(expMills);
        //生成token
        JwtBuilder jwtBuilder = Jwts.builder()
                .setHeaderParam("typ", "JWT")
                .setHeaderParam("alg", "HS256")
                .claim("iss", "yunqiacademy.org")
                .claim("company", "yunqiacademy")
                .setId(UUID.randomUUID().toString())
                .setIssuedAt(nowDate)
                .setExpiration(expDate)
                .signWith(SignatureAlgorithm.HS256, getKey(clientSecret));
        return jwtBuilder.compact();
    }

    /**
     * 拿取claims
     *
     * @param token
     * @return
     */
    public static Claims getToken(String token, String clientSecret) throws Exception {
        Claims claims = Jwts.parser()
                .setSigningKey(getKey(clientSecret))
                .parseClaimsJws(token)
                .getBody();
        return claims;
    }

    public static boolean vaild(String token) {
        try {
            //根据token拿到appSecret
            String clientSecret = "xxx";
            Map<String,Object> claimsMap = getToken(token, clientSecret);
            if (claimsMap != null) {
                ObjectMapper objectMapper = new ObjectMapper();
                String payload = objectMapper.writeValueAsString(claimsMap);
                JwtBuilder jwtBuilder = Jwts.builder()
                        .setHeaderParam("typ", "JWT")
                        .setHeaderParam("alg", "HS256")
                        .setPayload(payload)
                        .signWith(SignatureAlgorithm.HS256, getKey(clientSecret));
                String validToken = jwtBuilder.compact();
                return token.equals(validToken);
            }
            return false;
        } catch (Exception e) {
            if (e instanceof ExpiredJwtException) {
                //token过期
                System.out.println("token已过期");
            }
        }
        return false;
    }

}
