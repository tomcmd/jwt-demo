package com.example.jwt.entity;

import lombok.Data;

/**
 * @author: tomcmd
 * @create: 2018/11/27 2:54 PM
 */
@Data
public class Token {
    private String access_token;
    private String refresh_token;
    private int expires_in;
    private String token_type = "bearer";
}
