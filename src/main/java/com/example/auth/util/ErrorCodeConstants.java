package com.example.auth.util;

public class ErrorCodeConstants {

    // Validation
    public static final int USERNAME_INVALID = 100;
    public static final int USERNAME_EXISTS = 101;
    public static final int USERNAME_TOO_SHORT = 102;
    public static final int USERNAME_TOO_LONG = 103;
    public static final int USERNAME_BAD_CHAR = 104;

    public static final int EMAIL_INVALID = 110;
    public static final int EMAIL_EXISTS = 111;

    public static final int PASSWORD_TOO_SHORT = 120;
    public static final int PASSWORD_TOO_LONG = 121;
    public static final int PASSWORD_MUST_CONTAIN_NUMBER = 122;
    public static final int PASSWORD_MUST_CONTAIN_CAPITAL_LETTER = 123;
    public static final int PASSWORD_MUST_CONTAIN_SPECIAL_CHAR = 124;

    public static final int NAME_CANNOT_CONTAIN_CHAR = 130;
    public static final int NAME_TOO_LONG = 131;
    public static final int NAME_TOO_SHORT = 132;

    // errors
    public static final int USERNAME_NOT_FOUND = 200;

}
