package io.ont.utils;

public enum ErrorInfo {

    /**
     * success
     */
    SUCCESS(0, "SUCCESS"),

    /**
     * param error
     */
    PARAM_ERROR(61001, "FAIL, param error."),

    /**
     * nonce does not exist
     */
    NONCE_NOT_EXISTS(61003, "Fail, nonce does not exist."),

    /**
     * nonce already exists
     */
    NONCE_ALREADY_EXISTS(61004, "Fail, nonce already exists."),

    /**
     * JWT
     */
    VERIFY_TOKEN_FAILED(63001, "FAIL, verify token fail."),

    /**
     * token expired
     */
    TOKEN_EXPIRED(63002, "FAIL, token expired."),

    /**
     * token type error
     */
    TOKEN_TYPE_ERROR(63003, "FAIL, token type error."),
    ;
    private int errorCode;
    private String errorDescEN;

    ErrorInfo(int errorCode, String errorDescEN) {
        this.errorCode = errorCode;
        this.errorDescEN = errorDescEN;
    }

    public int code() {
        return errorCode;
    }

    public String descEN() {
        return errorDescEN;
    }

}
