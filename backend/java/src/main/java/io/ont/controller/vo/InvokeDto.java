package io.ont.controller.vo;

import lombok.Data;



@Data
public class InvokeDto {
    private String signer;
    private String signedTx;
    private InvokeExtraData extraData;

}
