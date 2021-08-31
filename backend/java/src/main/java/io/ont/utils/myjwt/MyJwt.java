package io.ont.utils.myjwt;



public abstract class MyJwt {
    public MyJwt() {
    }

    public static MyJwtCreator.Builder create() {
        return MyJwtCreator.init();
    }
}
