public class Test {
    public static void main(String[] args) throws Exception {
        /*
         * Java 需要将 rsa 密钥转成 pkcs8 padding 格式的密钥
         * openssl pkcs8 -topk8 -inform PEM -in private.pem -outform PEM -nocrypt > pkcs8.pem
         */
        Rsa rsa = new Rsa();
        //公钥和私钥地址需自己替换
        rsa.LoadPrivateKey("certs/pkcs8.pem");
        rsa.LoadPublicKey("certs/public.pem");

        String text = "a=1";
        String sign = rsa.sign(text);
        System.out.println(sign);

        System.out.println(rsa.verify(sign, text));
    }
}
