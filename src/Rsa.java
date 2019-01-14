import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

class Rsa {
    private PrivateKey privateKey;
    private PublicKey publicKey;

    public void LoadPublicKey(String file) throws Exception {
        String publicKeyContent = new String(Files.readAllBytes(Paths.get(file)), StandardCharsets.UTF_8);
        publicKeyContent = publicKeyContent.replaceAll("\\n", "").replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "");
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyContent));
        this.publicKey = keyFactory.generatePublic(keySpecX509);
    }

    public void LoadPrivateKey(String file) throws Exception {
        String privateKeyContent = new String(Files.readAllBytes(Paths.get(file)), StandardCharsets.UTF_8);
        privateKeyContent = privateKeyContent.replaceAll("\\n", "").replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "");
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        KeySpec ks = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyContent));
        this.privateKey = keyFactory.generatePrivate(ks);
    }

    public String sign(String text) throws Exception {
        Signature privateSignature = Signature.getInstance("SHA1withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(text.getBytes());
        byte[] signature = privateSignature.sign();
        return Base64.getUrlEncoder().encodeToString(signature);
    }

    public boolean verify(String sign, String text) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA1withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(text.getBytes());
        byte[] signatureBytes = Base64.getUrlDecoder().decode(sign);
        return publicSignature.verify(signatureBytes);
    }
}
